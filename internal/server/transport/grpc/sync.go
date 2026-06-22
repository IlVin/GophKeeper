package grpc

import (
	"context"
	"errors"
	"time"

	pb "gophkeeper/gen/go/gophkeeper/v1"
	"gophkeeper/internal/server/auth"
	"gophkeeper/internal/server/config"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type SyncHandler struct {
	pb.UnimplementedSyncServiceServer
	cfg  config.Config
	pool *pgxpool.Pool
}

func NewSyncHandler(cfg config.Config, pool *pgxpool.Pool) *SyncHandler {
	return &SyncHandler{cfg: cfg, pool: pool}
}

// SyncCheck реализует Last-Write-Wins (LWW) стратегию сравнения метаданных
func (h *SyncHandler) SyncCheck(ctx context.Context, req *pb.SyncCheckRequest) (*pb.SyncCheckResponse, error) {
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		return nil, err
	}

	// 1. Вычитываем из базы актуальные версии всех секретов пользователя
	query := `SELECT id, updated_at FROM records WHERE user_id = $1;`
	rows, err := h.pool.Query(ctx, query, userID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "db query failed: %v", err)
	}
	defer rows.Close()

	serverVersions := make(map[string]time.Time)
	for rows.Next() {
		var rID string
		var uTime time.Time
		if err := rows.Scan(&rID, &uTime); err != nil {
			return nil, status.Errorf(codes.Internal, "scan failed: %v", err)
		}
		serverVersions[rID] = uTime.UTC()
	}

	// 2. Сравниваем с тем, что прислал клиент
	clientVersions := make(map[string]time.Time)
	for _, lv := range req.GetLocalVersions() {
		t, err := time.Parse(time.RFC3339, lv.GetUpdatedAt())
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid updated_at format: %v", err)
		}
		clientVersions[lv.GetRecordId()] = t.UTC()
	}

	var idsToPull []string
	var idsToPush []string

	// Фаза А: Проверяем, что на сервере новее (клиент должен сделать Pull)
	for rID, sTime := range serverVersions {
		cTime, exists := clientVersions[rID]
		if !exists || sTime.After(cTime) {
			idsToPull = append(idsToPull, rID)
		}
	}

	// Фаза Б: Проверяем, что у клиента новее (клиент должен сделать Push)
	for rID, cTime := range clientVersions {
		sTime, exists := serverVersions[rID]
		if !exists || cTime.After(sTime) {
			idsToPush = append(idsToPush, rID)
		}
	}

	return &pb.SyncCheckResponse{
		IdsToPull: idsToPull,
		IdsToPush: idsToPush,
	}, nil
}

// PushRecords принимает от mTLS-клиента новые/измененные секреты и пишет их в историю
func (h *SyncHandler) PushRecords(ctx context.Context, req *pb.PushRecordsRequest) (*pb.PushRecordsResponse, error) {
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		return nil, err
	}

	// Запускаем транзакцию для обеспечения атомарности записи в records и records_history
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to begin tx: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	for _, r := range req.GetRecords() {
		cTime, _ := time.Parse(time.RFC3339, r.GetCreatedAt())
		uTime, _ := time.Parse(time.RFC3339, r.GetUpdatedAt())

		// Проверяем инвариант LWW: если в базе вдруг уже лежит запись новее, чем пушит клиент,
		// (например, race condition), то отклоняем пуш этой записи
		var dbUpdatedAt time.Time
		err = tx.QueryRow(ctx, "SELECT updated_at FROM records WHERE id = $1 FOR UPDATE;", r.GetRecordId()).Scan(&dbUpdatedAt)
		if err == nil && !uTime.After(dbUpdatedAt) {
			continue // Серверная копия новее или равна, пропускаем (LWW)
		}

		// 1. Обновляем или создаем актуальную запись
		upsertQuery := `
			INSERT INTO records (id, user_id, name, type, envelope, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
			ON CONFLICT (id) DO UPDATE SET
				name = EXCLUDED.name,
				type = EXCLUDED.type,
				envelope = EXCLUDED.envelope,
				updated_at = EXCLUDED.updated_at;`

		_, err = tx.Exec(ctx, upsertQuery, r.GetRecordId(), userID, r.GetName(), r.GetType(), r.GetEnvelope(), cTime, uTime)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "upsert failed: %v", err)
		}

		// 2. Записываем срез состояния в историю изменений (Пункт 1: История секретов)
		historyQuery := `
			INSERT INTO records_history (record_id, user_id, name, type, envelope, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6);`

		_, err = tx.Exec(ctx, historyQuery, r.GetRecordId(), userID, r.GetName(), r.GetType(), r.GetEnvelope(), uTime)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "history log failed: %v", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, status.Errorf(codes.Internal, "commit failed: %v", err)
	}

	return &pb.PushRecordsResponse{Success: true}, nil
}

func (h *SyncHandler) PullRecords(ctx context.Context, req *pb.PullRecordsRequest) (*pb.PullRecordsResponse, error) {
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		return nil, err
	}

	if len(req.GetRecordIds()) == 0 {
		return &pb.PullRecordsResponse{}, nil
	}

	query := `SELECT id, name, type, envelope, created_at, updated_at FROM records WHERE id = ANY($1) AND user_id = $2;`
	rows, err := h.pool.Query(ctx, query, req.GetRecordIds(), userID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "query failed: %v", err)
	}
	defer rows.Close()

	var pulled []*pb.EncryptedRecordPayload
	for rows.Next() {
		var r pb.EncryptedRecordPayload
		var cTime, uTime time.Time
		if err := rows.Scan(&r.RecordId, &r.Name, &r.Type, &r.Envelope, &cTime, &uTime); err != nil {
			return nil, status.Errorf(codes.Internal, "scan failed: %v", err)
		}
		r.CreatedAt = cTime.Format(time.RFC3339)
		r.UpdatedAt = uTime.Format(time.RFC3339)
		pulled = append(pulled, &r)
	}

	return &pb.PullRecordsResponse{Records: pulled}, nil
}

// getUserIDFromContext мапит DeviceID из mTLS-сертификата на UserID владельца аккаунта
func (h *SyncHandler) getUserIDFromContext(ctx context.Context) (string, error) {
	deviceID, ok := ctx.Value(auth.DeviceIDContextKey).(string)
	if !ok || deviceID == "" {
		return "", status.Error(codes.Unauthenticated, "unauthenticated mTLS identity context missing")
	}

	var userID string
	err := h.pool.QueryRow(ctx, "SELECT user_id FROM devices WHERE id = $1 AND status = 'active';", deviceID).Scan(&userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", status.Error(codes.PermissionDenied, "device is revoked or not registered")
	}
	if err != nil {
		return "", status.Error(codes.Internal, "registry lookup failed")
	}

	return userID, nil
}
