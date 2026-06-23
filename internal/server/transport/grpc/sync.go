// Package grpc предоставляет реализации gRPC-хендлеров и интерцепторов
// для серверной части распределенной экосистемы GophKeeper.
package grpc

import (
	"context"
	"errors"
	"log/slog"
	"time"

	pb "gophkeeper/gen/go/gophkeeper/v1"
	"gophkeeper/internal/server/auth"
	"gophkeeper/internal/server/config"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// SyncHandler координирует операции пакетного обмена, дифференциальной сверки карт
// версий и фиксации оффлайн-изменений записей на стороне облачного сервера.
type SyncHandler struct {
	pb.UnimplementedSyncServiceServer
	cfg  config.Config
	pool *pgxpool.Pool
}

// NewSyncHandler конструирует новый экземпляр обработчика SyncHandler.
func NewSyncHandler(cfg config.Config, pool *pgxpool.Pool) *SyncHandler {
	return &SyncHandler{cfg: cfg, pool: pool}
}

// SyncCheck реализует Last-Write-Wins (LWW) стратегию распределенной сверки метаданных.
func (h *SyncHandler) SyncCheck(ctx context.Context, req *pb.SyncCheckRequest) (*pb.SyncCheckResponse, error) {
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		return nil, err
	}

	// 1. Вычитываем из базы актуальные канонические версии всех секретов пользователя
	query := `SELECT id, updated_at FROM records WHERE user_id = $1;`
	rows, err := h.pool.Query(ctx, query, userID)
	if err != nil {
		slog.Error("Database query failed in SyncCheck phase", "user_id", userID, "error", err)
		return nil, status.Error(codes.Internal, "Internal server error")
	}
	defer rows.Close()

	serverVersions := make(map[string]time.Time)
	for rows.Next() {
		var rID string
		var uTime time.Time
		if err := rows.Scan(&rID, &uTime); err != nil {
			slog.Error("Row scan failed in SyncCheck database iteration", "error", err)
			return nil, status.Error(codes.Internal, "Internal server error")
		}
		serverVersions[rID] = uTime.UTC()
	}

	// 2. Сравниваем с тем, что прислал клиент
	clientVersions := make(map[string]time.Time)
	for _, lv := range req.GetLocalVersions() {
		if lv.GetUpdatedAt() == nil {
			slog.Warn("Client provided nil updated_at timestamp, record skipped", "record_id", lv.GetRecordId())
			continue
		}
		// Время извлекается аппаратно через .AsTime() без строкового парсинга
		clientVersions[lv.GetRecordId()] = lv.GetUpdatedAt().AsTime().UTC()
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

// PushRecords принимает от mTLS-клиента новые/измененные секреты и транзакционно пишет их в историю.
func (h *SyncHandler) PushRecords(ctx context.Context, req *pb.PushRecordsRequest) (*pb.PushRecordsResponse, error) {
	userID, err := h.getUserIDFromContext(ctx)
	if err != nil {
		return nil, err
	}

	// Запускаем транзакцию для обеспечения атомарности записи в records и records_history
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		slog.Error("Failed to initiate PostgreSQL transaction for PushRecords", "user_id", userID, "error", err)
		return nil, status.Error(codes.Internal, "Internal server error")
	}

	txCommitted := false
	defer func() {
		if !txCommitted {
			if rollbackErr := tx.Rollback(ctx); rollbackErr != nil && !errors.Is(rollbackErr, pgx.ErrTxClosed) {
				slog.Error("Critical failure: transaction rollback crashed during PushRecords panic handler", "error", rollbackErr)
			}
		}
	}()

	for _, r := range req.GetRecords() {
		if r.GetCreatedAt() == nil || r.GetUpdatedAt() == nil {
			slog.Warn("Push packet contains record with missing timestamps, skipped", "record_id", r.GetRecordId())
			continue
		}

		// Извлечение времени происходит нативно до наносекунд
		cTime := r.GetCreatedAt().AsTime().UTC()
		uTime := r.GetUpdatedAt().AsTime().UTC()

		// Проверяем инвариант LWW: если в базе вдруг уже лежит запись новее, чем пушит клиент, то отклоняем пуш
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
			slog.Error("UPSERT query failed inside PushRecords transaction", "record_id", r.GetRecordId(), "error", err)
			return nil, status.Error(codes.Internal, "Internal server error")
		}

		// 2. Записываем срез состояния в историю изменений (История секретов)
		historyQuery := `
			INSERT INTO records_history (record_id, user_id, name, type, envelope, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6);`

		_, err = tx.Exec(ctx, historyQuery, r.GetRecordId(), userID, r.GetName(), r.GetType(), r.GetEnvelope(), uTime)
		if err != nil {
			slog.Error("History log insert failed inside PushRecords transaction", "record_id", r.GetRecordId(), "error", err)
			return nil, status.Error(codes.Internal, "Internal server error")
		}
	}

	if err := tx.Commit(ctx); err != nil {
		slog.Error("PostgreSQL transaction commit crashed for PushRecords", "user_id", userID, "error", err)
		return nil, status.Error(codes.Internal, "Internal server error")
	}
	txCommitted = true

	return &pb.PushRecordsResponse{Success: true}, nil
}

// PullRecords извлекает и стримит запрашиваемые зашифрованные конверты клиенту.
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
		slog.Error("Database query failed inside PullRecords packet stream", "user_id", userID, "error", err)
		return nil, status.Error(codes.Internal, "Internal server error")
	}
	defer rows.Close()

	var pulled []*pb.EncryptedRecordPayload
	for rows.Next() {
		var r pb.EncryptedRecordPayload
		var cTime, uTime time.Time
		if err := rows.Scan(&r.RecordId, &r.Name, &r.Type, &r.Envelope, &cTime, &uTime); err != nil {
			slog.Error("Row scan failed inside PullRecords processing iteration", "error", err)
			return nil, status.Error(codes.Internal, "Internal server error")
		}

		// Нативно мапим объекты во временные метки Google Protobuf
		r.CreatedAt = timestamppb.New(cTime)
		r.UpdatedAt = timestamppb.New(uTime)

		pulled = append(pulled, &r)
	}

	if err := rows.Err(); err != nil {
		slog.Error("Rows iteration error tracked inside PullRecords stream finalisation", "error", err)
		return nil, status.Error(codes.Internal, "Internal server error")
	}

	return &pb.PullRecordsResponse{Records: pulled}, nil
}

// getUserIDFromContext мапит DeviceID из mTLS-сертификата на UserID владельца аккаунта.
func (h *SyncHandler) getUserIDFromContext(ctx context.Context) (string, error) {
	deviceID, ok := ctx.Value(auth.DeviceIDContextKey).(string)
	if !ok || deviceID == "" {
		return "", status.Error(codes.Unauthenticated, "unauthenticated mTLS identity context missing")
	}

	var userID string
	err := h.pool.QueryRow(ctx, "SELECT user_id FROM devices WHERE id = $1 AND status = 'active';", deviceID).Scan(&userID)
	if errors.Is(err, pgx.ErrNoRows) {
		slog.Warn("mTLS access denied: current DeviceID is revoked or unregistered", "device_id", deviceID)
		return "", status.Error(codes.PermissionDenied, "device is revoked or not registered")
	}
	if err != nil {
		slog.Error("Database lookup failure in mTLS interceptor context validation", "device_id", deviceID, "error", err)
		return "", status.Error(codes.Internal, "Internal server error")
	}

	return userID, nil
}
