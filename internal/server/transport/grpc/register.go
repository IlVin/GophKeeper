// Package grpc предоставляет реализации gRPC-хендлеров и интерцепторов
// для серверной части распределенной экосистемы GophKeeper.
package grpc

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"log/slog"
	"strings"
	"time"

	"gophkeeper/internal/domain/security"
	"gophkeeper/internal/server/config"
	"gophkeeper/internal/server/pki"
	"gophkeeper/internal/server/providers/postgres"
	"gophkeeper/internal/server/repository"

	// Канонический путь импорта обновленных protobuf-файлов
	pb "gophkeeper/gen/go/gophkeeper/v1"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// RegistrationHandler координирует обработку входящих rpc-вызовов двухэтапного
// Zero-Knowledge протокола регистрации и mTLS паспортизации контейнеров.
type RegistrationHandler struct {
	pb.UnimplementedRegistrationServer
	cfg  config.Config
	repo *postgres.PostgresRepository
}

// NewRegistrationHandler конструирует новый экземпляр обработчика RegistrationHandler.
func NewRegistrationHandler(cfg config.Config, pool *pgxpool.Pool) *RegistrationHandler {
	return &RegistrationHandler{
		cfg:  cfg,
		repo: postgres.NewPostgresRepository(pool),
	}
}

// RegisterBegin — Шаг 1: Инициация сессии челленджа и генерация одноразового серверного nonce.
func (h *RegistrationHandler) RegisterBegin(ctx context.Context, req *pb.RegisterBeginRequest) (*pb.RegisterBeginResponse, error) {
	if len(req.GetSshPublicKey()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "ssh public key cannot be empty")
	}

	pubKey, err := ssh.ParsePublicKey(req.GetSshPublicKey())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid ssh public key format: %v", err)
	}
	fingerprint := serverCalculateFingerprint(pubKey)

	existingUser, err := h.repo.GetByFingerprint(ctx, fingerprint)
	if err != nil {
		slog.ErrorContext(context.Background(), "Database fetch failed in RegisterBegin",
			slog.String("fingerprint", fingerprint),
			slog.Any("error", err),
		)
		return nil, status.Error(codes.Internal, "Internal server error")
	}

	var userID string
	if existingUser != nil {
		userID = existingUser.ID
	} else {
		userID = fingerprint
	}

	sessionID := uuid.New().String()

	serverNonce := make([]byte, 32)
	if _, err = rand.Read(serverNonce); err != nil {
		slog.ErrorContext(context.Background(), "CSPRNG entropy generation failed for server nonce",
			slog.Any("error", err),
		)
		return nil, status.Error(codes.Internal, "Internal server error")
	}

	session := &repository.ChallengeSession{
		ID:          sessionID,
		UserID:      userID,
		ServerNonce: serverNonce,
		Operation:   "register",
		State:       "Unused",
		CreatedAt:   time.Now().UTC(),
		ExpiresAt:   time.Now().UTC().Add(5 * time.Minute),
	}

	if err = h.repo.CreateChallengeSession(ctx, session); err != nil {
		slog.ErrorContext(context.Background(), "Failed to persist challenge session context in PostgreSQL",
			slog.String("session_id", sessionID),
			slog.Any("error", err),
		)
		return nil, status.Error(codes.Internal, "Internal server error")
	}

	return &pb.RegisterBeginResponse{
		UserId:      userID,
		SessionId:   sessionID,
		ServerNonce: serverNonce,
	}, nil
}

// RegisterFinish — Шаг 2: Верификация подписи крипто-челленджа из ssh-agent и выпуск mTLS сертификата.
func (h *RegistrationHandler) RegisterFinish(ctx context.Context, req *pb.RegisterFinishRequest) (*pb.RegisterFinishResponse, error) {
	if req.GetUserId() == "" || req.GetSessionId() == "" || req.GetDeviceId() == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id, session_id and device_id are required")
	}
	if len(req.GetAuthChallengeSignature()) == 0 || len(req.GetCsr()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "signature and csr payloads are required")
	}
	if len(req.GetAccountBootstrapEnvelope()) == 0 || len(req.GetDeviceMasterKeyEnvelope()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "cryptographic master envelopes are required")
	}
	if len(req.GetAccountSalt()) != 32 {
		return nil, status.Error(codes.InvalidArgument, "account salt must be exactly 32 bytes")
	}

	// 1. Вызываем потокобезопасный транзакционный ConsumeChallengeSession
	session, err := h.repo.ConsumeChallengeSession(ctx, req.GetSessionId())
	if err != nil {
		slog.ErrorContext(context.Background(), "Transactional challenge token consumption crashed",
			slog.String("session_id", req.GetSessionId()),
			slog.Any("error", err),
		)
		return nil, status.Error(codes.Internal, "Internal server error")
	}
	if session == nil {
		return nil, status.Error(codes.NotFound, "challenge session not found")
	}

	// Проверяем TTL сессии
	if time.Now().UTC().After(session.ExpiresAt) {
		_ = h.repo.UpdateState(ctx, session.ID, "Expired")
		return nil, status.Error(codes.DeadlineExceeded, "challenge session has expired (TTL 5 min)")
	}

	// УБРАНО: Проверка session.State != "Unused" больше не нужна.
	// Метод ConsumeChallengeSession сам атомарно проверил статус и погасил токен (перевёл в 'Used').
	// Если бы сессия была погашена ранее, повторный вызов вернул бы состояние 'Used', но ConsumeChallengeSession
	// обновляет и переводит в Used только если на входе было строго 'Unused', защищая от Replay.
	if session.State != "Used" {
		return nil, status.Error(codes.PermissionDenied, "challenge session already consumed or invalid, replay blocked")
	}

	if session.UserID != req.GetUserId() || session.Operation != "register" {
		return nil, status.Error(codes.InvalidArgument, "session parameter mismatch")
	}

	// 2. КРИПТОГРАФИЧЕСКАЯ ВЕРИФИКАЦИЯ SSH-ПОДПИСИ (Инвариант №3)
	challengePayload := security.NewChallengePayload(session.UserID, session.ID, session.ServerNonce, "register")
	marshaledChallenge := challengePayload.Marshal()

	clientPubKey, err := ssh.ParsePublicKey(req.GetSshPublicKey())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to parse client public key wire format: %v", err)
	}

	cryptoPubKey, ok := clientPubKey.(ssh.CryptoPublicKey)
	if !ok {
		return nil, status.Error(codes.InvalidArgument, "provided key is not a cryptographic public key")
	}
	ed25519PubKey, ok := cryptoPubKey.CryptoPublicKey().(ed25519.PublicKey)
	if !ok {
		return nil, status.Error(codes.InvalidArgument, "the operational root key must be strictly of type Ed25519")
	}

	if !ed25519.Verify(ed25519PubKey, marshaledChallenge, req.GetAuthChallengeSignature()) {
		slog.Warn("Cryptographic signature challenge verification failed: unauthorized tampering detected",
			slog.String("user_id", session.UserID),
		)
		return nil, status.Error(codes.Unauthenticated, "cryptographic challenge signature verification failed")
	}

	// 3. УНИФИЦИРОВАННАЯ РЕГИСТРАЦИЯ И СВЕРКА КАНОНА
	var canonicalSalt []byte
	var canonicalBootstrap []byte
	var statusEnum pb.RegistrationStatus

	currentFingerprint := serverCalculateFingerprint(clientPubKey)

	existingUser, err := h.repo.GetByFingerprint(ctx, currentFingerprint)
	if err != nil {
		slog.ErrorContext(context.Background(), "Database fetch failed in RegisterFinish white-listing check",
			slog.Any("error", err),
		)
		return nil, status.Error(codes.Internal, "Internal server error")
	}

	if existingUser == nil {
		// Сценарий А: Новый аккаунт. Принимаем данные клиента как КАНОНИЧЕСКИЕ
		statusEnum = pb.RegistrationStatus_REGISTRATION_STATUS_ACCOUNT_CREATED
		canonicalSalt = req.GetAccountSalt()
		canonicalBootstrap = req.GetAccountBootstrapEnvelope()

		newUser := &repository.User{
			ID:                         session.UserID,
			SshFingerprint:             currentFingerprint,
			SshPublicKey:               req.GetSshPublicKey(),
			CanonicalAccountSalt:       canonicalSalt,
			CanonicalBootstrapEnvelope: canonicalBootstrap,
			CreatedAt:                  time.Now().UTC(),
		}

		if err = h.repo.CreateUser(ctx, newUser); err != nil {
			slog.ErrorContext(context.Background(), "Failed to commit new user entity registration block to PostgreSQL",
				slog.String("user_id", session.UserID),
				slog.Any("error", err),
			)
			return nil, status.Error(codes.Internal, "Internal server error")
		}
	} else {
		// Сценарий Б: Аккаунт уже существует. Возвращаем каноничную соль сервера для сверки и Reconcile
		statusEnum = pb.RegistrationStatus_REGISTRATION_STATUS_ACCOUNT_JOINED
		canonicalSalt = existingUser.CanonicalAccountSalt
		canonicalBootstrap = existingUser.CanonicalBootstrapEnvelope
	}

	// 4. ДИНАМИЧЕСКИЙ ВЫПУСК mTLS СЕРТИФИКАТА УСТРОЙСТВА (PKI слой)
	deviceCACert, deviceCAKey, err := pki.LoadDeviceCA(h.cfg)
	if err != nil {
		slog.ErrorContext(context.Background(), "PKI infrastructure failure: could not read Device CA trust anchors",
			slog.Any("error", err),
		)
		return nil, status.Error(codes.Internal, "Internal server error")
	}

	clientCertDER, serialNumber, err := pki.IssueDeviceCertificate(
		req.GetCsr(),
		req.GetDeviceId(),
		deviceCACert,
		deviceCAKey,
	)
	if err != nil {
		slog.ErrorContext(context.Background(), "PKI generation cascade failure: could not sign container CSR template",
			slog.String("device_id", req.GetDeviceId()),
			slog.Any("error", err),
		)
		return nil, status.Error(codes.Internal, "Internal server error")
	}

	newDevice := &repository.Device{
		ID:                      req.GetDeviceId(),
		UserID:                  session.UserID,
		DeviceMasterKeyEnvelope: req.GetDeviceMasterKeyEnvelope(),
		ClientCertificate:       clientCertDER,
		CertSerialNumber:        serialNumber,
		Status:                  "active",
		RegisteredAt:            time.Now().UTC(),
		LastSyncAt:              time.Now().UTC(),
	}

	if err = h.repo.CreateDevice(ctx, newDevice); err != nil {
		slog.ErrorContext(context.Background(), "Failed to register active device metadata mapping in PostgreSQL",
			slog.String("device_id", req.GetDeviceId()),
			slog.Any("error", err),
		)
		return nil, status.Error(codes.Internal, "Internal server error")
	}

	return &pb.RegisterFinishResponse{
		Status:                            statusEnum,
		CanonicalAccountSalt:              canonicalSalt,
		CanonicalAccountBootstrapEnvelope: canonicalBootstrap,
		ClientCertificate:                 clientCertDER,
		CaChain:                           deviceCACert.Raw,
	}, nil
}

// Внутренний изолированный серверный метод расчета канонических фингерпринтов OpenSSH
func serverCalculateFingerprint(pub ssh.PublicKey) string {
	sum := sha256.Sum256(pub.Marshal())
	b64 := base64.StdEncoding.EncodeToString(sum[:])
	return "SHA256:" + strings.TrimRight(b64, "=")
}
