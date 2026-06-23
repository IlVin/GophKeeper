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

	// Парсим публичный ключ для расчета SshFingerprint (Identity Binding)
	pubKey, err := ssh.ParsePublicKey(req.GetSshPublicKey())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid ssh public key format: %v", err)
	}
	fingerprint := serverCalculateFingerprint(pubKey)

	// Ищем существующего пользователя в PostgreSQL (Схема Register-or-Join)
	existingUser, err := h.repo.GetByFingerprint(ctx, fingerprint)
	if err != nil {
		// БАРЬЕР ИБ: Маскируем сырые трейсы СУБД, пишем их в лог сервера, отдаем безопасный Internal текст
		slog.Error("Database fetch failed in RegisterBegin", "fingerprint", fingerprint, "error", err)
		return nil, status.Error(codes.Internal, "Internal server error")
	}

	var userID string
	if existingUser != nil {
		userID = existingUser.ID
	} else {
		userID = fingerprint
	}

	sessionID := uuid.New().String()

	// Генерируем 32-байтный случайный серверный nonce через OS CSPRNG (Защита от Replay)
	serverNonce := make([]byte, 32)
	if _, err = rand.Read(serverNonce); err != nil {
		slog.Error("CSPRNG entropy generation failed for server nonce", "error", err)
		return nil, status.Error(codes.Internal, "Internal server error")
	}

	// Сохраняем challenge session в PostgreSQL со статусом "Unused" и TTL 5 минут
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
		slog.Error("Failed to persist challenge session context in PostgreSQL", "session_id", sessionID, "error", err)
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
	// Базовая валидация параметров
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

	// 1. ВАЛИДАЦИЯ СЕССИИ (Challenge State Machine и защита от Replay)
	session, err := h.repo.GetAndLock(ctx, req.GetSessionId())
	if err != nil {
		slog.Error("Row locking failed for challenge session transaction", "session_id", req.GetSessionId(), "error", err)
		return nil, status.Error(codes.Internal, "Internal server error")
	}
	if session == nil {
		return nil, status.Error(codes.NotFound, "challenge session not found")
	}

	// Проверяем TTL и статус сессии
	if time.Now().UTC().After(session.ExpiresAt) {
		_ = h.repo.UpdateState(ctx, session.ID, "Expired")
		return nil, status.Error(codes.DeadlineExceeded, "challenge session has expired (TTL 5 min)")
	}
	if session.State != "Unused" {
		return nil, status.Error(codes.PermissionDenied, "challenge session already used, replay blocked")
	}
	if session.UserID != req.GetUserId() || session.Operation != "register" {
		return nil, status.Error(codes.InvalidArgument, "session parameter mismatch")
	}

	// Погашаем сессию МГНОВЕННО (Атомарный переход Unused -> Used для предотвращения атак повторения)
	if err = h.repo.UpdateState(ctx, session.ID, "Used"); err != nil {
		slog.Error("Failed to update challenge session state atomic transition to Used", "session_id", session.ID, "error", err)
		return nil, status.Error(codes.Internal, "Internal server error")
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
		slog.Warn("Cryptographic signature challenge verification failed: unauthorized tampering detected", "user_id", session.UserID)
		return nil, status.Error(codes.Unauthenticated, "cryptographic challenge signature verification failed")
	}

	// 3. УНИФИЦИРОВАННАЯ РЕГИСТРАЦИЯ И СВЕРКА КАНОНА
	var canonicalSalt []byte
	var canonicalBootstrap []byte
	var statusEnum pb.RegistrationStatus

	// ИСПРАВЛЕНО: Полностью удален импорт клиентского пакета sshagent! Расчет идет на месте.
	currentFingerprint := serverCalculateFingerprint(clientPubKey)

	existingUser, err := h.repo.GetByFingerprint(ctx, currentFingerprint)
	if err != nil {
		slog.Error("Database fetch failed in RegisterFinish white-listing check", "error", err)
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
			slog.Error("Failed to commit new user entity registration block to PostgreSQL", "user_id", session.UserID, "error", err)
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
		slog.Error("PKI infrastructure failure: could not read Device CA trust anchors", "error", err)
		return nil, status.Error(codes.Internal, "Internal server error")
	}

	clientCertDER, serialNumber, err := pki.IssueDeviceCertificate(
		req.GetCsr(),
		req.GetDeviceId(),
		deviceCACert,
		deviceCAKey,
	)
	if err != nil {
		slog.Error("PKI generation cascade failure: could not sign container CSR template", "device_id", req.GetDeviceId(), "error", err)
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
		slog.Error("Failed to register active device metadata mapping in PostgreSQL", "device_id", req.GetDeviceId(), "error", err)
		return nil, status.Error(codes.Internal, "Internal server error")
	}

	return &pb.RegisterFinishResponse{
		Status:                            statusEnum, // ИСПРАВЛЕНО: Передаем строго типизированный enum
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
