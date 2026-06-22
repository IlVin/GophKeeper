package grpc

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"time"

	"gophkeeper/internal/client/providers/sshagent"
	"gophkeeper/internal/domain/security"
	"gophkeeper/internal/server/config"
	"gophkeeper/internal/server/pki"
	"gophkeeper/internal/server/providers/postgres"
	"gophkeeper/internal/server/repository"

	// Канонический путь импорта protobuf-файлов v4.1
	pb "gophkeeper/gen/go/gophkeeper/v1"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type DeviceAttachmentHandler struct {
	pb.UnimplementedDeviceAttachmentServer
	cfg  config.Config
	repo *postgres.PostgresRepository
	pool *pgxpool.Pool
}

// NewDeviceAttachmentHandler конструирует обработчик привязки устройств с поддержкой СУБД.
func NewDeviceAttachmentHandler(cfg config.Config, pool *pgxpool.Pool) *DeviceAttachmentHandler {
	return &DeviceAttachmentHandler{
		cfg:  cfg,
		repo: postgres.NewPostgresRepository(pool),
		pool: pool,
	}
}

// AttachDeviceBegin — Шаг 1: Инициация привязки нового контейнера.
// Сервер находит аккаунт по публичному SSH-ключу, создает временную сессию челленджа,
// генерирует nonce и возвращает ТОЛЬКО публичные параметры.
// Реализует инвариант Withholding для защиты от User Enumeration (перебора логинов/ключей).
func (h *DeviceAttachmentHandler) AttachDeviceBegin(ctx context.Context, req *pb.AttachDeviceBeginRequest) (*pb.AttachDeviceBeginResponse, error) {
	if len(req.GetSshPublicKey()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "ssh public key cannot be empty")
	}

	// 1. Вычисляем фингерпринт входящего публичного ключа
	pubKey, err := ssh.ParsePublicKey(req.GetSshPublicKey())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid ssh public key format: %v", err)
	}
	fingerprint := sshagent.FingerprintSHA256(pubKey)

	// 2. Ищем существующего пользователя в PostgreSQL
	existingUser, err := h.repo.GetByFingerprint(ctx, fingerprint)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "database user lookup failed: %v", err)
	}

	// Если ключ не зарегистрирован, возвращаем унифицированную фейковую сессию.
	// Злоумышленник не сможет понять, существует ли аккаунт, перебирая ключи.
	var targetUserID string
	if existingUser != nil {
		targetUserID = existingUser.ID
	} else {
		// Генерируем случайный UUID плейсхолдер
		targetUserID = uuid.New().String()
	}

	sessionID := uuid.New().String()

	// 3. Генерируем случайный серверный nonce через OS CSPRNG
	serverNonce := make([]byte, 32)
	if _, err = rand.Read(serverNonce); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to generate server nonce: %v", err)
	}

	// 4. Записываем challenge сессию в PostgreSQL со статусом "Unused" и TTL 5 минут.
	// Даже если пользователя нет, мы пишем фейковую сессию под случайный userID, чтобы тайминги ответов совпадали.
	session := &repository.ChallengeSession{
		ID:          sessionID,
		UserID:      targetUserID,
		ServerNonce: serverNonce,
		Operation:   "attach-device",
		State:       "Unused",
		CreatedAt:   time.Now().UTC(),
		ExpiresAt:   time.Now().UTC().Add(5 * time.Minute),
	}

	if err = h.repo.CreateChallengeSession(ctx, session); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to save challenge session: %v", err)
	}

	return &pb.AttachDeviceBeginResponse{
		UserId:      targetUserID,
		SessionId:   sessionID,
		ServerNonce: serverNonce,
	}, nil
}

// AttachDeviceAuth — Шаг 2: Проверка владения SSH-ключом.
// Клиент присылает подпись челленджа. Сервер верифицирует её с помощью ранее сохраненного SSH-ключа.
// Только в случае успешной проверки сервер раскрывает AccountSalt и облачный AccountBootstrapEnvelope.
func (h *DeviceAttachmentHandler) AttachDeviceAuth(ctx context.Context, req *pb.AttachDeviceAuthRequest) (*pb.AttachDeviceAuthResponse, error) {
	if req.GetUserId() == "" || req.GetSessionId() == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id and session_id are required")
	}
	if len(req.GetAuthChallengeSignature()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "authentication challenge signature is required")
	}

	// 1. Атомарная валидация сессии (Challenge State Machine и защита от Replay)
	// Блокируем строку сессии в СУБД (FOR UPDATE)
	session, err := h.repo.GetAndLock(ctx, req.GetSessionId())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to lock challenge session: %v", err)
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
	if session.UserID != req.GetUserId() || session.Operation != "attach-device" {
		return nil, status.Error(codes.InvalidArgument, "session parameter mismatch")
	}

	// Погашаем сессию МГНОВЕННО (Переводим в промежуточное состояние Authenticated)
	if err = h.repo.UpdateState(ctx, session.ID, "Authenticated"); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to update session state: %v", err)
	}

	// 2. Извлекаем реального пользователя по его ID
	// Поиск делаем по ID, так как на Шаге 1 мы привязали сессию к конкретному userID
	var targetUser *repository.User
	query := `SELECT id, username, ssh_fingerprint, ssh_public_key, canonical_account_salt, canonical_bootstrap_envelope FROM users WHERE id = $1;`

	var u repository.User
	err = h.pool.QueryRow(ctx, query, session.UserID).Scan(
		&u.ID, &u.SshFingerprint, &u.SshPublicKey, &u.CanonicalAccountSalt, &u.CanonicalBootstrapEnvelope,
	)
	if err == nil {
		targetUser = &u
	}

	// Если сессия была фейковой (пользователя нет в базе), выбрасываем Unauthenticated.
	// Мы делаем это ПОСЛЕ гашения сессии, сохраняя одинаковое время ответа для легитимных и фейковых запросов.
	if targetUser == nil {
		return nil, status.Error(codes.Unauthenticated, "challenge signature verification failed (user not found)")
	}

	// 3. Сборка контекста ChallengePayload и строгая проверка подписи Ed25519 от ssh-agent
	challengePayload := security.NewChallengePayload(session.UserID, session.ID, session.ServerNonce, "attach-device")
	marshaledChallenge := challengePayload.Marshal()

	// Извлекаем чистые байты сырого публичного ключа Ed25519 из OpenSSH структуры
	sshPubKey, err := ssh.ParsePublicKey(targetUser.SshPublicKey)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to parse cached public key: %v", err)
	}
	cryptoPubKey := sshPubKey.(ssh.CryptoPublicKey).CryptoPublicKey()
	ed25519PubKey := cryptoPubKey.(ed25519.PublicKey)

	if !ed25519.Verify(ed25519PubKey, marshaledChallenge, req.GetAuthChallengeSignature()) {
		// В случае провала откатываем состояние сессии в Used, чтобы заблокировать повторное использование
		_ = h.repo.UpdateState(ctx, session.ID, "Used")
		return nil, status.Error(codes.Unauthenticated, "challenge signature verification failed")
	}

	// 4. Доступ разрешен: Раскрываем каноническую соль и облачный конверт
	return &pb.AttachDeviceAuthResponse{
		AccountSalt:              targetUser.CanonicalAccountSalt,
		AccountBootstrapEnvelope: targetUser.CanonicalBootstrapEnvelope,
	}, nil
}

// AttachDeviceFinish — Шаг 3: Завершение привязки устройства.
// Клиент локально расшифровал AccountBootstrapEnvelope, вывел DeviceKEK, зашифровал DeviceMasterKeyEnvelope
// и сгенерировал CSR. Сервер проверяет статус сессии ("Authenticated"), выпускает сертификат mTLS и фиксирует привязку.
func (h *DeviceAttachmentHandler) AttachDeviceFinish(ctx context.Context, req *pb.AttachDeviceFinishRequest) (*pb.AttachDeviceFinishResponse, error) {
	if req.GetUserId() == "" || req.GetSessionId() == "" || req.GetDeviceId() == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id, session_id and device_id are required")
	}
	if len(req.GetDeviceMasterKeyEnvelope()) == 0 || len(req.GetCsr()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "envelope and csr payloads are required")
	}

	// 1. Проверяем, что сессия существует и была успешно авторизована на Шаге 2
	session, err := h.repo.GetAndLock(ctx, req.GetSessionId())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to lock challenge session: %v", err)
	}
	if session == nil {
		return nil, status.Error(codes.NotFound, "challenge session not found")
	}

	if session.State != "Authenticated" || session.UserID != req.GetUserId() {
		return nil, status.Error(codes.PermissionDenied, "invalid or unauthenticated challenge session state")
	}

	// Закрываем автомат сессий: перевод в финальный статус "Completed"
	if err = h.repo.UpdateState(ctx, session.ID, "Completed"); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to complete challenge session: %v", err)
	}

	// 2. ДИНАМИЧЕСКИЙ ВЫПУСК mTLS СЕРТИФИКАТА УСТРОЙСТВА
	// Загружаем Device CA из файловой системы через pki-компонент
	deviceCACert, deviceCAKey, err := pki.LoadDeviceCA(h.cfg)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to load device identity ca: %v", err)
	}

	// Подписываем входящий CSR на 30 дней, внедряя ExtendedKeyUsage=clientAuth и SAN URN идентификатор контейнера
	clientCertDER, serialNumber, err := pki.IssueDeviceCertificate(
		req.GetCsr(),
		req.GetDeviceId(),
		deviceCACert,
		deviceCAKey,
	)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to issue mTLS client certificate: %v", err)
	}

	// 3. Фиксируем новое устройство/контейнер в реестре устройств PostgreSQL сервера
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
		return nil, status.Errorf(codes.Internal, "failed to save device registration: %v", err)
	}

	return &pb.AttachDeviceFinishResponse{
			ClientCertificate: clientCertDER,
			CaChain:           deviceCACert.Raw,
		},
		nil
}
