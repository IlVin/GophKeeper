package grpc

import (
	"context"
	"crypto/rand"

	"gophkeeper/internal/server/config"

	// ИСПРАВЛЕНО: Канонический путь импорта обновленных protobuf-файлов
	pb "gophkeeper/gen/go/gophkeeper/v1"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type RegistrationHandler struct {
	pb.UnimplementedRegistrationServer
	cfg config.Config
}

// NewRegistrationHandler конструирует обработчик регистрации.
func NewRegistrationHandler(cfg config.Config) *RegistrationHandler {
	return &RegistrationHandler{
		cfg: cfg,
	}
}

// RegisterBegin — первый шаг регистрации (выполняется через чистый TLS 1.3).
// Генерирует уникальный ID сессии, соль аккаунта и случайный криптографический nonce для проверки владения SSH-ключом.
func (h *RegistrationHandler) RegisterBegin(ctx context.Context, req *pb.RegisterBeginRequest) (*pb.RegisterBeginResponse, error) {
	if req.GetUsername() == "" {
		return nil, status.Error(codes.InvalidArgument, "username cannot be empty")
	}
	// ИСПРАВЛЕНО: Заменен старый геттер GetSshPublicKeyBytes() на GetSshPublicKey()
	if len(req.GetSshPublicKey()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "ssh public key cannot be empty")
	}

	// 1. Генерируем идентификаторы для сессии челленджа
	userID := uuid.New().String()
	sessionID := uuid.New().String()

	// 2. Генерируем 32-байтный случайный серверный nonce через OS CSPRNG
	serverNonce := make([]byte, 32)
	if _, err := rand.Read(serverNonce); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to generate server nonce: %v", err)
	}

	// 3. ДОБАВЛЕНО: По спецификации v4.0 сервер генерирует 32-байтовую соль аккаунта на шаге Begin
	accountSalt := make([]byte, 32)
	if _, err := rand.Read(accountSalt); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to generate account salt: %v", err)
	}

	// TODO: Здесь должна быть логика сохранения pending_session и accountSalt в кэш/БД с TTL до 5 минут

	return &pb.RegisterBeginResponse{
		UserId:      userID,
		AccountSalt: accountSalt, // ИСПРАВЛЕНО: Возвращаем соль клиенту по контракту
		SessionId:   sessionID,
		ServerNonce: serverNonce,
	}, nil
}

// RegisterFinish — второй шаг регистрации.
// Принимает подписанный челлендж, CSR и zero-knowledge конверты.
func (h *RegistrationHandler) RegisterFinish(ctx context.Context, req *pb.RegisterFinishRequest) (*pb.RegisterFinishResponse, error) {
	// ИСПРАВЛЕНО: Добавлена обязательная проверка device_id
	if req.GetUserId() == "" || req.GetSessionId() == "" || req.GetDeviceId() == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id, session_id and device_id are required")
	}
	// ИСПРАВЛЕНО: Заменен старый геттер GetSshSignature() на GetAuthChallengeSignature()
	if len(req.GetAuthChallengeSignature()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "authentication challenge signature is required")
	}
	// ИСПРАВЛЕНО: Заменен старый геттер GetCsrBytes() на GetCsr()
	if len(req.GetCsr()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "csr bytes are required")
	}

	// ИСПРАВЛЕНО: Добавлена проверка наличия обязательных криптографических конвертов для MVP v4.0
	if len(req.GetAccountBootstrapEnvelope()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "account bootstrap envelope is required")
	}
	if len(req.GetDeviceMasterKeyEnvelope()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "device master key envelope is required")
	}

	// УДАЛЕНО: req.GetAccountSalt() полностью вырезан из запроса Finish,
	// так как соль генерируется сервером в RegisterBegin и извлекается из кэша сессии.

	// TODO: Реализовать валидацию сессии, проверку подписи челленджа [register_first_device]
	// TODO: Реализовать подпись CSR с помощью встроенного CA и выпуск mTLS сертификата устройства

	// Временная заглушка: возвращаем структуру, полностью соответствующую новому register.proto
	return &pb.RegisterFinishResponse{
		// ИСПРАВЛЕНО: Поля приведены в точное соответствие с контрактом (ClientCertificate и CaChain)
		ClientCertificate: []byte("-----BEGIN CERTIFICATE-----\nMOCK_DEVICE_CERTIFICATE\n-----END CERTIFICATE-----"),
		CaChain:           []byte("-----BEGIN CERTIFICATE-----\nMOCK_CA_CHAIN\n-----END CERTIFICATE-----"),
	}, nil
}
