package grpc

import (
	"context"
	"crypto/rand"

	"gophkeeper/internal/server/config"

	// Используем ваш рабочий путь генерации protobuf-файлов
	pb "gophkeeper/gen/go/gophkeeper/v1"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type DeviceAttachmentHandler struct {
	pb.UnimplementedDeviceAttachmentServer
	cfg config.Config
}

// NewDeviceAttachmentHandler конструирует обработчик привязки устройств.
func NewDeviceAttachmentHandler(cfg config.Config) *DeviceAttachmentHandler {
	return &DeviceAttachmentHandler{
		cfg: cfg,
	}
}

// AttachDeviceBegin — Шаг 1: Инициация привязки нового контейнера.
// Сервер находит аккаунт по публичному SSH-ключу, создает временную сессию челленджа,
// генерирует nonce и возвращает ТОЛЬКО публичные параметры.
// ВАЖНО: соль аккаунта и облачный конверт жестко удерживаются (Withholding) для защиты от User Enumeration.
func (h *DeviceAttachmentHandler) AttachDeviceBegin(ctx context.Context, req *pb.AttachDeviceBeginRequest) (*pb.AttachDeviceBeginResponse, error) {
	if len(req.GetSshPublicKey()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "ssh public key cannot be empty")
	}

	// TODO: Логика поиска существующего пользователя по его публичному SSH-ключу.
	// Если ключ не зарегистрирован, возвращаем унифицированную ошибку для защиты от перебора.
	userID := uuid.New().String()
	sessionID := uuid.New().String()

	// Генерируем случайный серверный nonce через OS CSPRNG
	serverNonce := make([]byte, 32)
	if _, err := rand.Read(serverNonce); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to generate server nonce: %v", err)
	}

	// TODO: Сохранить в кэш/БД pending_session (sessionID, userID, serverNonce, state = "created") с TTL 5 минут

	return &pb.AttachDeviceBeginResponse{
		UserId:      userID,
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

	// TODO: Логика извлечения сессии из кэша, валидация по TTL (до 5 минут), проверка однократности использования сессии.
	// TODO: Верификация подписи req.GetAuthChallengeSignature() над ChallengePayload с помощью OpenSSH публичного ключа юзера.

	// TODO: Логика обновления статуса сессии в кэше/БД на state = "authenticated".

	// Мок-данные, возвращаемые только ПОСЛЕ успешной авторизации подписи:
	mockAccountSalt := make([]byte, 32)
	mockBootstrapEnvelope := []byte("mock-envelope")

	return &pb.AttachDeviceAuthResponse{
		AccountSalt:              mockAccountSalt,
		AccountBootstrapEnvelope: mockBootstrapEnvelope,
	}, nil
}

// AttachDeviceFinish — Шаг 3: Завершение привязки устройства.
// Клиент локально расшифровал AccountBootstrapEnvelope, вывел DeviceKEK, зашифровал DeviceMasterKeyEnvelope
// и сгенерировал CSR. Сервер проверяет статус сессии ("authenticated"), выпускает сертификат mTLS и фиксирует привязку.
func (h *DeviceAttachmentHandler) AttachDeviceFinish(ctx context.Context, req *pb.AttachDeviceFinishRequest) (*pb.AttachDeviceFinishResponse, error) {
	if req.GetUserId() == "" || req.GetSessionId() == "" || req.GetDeviceId() == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id, session_id and device_id are required")
	}
	if len(req.GetDeviceMasterKeyEnvelope()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "device master key envelope is required")
	}
	if len(req.GetCsr()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "csr payload is required")
	}

	// TODO: Логика проверки, что сессия существует, имеет статус "authenticated" и принадлежит данному UserId.
	// TODO: Валидация уникальности и синтаксиса UUID device_id.
	// TODO: Подпись входящего CSR с помощью Private CA сервера, генерация SAN URI в формате urn:gophkeeper:file:<device_id>.
	// TODO: Атомарное сохранение нового устройства в БД и удаление/погашение сессии челленджа (защита от Replay).

	return &pb.AttachDeviceFinishResponse{
		ClientCertificate: []byte("-----BEGIN CERTIFICATE-----\nMOCK_ATTACHED_DEVICE_CERTIFICATE\n-----END CERTIFICATE-----"),
		CaChain:           []byte("-----BEGIN CERTIFICATE-----\nMOCK_CA_CHAIN\n-----END CERTIFICATE-----"),
	}, nil
}
