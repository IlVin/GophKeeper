package grpc

import (
	"context"
	"testing"

	"gophkeeper/internal/server/config"

	pb "gophkeeper/gen/go/gophkeeper/v1"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestRegistrationHandler_RegisterBegin_Success(t *testing.T) {
	var cfg config.Config
	handler := NewRegistrationHandler(cfg)

	req := &pb.RegisterBeginRequest{
		Username:     "testuser",
		SshPublicKey: []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA..."),
	}

	resp, err := handler.RegisterBegin(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.NotEmpty(t, resp.GetUserId())
	assert.NotEmpty(t, resp.GetSessionId())
	assert.Len(t, resp.GetServerNonce(), 32)
	assert.Len(t, resp.GetAccountSalt(), 32)
}

func TestRegistrationHandler_RegisterBegin_ValidationErrors(t *testing.T) {
	var cfg config.Config
	handler := NewRegistrationHandler(cfg)

	// Тест на пустой username
	reqNoUser := &pb.RegisterBeginRequest{
		Username:     "",
		SshPublicKey: []byte("mock-key"),
	}
	_, err := handler.RegisterBegin(context.Background(), reqNoUser)
	assert.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))

	// Тест на пустой SSH ключ
	reqNoKey := &pb.RegisterBeginRequest{
		Username:     "user",
		SshPublicKey: nil,
	}
	_, err = handler.RegisterBegin(context.Background(), reqNoKey)
	assert.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestRegistrationHandler_RegisterFinish_ValidationErrors(t *testing.T) {
	var cfg config.Config
	handler := NewRegistrationHandler(cfg)

	// Тест на отсутствие обязательных идентификаторов
	reqMissingIDs := &pb.RegisterFinishRequest{}
	_, err := handler.RegisterFinish(context.Background(), reqMissingIDs)
	assert.ErrorContains(t, err, "user_id, session_id and device_id are required")

	// Тест на отсутствие подписи
	reqNoSig := &pb.RegisterFinishRequest{
		UserId:    "u-uuid",
		SessionId: "s-uuid",
		DeviceId:  "d-uuid",
	}
	_, err = handler.RegisterFinish(context.Background(), reqNoSig)
	assert.ErrorContains(t, err, "authentication challenge signature is required")

	// Тест на отсутствие CSR
	reqNoCsr := &pb.RegisterFinishRequest{
		UserId:                 "u-uuid",
		SessionId:              "s-uuid",
		DeviceId:               "d-uuid",
		AuthChallengeSignature: []byte("sig"),
	}
	_, err = handler.RegisterFinish(context.Background(), reqNoCsr)
	assert.ErrorContains(t, err, "csr bytes are required")

	// Тест на отсутствие конверта аккаунта
	reqNoBootstrap := &pb.RegisterFinishRequest{
		UserId:                 "u-uuid",
		SessionId:              "s-uuid",
		DeviceId:               "d-uuid",
		AuthChallengeSignature: []byte("sig"),
		Csr:                    []byte("csr"),
	}
	_, err = handler.RegisterFinish(context.Background(), reqNoBootstrap)
	assert.ErrorContains(t, err, "account bootstrap envelope is required")

	// Тест на отсутствие локального конверта устройства
	reqNoDeviceEnv := &pb.RegisterFinishRequest{
		UserId:                   "u-uuid",
		SessionId:                "s-uuid",
		DeviceId:                 "d-uuid",
		AuthChallengeSignature:   []byte("sig"),
		Csr:                      []byte("csr"),
		AccountBootstrapEnvelope: []byte("boot-env"),
	}
	_, err = handler.RegisterFinish(context.Background(), reqNoDeviceEnv)
	assert.ErrorContains(t, err, "device master key envelope is required")

	// Успешная обработка валидного запроса (заглушка)
	reqValid := &pb.RegisterFinishRequest{
		UserId:                   "u-uuid",
		SessionId:                "s-uuid",
		DeviceId:                 "d-uuid",
		AuthChallengeSignature:   []byte("sig"),
		Csr:                      []byte("csr"),
		AccountBootstrapEnvelope: []byte("boot-env"),
		DeviceMasterKeyEnvelope:  []byte("dev-env"),
	}
	resp, err := handler.RegisterFinish(context.Background(), reqValid)
	require.NoError(t, err)
	assert.NotEmpty(t, resp.GetClientCertificate())
	assert.NotEmpty(t, resp.GetCaChain())
}
