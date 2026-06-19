package grpc

import (
	"context"
	"fmt"

	pb "gophkeeper/gen/go/gophkeeper/v1" // Путь к автосгенерированным grpc-структурам
	"gophkeeper/internal/client/providers/sqlite"
	"gophkeeper/internal/client/providers/sshagent"
	"gophkeeper/internal/domain/security"

	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func ExecuteRegistrationFlow(
	ctx context.Context,
	serverAddr string,
	login string,
	pubKey ssh.PublicKey,
	fingerprint string,
	agent *sshagent.Client,
	sqlitePath string, // ДОБАВЛЕНО: путь к локальной sqlite БД
) error {
	tlsConfig, err := ConfigForBootstrap()
	if err != nil {
		return fmt.Errorf("tls config error: %w", err)
	}

	conn, err := grpc.NewClient(serverAddr, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	if err != nil {
		return fmt.Errorf("connect to server: %w", err)
	}
	defer conn.Close()

	client := pb.NewRegistrationClient(conn)

	// === ШАГ 1: RegisterBegin ===
	beginResp, err := client.RegisterBegin(ctx, &pb.RegisterBeginRequest{
		Username:     login,
		SshPublicKey: pubKey.Marshal(),
	})
	if err != nil {
		return fmt.Errorf("RegisterBegin failed: %w", err)
	}

	sessionID := beginResp.GetSessionId()
	serverNonce := beginResp.GetServerNonce()
	userID := beginResp.GetUserId()

	fmt.Printf("Received challenge session. SessionID: %s\n", sessionID)

	// === СБОРКА ЧЕЛЛЕНДЖА НА КЛИЕНТЕ ===
	challengePayload := []byte(fmt.Sprintf("%s:%s:register", sessionID, serverNonce))

	sshSig, err := agent.Sign(fingerprint, challengePayload)
	if err != nil {
		return fmt.Errorf("failed to sign authentication challenge via ssh-agent: %w", err)
	}

	// === ВЫВОД ЛОКАЛЬНЫХ КЛЮЧЕЙ ===
	derivationPayload, err := security.MarshalDerivationPayload(userID, []byte(fingerprint))
	if err != nil {
		return fmt.Errorf("prepare derivation payload: %w", err)
	}

	rawDerivationSig, err := agent.SignED25519Raw(fingerprint, derivationPayload)
	if err != nil {
		return fmt.Errorf("failed to generate derivation signature: %w", err)
	}

	var salt security.AccountSalt
	copy(salt[:], beginResp.GetAccountSalt())

	derivSig, _ := security.NewDerivationSignature(rawDerivationSig)
	accountUnlockKey, err := security.DeriveAccountUnlockKey(derivSig, salt)
	if err != nil {
		return fmt.Errorf("local key derivation failed: %w", err)
	}

	// ПОЛУЧЕНИЕ/ГЕНЕРАЦИЯ DEVICE ID ИЗ SQLITE ===
	deviceIDStr, err := sqlite.GetOrCreateDeviceID(sqlitePath)
	if err != nil {
		return fmt.Errorf("failed to handle database-bound DeviceID: %w", err)
	}
	fmt.Printf("Database-bound DeviceID loaded: %s\n", deviceIDStr)

	// === ШАГ 2: RegisterFinish ===
	_, err = client.RegisterFinish(ctx, &pb.RegisterFinishRequest{
		UserId:                   userID,
		SessionId:                sessionID,
		DeviceId:                 deviceIDStr, // Передаем честный ID контейнера
		AuthChallengeSignature:   sshSig.Blob,
		AccountBootstrapEnvelope: []byte{},
		DeviceMasterKeyEnvelope:  []byte{},
		Csr:                      []byte{},
	})
	if err != nil {
		return fmt.Errorf("RegisterFinish activation failed: %w", err)
	}

	_ = accountUnlockKey
	return nil
}
