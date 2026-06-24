package commands

import (
	"bytes"
	"fmt"
	pb "gophkeeper/gen/go/gophkeeper/v1"
	"gophkeeper/internal/client/repository"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// TestSyncResponse_Mapping проверяет корректность DTO-структуры ответа для E2E автоматизации.
func TestSyncResponse_Mapping(t *testing.T) {
	payload := SyncResponse{
		Pulled: 5,
		Pushed: 12,
	}

	assert.Equal(t, 5, payload.Pulled)
	assert.Equal(t, 12, payload.Pushed)
}

// TestSyncCommandFormatting_WithStandardOutput проверяет UX-отображение процесса репликации.
func TestSyncCommandFormatting_WithStandardOutput(t *testing.T) {
	v := viper.New()
	cli := NewCLI(v)
	cli.JSONOutput = false

	buf := new(bytes.Buffer)
	mockPayload := SyncResponse{
		Pulled: 3,
		Pushed: 0,
	}

	cli.PrintResult(buf, mockPayload, func() {
		fmt.Fprintf(buf, "  Скачано изменений из облака (Pull): %d\n", mockPayload.Pulled)
		fmt.Fprintf(buf, "  Загружено оффлайн-записей в облако (Push): %d\n", mockPayload.Pushed)
	})

	assert.Contains(t, buf.String(), "Скачано изменений из облака (Pull): 3")
	assert.Contains(t, buf.String(), "Загружено оффлайн-записей в облако (Push): 0")
}

// TestRecordVersion_IsDeleted_Mapping проверяет, что RecordVersion содержит IsDeleted.
func TestRecordVersion_IsDeleted_Mapping(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)

	// Создаем RecordVersion с is_deleted=1
	recordVersion := &pb.RecordVersion{
		RecordId:  "test-uuid-123",
		UpdatedAt: timestamppb.New(now),
		IsDeleted: 1,
	}

	assert.Equal(t, "test-uuid-123", recordVersion.GetRecordId())
	assert.Equal(t, now.Unix(), recordVersion.GetUpdatedAt().AsTime().Unix())
	assert.Equal(t, int32(1), recordVersion.GetIsDeleted(), "IsDeleted должен сохраняться в RecordVersion")

	// Проверяем, что is_deleted=0 работает корректно
	recordVersionActive := &pb.RecordVersion{
		RecordId:  "test-uuid-456",
		UpdatedAt: timestamppb.New(now),
		IsDeleted: 0,
	}
	assert.Equal(t, int32(0), recordVersionActive.GetIsDeleted(), "IsDeleted=0 должен корректно передаваться")
}

// TestSyncCheckRequest_ContainsIsDeleted проверяет, что SyncCheckRequest содержит is_deleted.
func TestSyncCheckRequest_ContainsIsDeleted(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)

	// Создаем SyncCheckRequest с локальными версиями
	localVersions := []*pb.RecordVersion{
		{
			RecordId:  "active-record",
			UpdatedAt: timestamppb.New(now),
			IsDeleted: 0,
		},
		{
			RecordId:  "deleted-record",
			UpdatedAt: timestamppb.New(now.Add(-5 * time.Minute)),
			IsDeleted: 1,
		},
	}

	request := &pb.SyncCheckRequest{
		LocalVersions: localVersions,
	}

	// Проверяем, что все версии содержат is_deleted
	for _, v := range request.GetLocalVersions() {
		if v.GetRecordId() == "deleted-record" {
			assert.Equal(t, int32(1), v.GetIsDeleted(), "Удаленная запись должна иметь is_deleted=1")
		}
		if v.GetRecordId() == "active-record" {
			assert.Equal(t, int32(0), v.GetIsDeleted(), "Активная запись должна иметь is_deleted=0")
		}
	}
}

// TestRecordVersionMeta_Structure проверяет структуру RecordVersionMeta.
func TestRecordVersionMeta_Structure(t *testing.T) {
	now := time.Now().UTC()

	meta := repository.RecordVersionMeta{
		UpdatedAt: now,
		IsDeleted: 1,
	}

	assert.Equal(t, now, meta.UpdatedAt)
	assert.Equal(t, int32(1), meta.IsDeleted)
}
