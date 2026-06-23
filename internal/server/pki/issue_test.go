package pki

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestIssueDeviceCertificate_FailsIfInputsInvalid проверяет защиту фабрики
// выпуска паспортов от паник при передаче пустых аргументов или nil-указателей.
func TestIssueDeviceCertificate_FailsIfInputsInvalid(t *testing.T) {
	cert, serial, err := IssueDeviceCertificate(nil, "", nil, nil)

	assert.Error(t, err)
	assert.Nil(t, cert)
	assert.Nil(t, serial)
	assert.Contains(t, err.Error(), "invalid inputs for device certificate issuance")
}
