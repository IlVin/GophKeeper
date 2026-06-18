package security

import "fmt"

const (
	DerivationSignatureSize = 64
	KEKSize                 = 32
	SaltSize                = 32
	DeviceIDSize            = 16
)

type DerivationSignature [DerivationSignatureSize]byte
type AccountUnlockKey [KEKSize]byte
type DeviceKEK [KEKSize]byte
type AccountSalt [SaltSize]byte
type DeviceID [DeviceIDSize]byte

func NewDerivationSignature(raw []byte) (DerivationSignature, error) {
	if len(raw) != DerivationSignatureSize {
		return DerivationSignature{}, fmt.Errorf("invalid derivation signature length: got=%d want=%d", len(raw), DerivationSignatureSize)
	}

	var sig DerivationSignature
	copy(sig[:], raw)

	return sig, nil
}
