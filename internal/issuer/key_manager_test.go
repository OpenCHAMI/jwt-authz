package issuer

import (
	"crypto"
	"crypto/rsa"
	"testing"
)

func TestGeneratePrivateKey(t *testing.T) {
	bitSize := 2048

	privateKey, err := GeneratePrivateKey(bitSize)
	if err != nil {
		t.Errorf("Failed to generate private key: %v", err)
	}

	// Validate Private Key
	err = privateKey.Validate()
	if err != nil {
		t.Errorf("Private key validation failed: %v", err)
	}

	// Check key size
	if privateKey.Size() != bitSize/8 {
		t.Errorf("Private key size mismatch")
	}

	// Check key type
	if _, ok := privateKey.Public().(*rsa.PublicKey); !ok {
		t.Errorf("Invalid private key type")
	}

	t.Log("Private key generation test passed")
}

func TestSignMessage(t *testing.T) {
	bitSize := 2048

	privateKey, err := GeneratePrivateKey(bitSize)
	if err != nil {
		t.Errorf("Failed to generate private key: %v", err)
	}

	message := []byte("Hello, world!")

	_, err = SignPSSMessage(message, privateKey, crypto.SHA256)
	if err != nil {
		t.Errorf("Failed to sign message: %v", err)
	}

	t.Log("SignMessage test passed")
}

func TestVerifyPSSMessage(t *testing.T) {
	bitSize := 2048

	privateKey, err := GeneratePrivateKey(bitSize)
	if err != nil {
		t.Errorf("Failed to generate private key: %v", err)
	}

	message := []byte("Hello, world!")
	signature, err := SignPSSMessage(message, privateKey, crypto.SHA256)
	if err != nil {
		t.Errorf("Failed to sign message: %v", err)
	}

	err = VerifyPSSMessage(message, signature, privateKey.Public().(*rsa.PublicKey), crypto.SHA256)
	if err != nil {
		t.Errorf("Failed to verify PSS message: %v", err)
	}

	t.Log("VerifyPSSMessage test passed")
}
