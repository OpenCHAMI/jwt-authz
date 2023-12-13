package issuer

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"log"
)

// GeneratePrivateKey creates a RSA Private Key of specified byte size
func GeneratePrivateKey(bitSize int) (*rsa.PrivateKey, error) {
	// Private Key generation
	privateKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		return nil, err
	}

	// Validate Private Key
	err = privateKey.Validate()
	if err != nil {
		return nil, err
	}

	log.Println("Private Key generated")
	return privateKey, nil
}

func SignPSSMessage(message []byte, privateKey *rsa.PrivateKey, hash crypto.Hash) ([]byte, error) {
	// Hash the message with the given hash function
	hashed, err := hashMessage(message, hash)
	if err != nil {
		return nil, err
	}

	signature, err := rsa.SignPSS(rand.Reader, privateKey, hash, hashed, nil)
	if err != nil {
		return nil, err
	}

	return signature, nil
}

func VerifyPSSMessage(message []byte, signature []byte, publicKey *rsa.PublicKey, hash crypto.Hash) error {
	// Hash the message with the given hash function
	hashed, err := hashMessage(message, hash)
	if err != nil {
		return err
	}

	return rsa.VerifyPSS(publicKey, hash, hashed, signature, nil)
}

func hashMessage(message []byte, hash crypto.Hash) ([]byte, error) {
	// Hash the message with the given hash function
	hashed := hash.New()
	_, err := hashed.Write(message)
	if err != nil {
		return nil, err
	}

	return hashed.Sum(nil), nil
}
