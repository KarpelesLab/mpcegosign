package mpc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
)

// GenerateX25519 generates an ephemeral X25519 key pair.
func GenerateX25519() (*ecdh.PrivateKey, error) {
	return ecdh.X25519().GenerateKey(rand.Reader)
}

// EncryptForParty encrypts data using ECDH shared secret (our private + their public) + AES-256-GCM.
func EncryptForParty(ourPrivate *ecdh.PrivateKey, theirPublic *ecdh.PublicKey, plaintext []byte) ([]byte, error) {
	shared, err := ourPrivate.ECDH(theirPublic)
	if err != nil {
		return nil, fmt.Errorf("ECDH: %w", err)
	}

	// Derive AES key from shared secret
	key := sha256.Sum256(shared)

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// DecryptFromParty decrypts data using ECDH shared secret (our private + their public) + AES-256-GCM.
func DecryptFromParty(ourPrivate *ecdh.PrivateKey, theirPublic *ecdh.PublicKey, ciphertext []byte) ([]byte, error) {
	shared, err := ourPrivate.ECDH(theirPublic)
	if err != nil {
		return nil, fmt.Errorf("ECDH: %w", err)
	}

	key := sha256.Sum256(shared)

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	return gcm.Open(nil, ciphertext[:nonceSize], ciphertext[nonceSize:], nil)
}
