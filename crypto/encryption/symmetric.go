package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"

	"io"
)

type Symmetric struct{}

func (s Symmetric) Encrypt(plaintext []byte, key interface{}) (string, error) {
	k, ok := key.([]byte)
	if !ok {
		return "", ErrInvalidKeyType
	}

	block, err := aes.NewCipher(k)
	if err != nil {
		return "", err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := aead.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func (s Symmetric) Decrypt(ciphertext string, key interface{}) ([]byte, error) {
	k, ok := key.([]byte)
	if !ok {
		return nil, ErrInvalidKeyType
	}
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := aead.NonceSize()
	if len(data) < nonceSize {
		return nil, ErrCiphertextTooShort
	}
	nonce, ciphertextBytes := data[:nonceSize], data[nonceSize:]
	return aead.Open(nil, nonce, ciphertextBytes, nil)
}
