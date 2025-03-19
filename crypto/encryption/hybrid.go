package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"

	"io"
)

type HybridPayload struct {
	EncryptedKey string `json:"encrypted_key"`
	Ciphertext   string `json:"ciphertext"`
}

type Hybrid struct{}

func (h Hybrid) Encrypt(plaintext []byte, key interface{}) (string, error) {
	pub, ok := key.(*rsa.PublicKey)
	if !ok {
		return "", ErrInvalidKeyType
	}

	aesKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, aesKey); err != nil {
		return "", err
	}
	block, err := aes.NewCipher(aesKey)
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

	encryptedKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, aesKey, nil)
	if err != nil {
		return "", err
	}
	payload := HybridPayload{
		EncryptedKey: base64.StdEncoding.EncodeToString(encryptedKey),
		Ciphertext:   base64.StdEncoding.EncodeToString(ciphertext),
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(data), nil
}

func (h Hybrid) Decrypt(ciphertext string, key interface{}) ([]byte, error) {
	priv, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, ErrInvalidKeyType
	}
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, err
	}
	var payload HybridPayload
	if err = json.Unmarshal(data, &payload); err != nil {
		return nil, err
	}
	encryptedKey, err := base64.StdEncoding.DecodeString(payload.EncryptedKey)
	if err != nil {
		return nil, err
	}
	ciphertextBytes, err := base64.StdEncoding.DecodeString(payload.Ciphertext)
	if err != nil {
		return nil, err
	}
	aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, encryptedKey, nil)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := aead.NonceSize()
	if len(ciphertextBytes) < nonceSize {
		return nil, ErrCiphertextTooShort
	}
	nonce, encryptedData := ciphertextBytes[:nonceSize], ciphertextBytes[nonceSize:]
	return aead.Open(nil, nonce, encryptedData, nil)
}
