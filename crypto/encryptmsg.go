package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"

	"whisper/message"
)

func EncryptMessage(msg message.Message, key []byte) (string, error) {
	plaintext, err := msg.Serialize()
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
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

func DecryptMessage(encrypted string, key []byte) (message.Message, error) {
	var msg message.Message

	ciphertext, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return msg, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return msg, err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return msg, err
	}

	nonceSize := aead.NonceSize()
	if len(ciphertext) < nonceSize {
		return msg, errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return msg, err
	}

	return message.DeserializeMessage(plaintext)
}
