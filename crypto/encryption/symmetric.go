package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"
)

// Symmetric provides methods for symmetric encryption using AES-GCM.
// It implements the Encryption interface.
type Symmetric struct{}

// Encrypt encrypts the given plaintext using AES-GCM with the provided key.
// The key must be a byte slice ([]byte) representing the AES key.
// It returns a base64-encoded string which consists of the nonce prepended to the ciphertext.
func (s Symmetric) Encrypt(plaintext []byte, key interface{}) (string, error) {
	// Ensure the provided key is of type []byte.
	k, ok := key.([]byte)
	if !ok {
		return "", ErrInvalidKeyType
	}

	// Create a new AES cipher block using the provided key.
	block, err := aes.NewCipher(k)
	if err != nil {
		return "", err
	}

	// Create a GCM cipher instance from the AES block.
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Generate a random nonce of the required size.
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	// Encrypt the plaintext. The nonce is automatically prepended to the ciphertext.
	ciphertext := aead.Seal(nonce, nonce, plaintext, nil)

	// Return the ciphertext as a base64-encoded string.
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts the provided base64-encoded ciphertext using AES-GCM with the given key.
// The key must be a byte slice ([]byte) representing the AES key.
// It returns the decrypted plaintext or an error if decryption fails.
func (s Symmetric) Decrypt(ciphertext string, key interface{}) ([]byte, error) {
	// Ensure the provided key is of type []byte.
	k, ok := key.([]byte)
	if !ok {
		return nil, ErrInvalidKeyType
	}

	// Decode the base64-encoded ciphertext.
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, err
	}

	// Create a new AES cipher block with the provided key.
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}

	// Create a GCM cipher instance from the AES block.
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Determine the nonce size from the GCM instance.
	nonceSize := aead.NonceSize()
	if len(data) < nonceSize {
		return nil, ErrCiphertextTooShort
	}

	// Extract the nonce and the actual ciphertext.
	nonce, ciphertextBytes := data[:nonceSize], data[nonceSize:]

	// Decrypt and return the plaintext.
	return aead.Open(nil, nonce, ciphertextBytes, nil)
}
