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

// HybridPayload is the structure used to hold the encrypted AES key and ciphertext.
// Both fields are encoded in base64.
type HybridPayload struct {
	EncryptedKey string `json:"encrypted_key"` // RSA-encrypted AES key.
	Ciphertext   string `json:"ciphertext"`    // AES-GCM encrypted message.
}

// Hybrid provides methods for hybrid encryption and decryption.
// It uses RSA to encrypt/decrypt an AES key, and AES-GCM for symmetric encryption.
type Hybrid struct{}

// Encrypt encrypts the given plaintext using a hybrid encryption scheme.
// It performs the following steps:
//  1. Generates a random 256-bit AES key.
//  2. Encrypts the plaintext using AES-GCM with the AES key.
//  3. Encrypts the AES key using RSA OAEP with the provided RSA public key.
//  4. Encodes both the encrypted AES key and the ciphertext in a JSON payload,
//     and returns the entire payload as a base64-encoded string.
func (h Hybrid) Encrypt(plaintext []byte, key interface{}) (string, error) {
	// Validate and cast the provided key to an RSA public key.
	pub, ok := key.(*rsa.PublicKey)
	if !ok {
		return "", ErrInvalidKeyType
	}

	// Generate a random 256-bit AES key.
	aesKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, aesKey); err != nil {
		return "", err
	}

	// Create a new AES cipher block with the generated key.
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return "", err
	}

	// Create a GCM cipher instance.
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Generate a random nonce of the appropriate size.
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	// Encrypt the plaintext with AES-GCM; the nonce is prepended to the ciphertext.
	ciphertext := aead.Seal(nonce, nonce, plaintext, nil)

	// Encrypt the AES key using RSA OAEP with SHA-256.
	encryptedKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, aesKey, nil)
	if err != nil {
		return "", err
	}

	// Create a payload containing the base64-encoded encrypted key and ciphertext.
	payload := HybridPayload{
		EncryptedKey: base64.StdEncoding.EncodeToString(encryptedKey),
		Ciphertext:   base64.StdEncoding.EncodeToString(ciphertext),
	}

	// Marshal the payload to JSON.
	data, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	// Return the JSON payload as a base64-encoded string.
	return base64.StdEncoding.EncodeToString(data), nil
}

// Decrypt decrypts a hybrid encrypted message using the provided RSA private key.
// It expects the input to be a base64-encoded JSON payload that contains the RSA-encrypted AES key
// and the AES-GCM encrypted ciphertext. The function performs the following steps:
//  1. Base64-decodes and unmarshals the JSON payload into a HybridPayload struct.
//  2. Decodes and decrypts the AES key using RSA OAEP with SHA-256.
//  3. Decodes the ciphertext and extracts the nonce.
//  4. Decrypts the ciphertext using AES-GCM and returns the plaintext.
func (h Hybrid) Decrypt(ciphertext string, key interface{}) ([]byte, error) {
	// Validate and cast the provided key to an RSA private key.
	priv, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, ErrInvalidKeyType
	}

	// Base64-decode the JSON payload.
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, err
	}

	// Unmarshal the JSON data into a HybridPayload struct.
	var payload HybridPayload
	if err = json.Unmarshal(data, &payload); err != nil {
		return nil, err
	}

	// Decode the RSA-encrypted AES key from base64.
	encryptedKey, err := base64.StdEncoding.DecodeString(payload.EncryptedKey)
	if err != nil {
		return nil, err
	}

	// Decode the ciphertext from base64.
	ciphertextBytes, err := base64.StdEncoding.DecodeString(payload.Ciphertext)
	if err != nil {
		return nil, err
	}

	// Decrypt the AES key using RSA OAEP with SHA-256.
	aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, encryptedKey, nil)
	if err != nil {
		return nil, err
	}

	// Create a new AES cipher block with the decrypted AES key.
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}

	// Create a GCM cipher instance.
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Ensure the ciphertext length is sufficient to contain the nonce.
	nonceSize := aead.NonceSize()
	if len(ciphertextBytes) < nonceSize {
		return nil, ErrCiphertextTooShort
	}

	// Extract the nonce and the actual encrypted data.
	nonce, encryptedData := ciphertextBytes[:nonceSize], ciphertextBytes[nonceSize:]

	// Decrypt the ciphertext using AES-GCM.
	return aead.Open(nil, nonce, encryptedData, nil)
}
