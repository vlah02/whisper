package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

type SessionKey struct {
	Key   []byte
	Nonce []byte
}

func GenerateSharedSecret(ourPrivateKey, theirPublicKey []byte) ([]byte, error) {
	if len(ourPrivateKey) != 32 || len(theirPublicKey) != 32 {
		return nil, fmt.Errorf("invalid key sizes")
	}

	var sharedSecret [32]byte
	curve25519.ScalarMult(&sharedSecret, (*[32]byte)(ourPrivateKey), (*[32]byte)(theirPublicKey))
	
	return sharedSecret[:], nil
}

func DeriveSessionKey(sharedSecret []byte, info string) (*SessionKey, error) {
	hkdfReader := hkdf.New(sha256.New, sharedSecret, nil, []byte(info))
	
	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, key); err != nil {
		return nil, fmt.Errorf("failed to derive session key: %w", err)
	}

	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	return &SessionKey{
		Key:   key,
		Nonce: nonce,
	}, nil
}

func (sk *SessionKey) EncryptMessage(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(sk.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	
	result := make([]byte, len(nonce)+len(ciphertext))
	copy(result, nonce)
	copy(result[len(nonce):], ciphertext)
	
	return result, nil
}

func (sk *SessionKey) DecryptMessage(encrypted []byte) ([]byte, error) {
	block, err := aes.NewCipher(sk.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(encrypted) < nonceSize {
		return nil, fmt.Errorf("encrypted message too short")
	}

	nonce := encrypted[:nonceSize]
	ciphertext := encrypted[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt message: %w", err)
	}

	return plaintext, nil
}

func GenerateEphemeralKeyPair() (private, public []byte, err error) {
	private = make([]byte, 32)
	if _, err := rand.Read(private); err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	public = make([]byte, 32)
	curve25519.ScalarBaseMult((*[32]byte)(public), (*[32]byte)(private))

	return private, public, nil
}

func NewSessionKey(ourEdPrivateKey, theirEdPublicKey []byte) (*SessionKey, error) {
	if len(ourEdPrivateKey) != 64 {
		return nil, fmt.Errorf("invalid private key length: %d, expected 64", len(ourEdPrivateKey))
	}
	if len(theirEdPublicKey) != 32 {
		return nil, fmt.Errorf("invalid public key length: %d, expected 32", len(theirEdPublicKey))
	}
	
	ourPublicKey := ourEdPrivateKey[32:]
	
	var key1, key2 []byte
	if string(ourPublicKey) < string(theirEdPublicKey) {
		key1, key2 = ourPublicKey, theirEdPublicKey
	} else {
		key1, key2 = theirEdPublicKey, ourPublicKey
	}
	
	combined := append(key1, key2...)
	sharedSecret := sha256.Sum256(combined)
	
	return DeriveSessionKey(sharedSecret[:], "whisper-session")
}

func NewSessionKeyFromExchange(ourEdPrivateKey, theirEdPublicKey, keyExchangeData []byte) (*SessionKey, error) {
	return NewSessionKey(ourEdPrivateKey, theirEdPublicKey)
}

func (sk *SessionKey) GetKeyExchangeData() []byte {
	return []byte("key-exchange-placeholder")
}

func (sk *SessionKey) Encrypt(message string) (string, error) {
	encrypted, err := sk.EncryptMessage([]byte(message))
	if err != nil {
		return "", err
	}
	
	return base64.StdEncoding.EncodeToString(encrypted), nil
}

func (sk *SessionKey) Decrypt(encryptedMessage string) (string, error) {
	encryptedBytes, err := base64.StdEncoding.DecodeString(encryptedMessage)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64: %w", err)
	}
	
	decrypted, err := sk.DecryptMessage(encryptedBytes)
	if err != nil {
		return "", err
	}
	
	return string(decrypted), nil
}