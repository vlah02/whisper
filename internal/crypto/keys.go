package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

type Identity struct {
	Username   string
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey
}

func NewIdentity(username string) (*Identity, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	return &Identity{
		Username:   username,
		PublicKey:  publicKey,
		PrivateKey: privateKey,
	}, nil
}

func (i *Identity) GetFingerprint() string {
	hash := sha256.Sum256(i.PublicKey)
	return base64.StdEncoding.EncodeToString(hash[:])[:16]
}

func (i *Identity) Sign(message []byte) []byte {
	return ed25519.Sign(i.PrivateKey, message)
}

func (i *Identity) Verify(message, signature []byte) bool {
	return ed25519.Verify(i.PublicKey, message, signature)
}

func VerifyPeerSignature(peerPublicKey ed25519.PublicKey, message, signature []byte) bool {
	return ed25519.Verify(peerPublicKey, message, signature)
}

func (i *Identity) PublicKeyToString() string {
	return base64.StdEncoding.EncodeToString(i.PublicKey)
}

func PublicKeyFromString(keyStr string) (ed25519.PublicKey, error) {
	keyBytes, err := base64.StdEncoding.DecodeString(keyStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key: %w", err)
	}
	
	if len(keyBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key size")
	}
	
	return ed25519.PublicKey(keyBytes), nil
}

func (i *Identity) ParsePublicKeyFromString(keyStr string) (ed25519.PublicKey, error) {
	return PublicKeyFromString(keyStr)
}

func (i *Identity) GetFingerprintFromPublicKey(pubKey ed25519.PublicKey) string {
	hash := sha256.Sum256(pubKey)
	return base64.StdEncoding.EncodeToString(hash[:])[:16] // First 16 chars for readability
}

func (i *Identity) SignMessage(message []byte) (string, error) {
	signature := ed25519.Sign(i.PrivateKey, message)
	return base64.StdEncoding.EncodeToString(signature), nil
}

func (i *Identity) VerifySignature(signature string, message []byte, peerPublicKey ed25519.PublicKey) bool {
	sigBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false
	}
	return ed25519.Verify(peerPublicKey, message, sigBytes)
}