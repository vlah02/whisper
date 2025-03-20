package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
)

// LocalOnionPrivateKey holds the RSA private key used for onion routing.
var LocalOnionPrivateKey *rsa.PrivateKey

// LocalOnionPublicKey holds the RSA public key corresponding to the local private key.
var LocalOnionPublicKey *rsa.PublicKey

// RemoteOnionPublicKeys stores RSA public keys of remote peers, mapped by their identifiers.
var RemoteOnionPublicKeys = make(map[string]*rsa.PublicKey)

// GenerateOnionKeys generates a new RSA key pair for onion routing.
// It initializes the global LocalOnionPrivateKey and LocalOnionPublicKey variables.
// The function logs a fatal error if key generation fails.
func GenerateOnionKeys() {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Failed to generate RSA key pair: %v", err)
	}
	LocalOnionPrivateKey = key
	LocalOnionPublicKey = &key.PublicKey
}

// EncodeRSAPublicKey converts an RSA public key into a PEM-encoded string.
// It returns the PEM string or an error if the encoding fails.
func EncodeRSAPublicKey(pub *rsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	}
	return string(pem.EncodeToMemory(block)), nil
}

// ParseRSAPublicKey decodes a PEM-encoded public key string and returns an RSA public key.
// It returns an error if the PEM block is invalid or the decoded key is not an RSA public key.
func ParseRSAPublicKey(pemStr string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("failed to decode PEM block containing public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not RSA public key")
	}
	return rsaPub, nil
}
