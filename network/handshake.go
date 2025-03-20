package network

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"strings"

	"golang.org/x/crypto/curve25519"
	"whisper/crypto"
)

// ReadPEM reads lines from the provided reader until an end marker
// (i.e. a line starting with "-----END") is encountered. It returns
// the concatenated PEM string.
func ReadPEM(reader *bufio.Reader) (string, error) {
	var lines []string
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return "", err
		}
		line = strings.TrimRight(line, "\r\n")
		lines = append(lines, line)
		if strings.HasPrefix(line, "-----END") {
			break
		}
	}
	return strings.Join(lines, "\n"), nil
}

// GenerateKeyPair generates an ephemeral Curve25519 key pair used during the handshake.
func GenerateKeyPair() (privateKey, publicKey []byte, err error) {
	privateKey = make([]byte, 32)
	if _, err = io.ReadFull(rand.Reader, privateKey); err != nil {
		return nil, nil, err
	}
	// Clamp the private key as required by Curve25519.
	privateKey[0] &= 248
	privateKey[31] &= 127
	privateKey[31] |= 64

	publicKey, err = curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, publicKey, nil
}

// ComputeSharedSecret computes the shared secret between a local private key and
// a remote public key using Curve25519, then hashes the result with SHA-256.
func ComputeSharedSecret(privateKey, remotePublicKey []byte) ([]byte, error) {
	sharedSecret, err := curve25519.X25519(privateKey, remotePublicKey)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(sharedSecret)
	return hash[:], nil
}

// exchangeOnionKeys handles the exchange of RSA onion keys between peers.
// It sends the local onion public key and reads the remote onion public key,
// validates its format, and stores it in the global RemoteOnionPublicKeys map.
func exchangeOnionKeys(reader *bufio.Reader, conn net.Conn, remoteID string) error {
	localOnionPubPEM, err := crypto.EncodeRSAPublicKey(crypto.LocalOnionPublicKey)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(conn, "%s\n", localOnionPubPEM); err != nil {
		return err
	}

	remoteOnionPubPEM, err := ReadPEM(reader)
	if err != nil {
		return err
	}
	fmt.Printf("DEBUG: Received remote onion PEM: %q\n", remoteOnionPubPEM)
	if remoteOnionPubPEM == "" {
		return fmt.Errorf("received empty onion public key")
	}
	if !strings.HasPrefix(remoteOnionPubPEM, "-----BEGIN PUBLIC KEY-----") {
		return fmt.Errorf("unexpected onion public key format: %s", remoteOnionPubPEM)
	}

	remoteOnionPub, err := crypto.ParseRSAPublicKey(remoteOnionPubPEM)
	if err != nil {
		return fmt.Errorf("failed to parse remote onion public key: %v", err)
	}
	crypto.RemoteOnionPublicKeys[remoteID] = remoteOnionPub
	return nil
}

// HandshakeInitiator initiates the handshake from the connecting peer.
// It performs the following steps:
//  1. Generates an ephemeral Curve25519 key pair and sends the public key.
//  2. Reads the remote peer's ephemeral public key and computes the session key.
//  3. Sends local identity and connection type.
//  4. Receives the remote peer's identity.
//  5. Exchanges RSA onion public keys.
func HandshakeInitiator(conn net.Conn, localID, connType string) ([]byte, string, error) {
	// Generate and send ephemeral key pair.
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		return nil, "", err
	}
	pubStr := base64.StdEncoding.EncodeToString(pub)
	if _, err := fmt.Fprintf(conn, "%s\n", pubStr); err != nil {
		return nil, "", err
	}

	reader := bufio.NewReader(conn)
	// Read remote ephemeral public key.
	remotePubStr, err := reader.ReadString('\n')
	if err != nil {
		return nil, "", err
	}
	remotePubStr = strings.TrimSpace(remotePubStr)
	remotePub, err := base64.StdEncoding.DecodeString(remotePubStr)
	if err != nil {
		return nil, "", fmt.Errorf("failed to decode remote ephemeral key: %v", err)
	}

	// Compute the shared session key.
	sessionKey, err := ComputeSharedSecret(priv, remotePub)
	if err != nil {
		return nil, "", err
	}

	// Send local identity and connection type.
	if _, err := fmt.Fprintf(conn, "%s|%s\n", localID, connType); err != nil {
		return nil, "", err
	}
	// Read remote identity.
	remoteIDLine, err := reader.ReadString('\n')
	if err != nil {
		return nil, "", err
	}
	remoteID := strings.TrimSpace(remoteIDLine)

	// Exchange RSA onion keys.
	if err := exchangeOnionKeys(reader, conn, remoteID); err != nil {
		return nil, "", err
	}

	return sessionKey, remoteID, nil
}

// HandshakeResponder responds to an incoming handshake request.
// It performs the following steps:
//  1. Reads the remote peer's ephemeral public key.
//  2. Generates its own ephemeral Curve25519 key pair and sends the public key.
//  3. Computes the shared session key.
//  4. Reads the remote peer's identity and connection type.
//  5. Sends its local identity.
//  6. Exchanges RSA onion public keys.
func HandshakeResponder(conn net.Conn, localID string) ([]byte, string, string, error) {
	reader := bufio.NewReader(conn)
	// Read remote ephemeral public key.
	remotePubStr, err := reader.ReadString('\n')
	if err != nil {
		return nil, "", "", err
	}
	remotePubStr = strings.TrimSpace(remotePubStr)
	remotePub, err := base64.StdEncoding.DecodeString(remotePubStr)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to decode remote ephemeral key: %v", err)
	}

	// Generate and send ephemeral key pair.
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		return nil, "", "", err
	}
	pubStr := base64.StdEncoding.EncodeToString(pub)
	if _, err := fmt.Fprintf(conn, "%s\n", pubStr); err != nil {
		return nil, "", "", err
	}

	// Compute the shared session key.
	sessionKey, err := ComputeSharedSecret(priv, remotePub)
	if err != nil {
		return nil, "", "", err
	}

	// Read remote identity and connection type.
	remoteIDLine, err := reader.ReadString('\n')
	if err != nil {
		return nil, "", "", err
	}
	remoteIDLine = strings.TrimSpace(remoteIDLine)
	fields := strings.Split(remoteIDLine, "|")
	remoteID := fields[0]
	connType := "explicit"
	if len(fields) > 1 {
		connType = fields[1]
	}

	// Send local identity.
	if _, err := fmt.Fprintf(conn, "%s\n", localID); err != nil {
		return nil, "", "", err
	}

	// Exchange RSA onion keys.
	if err := exchangeOnionKeys(reader, conn, remoteID); err != nil {
		return nil, "", "", err
	}

	return sessionKey, remoteID, connType, nil
}
