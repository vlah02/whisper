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

func GenerateKeyPair() (privateKey, publicKey []byte, err error) {
	privateKey = make([]byte, 32)
	if _, err = io.ReadFull(rand.Reader, privateKey); err != nil {
		return nil, nil, err
	}
	privateKey[0] &= 248
	privateKey[31] &= 127
	privateKey[31] |= 64

	publicKey, err = curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, publicKey, nil
}

func ComputeSharedSecret(privateKey, remotePublicKey []byte) ([]byte, error) {
	sharedSecret, err := curve25519.X25519(privateKey, remotePublicKey)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(sharedSecret)
	return hash[:], nil
}

func HandshakeInitiator(conn net.Conn, localID, connType string) ([]byte, string, error) {
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		return nil, "", err
	}
	pubStr := base64.StdEncoding.EncodeToString(pub)
	if _, err := fmt.Fprintf(conn, "%s\n", pubStr); err != nil {
		return nil, "", err
	}
	reader := bufio.NewReader(conn)

	remotePubStr, err := reader.ReadString('\n')
	if err != nil {
		return nil, "", err
	}
	remotePubStr = strings.TrimSpace(remotePubStr)
	remotePub, err := base64.StdEncoding.DecodeString(remotePubStr)
	if err != nil {
		return nil, "", fmt.Errorf("failed to decode remote ephemeral key: %v", err)
	}
	sessionKey, err := ComputeSharedSecret(priv, remotePub)
	if err != nil {
		return nil, "", err
	}

	if _, err := fmt.Fprintf(conn, "%s|%s\n", localID, connType); err != nil {
		return nil, "", err
	}
	remoteIDLine, err := reader.ReadString('\n')
	if err != nil {
		return nil, "", err
	}
	remoteID := strings.TrimSpace(remoteIDLine)

	localOnionPubPEM, err := crypto.EncodeRSAPublicKey(crypto.LocalOnionPublicKey)
	if err != nil {
		return nil, "", err
	}
	if _, err := fmt.Fprintf(conn, "%s\n", localOnionPubPEM); err != nil {
		return nil, "", err
	}
	remoteOnionPubPEM, err := ReadPEM(reader)
	if err != nil {
		return nil, "", err
	}
	fmt.Printf("DEBUG: Received remote onion PEM: %q\n", remoteOnionPubPEM)
	if remoteOnionPubPEM == "" {
		return nil, "", fmt.Errorf("received empty onion public key")
	}
	if !strings.HasPrefix(remoteOnionPubPEM, "-----BEGIN PUBLIC KEY-----") {
		return nil, "", fmt.Errorf("unexpected onion public key format: %s", remoteOnionPubPEM)
	}
	remoteOnionPub, err := crypto.ParseRSAPublicKey(remoteOnionPubPEM)
	if err != nil {
		return nil, "", fmt.Errorf("failed to parse remote onion public key: %v", err)
	}
	crypto.RemoteOnionPublicKeys[remoteID] = remoteOnionPub

	return sessionKey, remoteID, nil
}

func HandshakeResponder(conn net.Conn, localID string) ([]byte, string, string, error) {
	reader := bufio.NewReader(conn)
	remotePubStr, err := reader.ReadString('\n')
	if err != nil {
		return nil, "", "", err
	}
	remotePubStr = strings.TrimSpace(remotePubStr)
	remotePub, err := base64.StdEncoding.DecodeString(remotePubStr)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to decode remote ephemeral key: %v", err)
	}
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		return nil, "", "", err
	}
	pubStr := base64.StdEncoding.EncodeToString(pub)
	if _, err := fmt.Fprintf(conn, "%s\n", pubStr); err != nil {
		return nil, "", "", err
	}
	sessionKey, err := ComputeSharedSecret(priv, remotePub)
	if err != nil {
		return nil, "", "", err
	}
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
	if _, err := fmt.Fprintf(conn, "%s\n", localID); err != nil {
		return nil, "", "", err
	}

	localOnionPubPEM, err := crypto.EncodeRSAPublicKey(crypto.LocalOnionPublicKey)
	if err != nil {
		return nil, "", "", err
	}
	if _, err := fmt.Fprintf(conn, "%s\n", localOnionPubPEM); err != nil {
		return nil, "", "", err
	}
	remoteOnionPubPEM, err := ReadPEM(reader)
	if err != nil {
		return nil, "", "", err
	}
	fmt.Printf("DEBUG: Received remote onion PEM: %q\n", remoteOnionPubPEM)
	if remoteOnionPubPEM == "" {
		return nil, "", "", fmt.Errorf("received empty onion public key")
	}
	if !strings.HasPrefix(remoteOnionPubPEM, "-----BEGIN PUBLIC KEY-----") {
		return nil, "", "", fmt.Errorf("unexpected onion public key format: %s", remoteOnionPubPEM)
	}
	remoteOnionPub, err := crypto.ParseRSAPublicKey(remoteOnionPubPEM)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to parse remote onion public key: %v", err)
	}
	crypto.RemoteOnionPublicKeys[remoteID] = remoteOnionPub

	return sessionKey, remoteID, connType, nil
}
