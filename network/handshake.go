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
)

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

func HandshakeInitiator(conn net.Conn) ([]byte, error) {
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	pubStr := base64.StdEncoding.EncodeToString(pub)
	if _, err := fmt.Fprintf(conn, "%s\n", pubStr); err != nil {
		return nil, err
	}
	reader := bufio.NewReader(conn)
	remotePubStr, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	remotePubStr = strings.TrimSpace(remotePubStr)
	remotePub, err := base64.StdEncoding.DecodeString(remotePubStr)
	if err != nil {
		return nil, err
	}
	return ComputeSharedSecret(priv, remotePub)
}

func HandshakeResponder(conn net.Conn) ([]byte, error) {
	reader := bufio.NewReader(conn)
	remotePubStr, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	remotePubStr = strings.TrimSpace(remotePubStr)
	remotePub, err := base64.StdEncoding.DecodeString(remotePubStr)
	if err != nil {
		return nil, err
	}
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	pubStr := base64.StdEncoding.EncodeToString(pub)
	if _, err := fmt.Fprintf(conn, "%s\n", pubStr); err != nil {
		return nil, err
	}
	return ComputeSharedSecret(priv, remotePub)
}
