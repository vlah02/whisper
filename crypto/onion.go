package crypto

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"

	"whisper/crypto/encryption"
)

type OnionLayer struct {
	NextHop string `json:"next_hop"`
	Payload string `json:"payload"`
}

func GetOnionPublicKey(remoteID string) *rsa.PublicKey {
	if pub, ok := RemoteOnionPublicKeys[remoteID]; ok {
		return pub
	}
	return nil
}

func BuildOnionMessage(route []string, finalMessage string) (string, error) {
	payload := finalMessage

	for i := len(route) - 1; i >= 0; i-- {
		nextHop := ""
		if i < len(route)-1 {
			nextHop = route[i+1]
		}
		layer := OnionLayer{
			NextHop: nextHop,
			Payload: payload,
		}
		layerData, err := json.Marshal(layer)
		if err != nil {
			return "", err
		}
		pubKey := GetOnionPublicKey(route[i])
		if pubKey == nil {
			return "", fmt.Errorf("public key for node %s not found", route[i])
		}
		var hybrid encryption.Hybrid
		encryptedLayer, err := hybrid.Encrypt(layerData, pubKey)
		if err != nil {
			return "", err
		}
		payload = encryptedLayer
	}
	return "ONION:" + payload, nil
}

func ProcessOnionMessage(encrypted string) (nextHop string, innerPayload string, isFinal bool, err error) {
	const prefix = "ONION:"
	if len(encrypted) < len(prefix) || encrypted[:len(prefix)] != prefix {
		err = errors.New("invalid onion message")
		return
	}
	encrypted = encrypted[len(prefix):]

	var hybrid encryption.Hybrid
	decryptedData, err := hybrid.Decrypt(encrypted, LocalOnionPrivateKey)
	if err != nil {
		return
	}
	var layer OnionLayer
	err = json.Unmarshal(decryptedData, &layer)
	if err != nil {
		return
	}
	isFinal = layer.NextHop == ""
	nextHop = layer.NextHop
	innerPayload = layer.Payload
	return
}
