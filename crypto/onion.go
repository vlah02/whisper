package crypto

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"

	"whisper/crypto/encryption"
)

// OnionLayer represents a single encryption layer in an onion message.
// Each layer contains the address of the next hop and the encrypted payload.
type OnionLayer struct {
	NextHop string `json:"next_hop"` // The next node's identifier; empty if final destination.
	Payload string `json:"payload"`  // The encrypted message or next layer.
}

// GetOnionPublicKey returns the RSA public key for the given remoteID.
// It looks up the key from the global RemoteOnionPublicKeys map.
func GetOnionPublicKey(remoteID string) *rsa.PublicKey {
	if pub, ok := RemoteOnionPublicKeys[remoteID]; ok {
		return pub
	}
	return nil
}

// BuildOnionMessage wraps the final message in successive encryption layers according to the provided route.
// The route is a slice of peer IDs, and the final message is the innermost payload.
// It returns a string with a predefined "ONION:" prefix.
func BuildOnionMessage(route []string, finalMessage string) (string, error) {
	// Start with the final message as the innermost payload.
	payload := finalMessage

	// Process the route in reverse order, wrapping each layer.
	for i := len(route) - 1; i >= 0; i-- {
		// Determine the next hop. For the last node, nextHop remains empty.
		nextHop := ""
		if i < len(route)-1 {
			nextHop = route[i+1]
		}

		// Create the current onion layer.
		layer := OnionLayer{
			NextHop: nextHop,
			Payload: payload,
		}
		// Marshal the layer into JSON format.
		layerData, err := json.Marshal(layer)
		if err != nil {
			return "", err
		}

		// Retrieve the public key for the current hop.
		pubKey := GetOnionPublicKey(route[i])
		if pubKey == nil {
			return "", fmt.Errorf("public key for node %s not found", route[i])
		}

		// Use the hybrid encryption scheme to encrypt the JSON layer.
		var hybrid encryption.Hybrid
		encryptedLayer, err := hybrid.Encrypt(layerData, pubKey)
		if err != nil {
			return "", err
		}

		// Set the encrypted output as the payload for the next iteration.
		payload = encryptedLayer
	}
	// Prepend the payload with the "ONION:" prefix to indicate an onion message.
	return "ONION:" + payload, nil
}

// ProcessOnionMessage decrypts an onion-routed message and extracts the current layer's content.
// It expects a message with the "ONION:" prefix, decrypts the outermost layer, and returns:
//   - nextHop: the identifier for the next node in the route (if any),
//   - innerPayload: the decrypted payload to be processed or forwarded,
//   - isFinal: true if this is the final destination (no next hop),
//   - err: error if any decryption or unmarshalling error occurs.
func ProcessOnionMessage(encrypted string) (nextHop string, innerPayload string, isFinal bool, err error) {
	const prefix = "ONION:"
	// Check that the message has the proper prefix.
	if len(encrypted) < len(prefix) || encrypted[:len(prefix)] != prefix {
		err = errors.New("invalid onion message")
		return
	}
	// Remove the prefix to get the encrypted payload.
	encrypted = encrypted[len(prefix):]

	// Decrypt the outermost layer using the local private RSA key.
	var hybrid encryption.Hybrid
	decryptedData, err := hybrid.Decrypt(encrypted, LocalOnionPrivateKey)
	if err != nil {
		return
	}

	// Unmarshal the decrypted JSON data into an OnionLayer struct.
	var layer OnionLayer
	if err = json.Unmarshal(decryptedData, &layer); err != nil {
		return
	}

	// Determine if this is the final layer (i.e., no next hop).
	isFinal = layer.NextHop == ""
	nextHop = layer.NextHop
	innerPayload = layer.Payload
	return
}
