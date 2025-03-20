package message

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// Message represents a chat message exchanged between peers.
// It includes a unique ID, the sender's identifier, a timestamp,
// and the actual text content.
type Message struct {
	ID        string    `json:"id"`        // Unique message identifier.
	Sender    string    `json:"sender"`    // Identifier of the sender.
	Timestamp time.Time `json:"timestamp"` // Time when the message was created.
	Content   string    `json:"content"`   // The message content.
}

// NewMessage creates a new Message with a unique ID and current timestamp.
// The sender and content are provided as arguments.
//
// Example:
//
//	msg := NewMessage("peer1", "Hello, world!")
func NewMessage(sender, content string) Message {
	return Message{
		ID:        uuid.New().String(),
		Sender:    sender,
		Timestamp: time.Now(),
		Content:   content,
	}
}

// Serialize converts the Message into its JSON-encoded byte representation.
// It returns the JSON byte slice or an error if serialization fails.
func (m Message) Serialize() ([]byte, error) {
	return json.Marshal(m)
}

// DeserializeMessage converts a JSON-encoded byte slice into a Message object.
// It returns the deserialized Message or an error if the input is not valid JSON.
func DeserializeMessage(data []byte) (Message, error) {
	var m Message
	err := json.Unmarshal(data, &m)
	return m, err
}
