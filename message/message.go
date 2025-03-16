package message

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

type Message struct {
	ID        string    `json:"id"`
	Sender    string    `json:"sender"`
	Timestamp time.Time `json:"timestamp"`
	Content   string    `json:"content"`
}

func NewMessage(sender, content string) Message {
	return Message{
		ID:        uuid.New().String(),
		Sender:    sender,
		Timestamp: time.Now(),
		Content:   content,
	}
}

func (m Message) Serialize() ([]byte, error) {
	return json.Marshal(m)
}

func DeserializeMessage(data []byte) (Message, error) {
	var m Message
	err := json.Unmarshal(data, &m)
	return m, err
}
