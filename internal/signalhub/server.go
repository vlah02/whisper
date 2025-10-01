package signalhub

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/vlah02/whisper/internal/proto"
)

type Client struct {
	Username string
	Conn     *websocket.Conn
	SendQ    chan proto.Envelope
}

type Hub struct {
	mu      sync.RWMutex
	clients map[string]*Client
	pending map[string]map[string]struct{}
}

func NewHub() *Hub {
	return &Hub{
		clients: make(map[string]*Client),
		pending: make(map[string]map[string]struct{}),
	}
}

var upgrader = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}

func (h *Hub) ServeWS(w http.ResponseWriter, r *http.Request) {
	c, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	client := &Client{Conn: c, SendQ: make(chan proto.Envelope, 32)}

	go func() {
		for msg := range client.SendQ {
			_ = c.SetWriteDeadline(time.Now().Add(30 * time.Second))
			if err := c.WriteJSON(msg); err != nil {
				log.Printf("write error: %v", err)
				return
			}
		}
	}()

	for {
		var env proto.Envelope
		if err := c.ReadJSON(&env); err != nil {
			log.Printf("read error: %v", err)
			if client.Username != "" {
				h.logout(client.Username)
			}
			return
		}
		env.At = time.Now()
		switch env.Type {
		case proto.TypeRegister:
			var p proto.RegisterPayload
			decode(env.Payload, &p)
			if p.Username == "" {
				client.SendQ <- errEnv("username required")
				continue
			}
			if !h.login(p.Username, client) {
				client.SendQ <- proto.Envelope{Type: proto.TypeRegisterAck, At: time.Now(), Payload: proto.RegisterAckPayload{OK: false, Reason: "username taken"}}
				continue
			}
			client.Username = p.Username
			client.SendQ <- proto.Envelope{Type: proto.TypeRegisterAck, At: time.Now(), Payload: proto.RegisterAckPayload{OK: true}}

		case proto.TypeConnect:
			var p proto.ConnectPayload
			decode(env.Payload, &p)
			if p.To == "" || client.Username == "" {
				continue
			}
			if p.To == client.Username {
				client.SendQ <- errEnv("cannot connect to yourself")
				continue
			}
			h.enqueueIncoming(p.To, client.Username)
			h.sendTo(p.To, proto.Envelope{
				Type:    proto.TypeIncoming,
				From:    client.Username,
				At:      time.Now(),
				Payload: proto.IncomingPayload{From: client.Username},
			})

		case proto.TypeAccept, proto.TypeDecline, proto.TypeOffer, proto.TypeAnswer, proto.TypeICE, proto.TypeDrop:
			if client.Username == "" {
				continue
			}
			to := env.To
			if to == "" {
				if cp, ok := env.Payload.(map[string]any); ok {
					if v, ok := cp["to"].(string); ok {
						to = v
					}
				}
			}
			if to == "" {
				continue
			}
			if env.Type == proto.TypeAccept || env.Type == proto.TypeDecline {
				h.clearPending(client.Username, to)
			}
			h.sendTo(to, proto.Envelope{Type: env.Type, From: client.Username, To: to, At: time.Now(), Payload: env.Payload})

		case proto.TypeWho:
			who := h.snapshot(client.Username)
			client.SendQ <- proto.Envelope{Type: proto.TypeWhoResult, At: time.Now(), Payload: who}

		default:
			client.SendQ <- errEnv("unknown type")
		}
	}
}

func (h *Hub) login(username string, c *Client) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, exists := h.clients[username]; exists {
		return false
	}
	h.clients[username] = c
	return true
}

func (h *Hub) logout(username string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.clients, username)
	delete(h.pending, username)
	for _, set := range h.pending {
		delete(set, username)
	}
}

func (h *Hub) sendTo(username string, env proto.Envelope) {
	h.mu.RLock()
	c := h.clients[username]
	h.mu.RUnlock()
	if c != nil {
		select {
		case c.SendQ <- env:
		default:
			log.Printf("sendQ full for %s", username)
		}
	}
}

func (h *Hub) enqueueIncoming(target, from string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	set := h.pending[target]
	if set == nil {
		set = make(map[string]struct{})
		h.pending[target] = set
	}
	set[from] = struct{}{}
}

func (h *Hub) clearPending(user, requester string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if set := h.pending[user]; set != nil {
		delete(set, requester)
	}
}

func (h *Hub) snapshot(user string) proto.WhoResultPayload {
	h.mu.RLock()
	defer h.mu.RUnlock()
	pend := make([]string, 0)
	if set, ok := h.pending[user]; ok {
		for u := range set {
			pend = append(pend, u)
		}
	}
	return proto.WhoResultPayload{
		Connections: make([]string, 0),
		Pending:     pend,
	}
}

func errEnv(reason string) proto.Envelope {
	return proto.Envelope{Type: proto.TypeError, At: time.Now(), Payload: proto.ErrorPayload{Reason: reason}}
}

func decode(src any, dst any) {
	b, _ := json.Marshal(src)
	_ = json.Unmarshal(b, dst)
}
