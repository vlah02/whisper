package proto

import "time"

const (
	TypeRegister         = "register"
	TypeRegisterAck      = "register_ack"
	TypeConnect          = "connect"
	TypeIncoming         = "incoming"
	TypeAccept           = "accept"
	TypeDecline          = "decline"
	TypeOffer            = "offer"
	TypeAnswer           = "answer"
	TypeICE              = "ice"
	TypeDrop             = "drop"
	TypeWho              = "who"
	TypeWhoResult        = "who_result"
	TypeNewConnection    = "new_connection"
	TypePeerList         = "peer_list"
	TypeKeyExchange      = "key_exchange"
	TypeSecureMessage    = "secure_message"
	TypeRouteMessage     = "route_message"
	TypeError            = "error"
)

type Envelope struct {
	Type          string      `json:"type"`
	From          string      `json:"from,omitempty"`
	To            string      `json:"to,omitempty"`
	CorrelationID string      `json:"cid,omitempty"`
	Payload       interface{} `json:"payload,omitempty"`
	At            time.Time   `json:"at"`
}

type RegisterPayload struct {
	Username  string `json:"username"`
	PublicKey string `json:"publicKey"`
}

type RegisterAckPayload struct {
	OK     bool   `json:"ok"`
	Reason string `json:"reason,omitempty"`
}

type ConnectPayload struct {
	To string `json:"to"`
}

type AcceptPayload struct {
	PublicKey string `json:"public_key"`
}

type IncomingPayload struct {
	From      string `json:"from"`
	PublicKey string `json:"publicKey"`
}

type AcceptDeclinePayload struct {
	To string `json:"to"`
}

type SDPPayload struct {
	SDP string `json:"sdp"`
}

type ICEPayload struct {
	Candidate string `json:"candidate"`
}

type WhoResultPayload struct {
	Connections []string `json:"connections"`
	Pending     []string `json:"pending"`
}

type ErrorPayload struct {
	Reason string `json:"reason"`
}

type NewConnectionPayload struct {
	NewPeer string   `json:"newPeer"`
	Path    []string `json:"path,omitempty"`
}

type PeerListPayload struct {
	Peers []PeerInfo `json:"peers"`
}

type PeerInfo struct {
	Name string   `json:"name"`
	Path []string `json:"path"`
}

type RouteMessagePayload struct {
	OriginalSender   string `json:"originalSender"`
	TargetUser       string `json:"targetUser"`
	Message          string `json:"message"`
	EncryptedContent string `json:"encryptedContent,omitempty"`
	IsEncrypted      bool   `json:"isEncrypted"`
}

type KeyExchangePayload struct {
	EphemeralPublicKey string `json:"ephemeralPublicKey"`
}

type SecureMessagePayload struct {
	EncryptedContent []byte `json:"encryptedContent"`
	Signature        []byte `json:"signature"`
	MessageID        string `json:"messageId"`
}

type PublicKeyRequestPayload struct {
	RequestedUser string `json:"requestedUser"`
	RequesterUser string `json:"requesterUser"`
}

type PublicKeyResponsePayload struct {
	User      string `json:"user"`
	PublicKey string `json:"publicKey"`
	Requester string `json:"requester"`
}
