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
	Username string `json:"username"`
}

type RegisterAckPayload struct {
	OK     bool   `json:"ok"`
	Reason string `json:"reason,omitempty"`
}

type ConnectPayload struct {
	To string `json:"to"`
}

type IncomingPayload struct {
	From string `json:"from"`
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
	From     string `json:"from"`
	To       string `json:"to"`
	Content  string `json:"content"`
	HopCount int    `json:"hopCount"`
}
