package client

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pion/webrtc/v4"
	"github.com/vlah02/whisper/internal/crypto"
	"github.com/vlah02/whisper/internal/proto"
)

type ClientApp struct {
	Username string
	Identity *crypto.Identity
	ServerWS *websocket.Conn

	peersMu sync.RWMutex
	peers   map[string]*Peer

	pendingMu sync.Mutex
	pending   map[string]struct{}

	outMu    sync.Mutex
	outgoing map[string]struct{}

	routesMu sync.RWMutex
	routes   map[string]string
	routePaths map[string][]string
	knownMu  sync.RWMutex
	known    map[string]map[string]struct{}
	
	peerKeysMu sync.RWMutex
	peerKeys   map[string]ed25519.PublicKey
	sessionsMu sync.RWMutex
	sessions   map[string]*crypto.SessionKey
}

func NewClient(ctx context.Context, signalingURL, username string) (*ClientApp, error) {
	identity, err := crypto.NewIdentity(username)
	if err != nil {
		return nil, fmt.Errorf("failed to generate identity: %w", err)
	}
	
	log.Printf("Generated identity for %s", username)
	log.Printf("Public key fingerprint: %s", identity.GetFingerprint())

	u, err := url.Parse(signalingURL)
	if err != nil {
		return nil, err
	}
	c, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		return nil, err
	}
	
	app := &ClientApp{
		Username:   username,
		Identity:   identity,
		ServerWS:   c,
		peers:      make(map[string]*Peer),
		pending:    make(map[string]struct{}),
		outgoing:   make(map[string]struct{}),
		routes:     make(map[string]string),
		routePaths: make(map[string][]string),
		known:      make(map[string]map[string]struct{}),
		peerKeys:   make(map[string]ed25519.PublicKey),
		sessions:   make(map[string]*crypto.SessionKey),
	}
	
	reg := proto.Envelope{
		Type: proto.TypeRegister, 
		At:   time.Now(), 
		Payload: proto.RegisterPayload{
			Username:  username,
			PublicKey: identity.PublicKeyToString(),
		},
	}
	if err := c.WriteJSON(reg); err != nil {
		return nil, err
	}
	var env proto.Envelope
	if err := c.ReadJSON(&env); err != nil {
		return nil, err
	}
	if env.Type != proto.TypeRegisterAck {
		return nil, fmt.Errorf("unexpected register response: %s", env.Type)
	}
	b, _ := json.Marshal(env.Payload)
	var ack proto.RegisterAckPayload
	_ = json.Unmarshal(b, &ack)
	if !ack.OK {
		return nil, errors.New("username taken")
	}

	go app.readLoop()
	return app, nil
}

func (a *ClientApp) readLoop() {
	for {
		var env proto.Envelope
		if err := a.ServerWS.ReadJSON(&env); err != nil {
			log.Printf("ws read: %v", err)
			return
		}
		switch env.Type {
		case proto.TypeIncoming:
			var p proto.IncomingPayload
			b, _ := json.Marshal(env.Payload)
			_ = json.Unmarshal(b, &p)
			remote := p.From

			if p.PublicKey != "" {
				pubKey, err := a.Identity.ParsePublicKeyFromString(p.PublicKey)
				if err != nil {
					log.Printf("Invalid public key from %s: %v", remote, err)
					break
				}
				a.peerKeysMu.Lock()
				a.peerKeys[remote] = pubKey
				a.peerKeysMu.Unlock()
				log.Printf("Stored public key for %s", remote)
			}

			if a.getPeer(remote) != nil {
				break
			}

			a.outMu.Lock()
			_, weRequested := a.outgoing[remote]
			if weRequested {
				delete(a.outgoing, remote)
			}
			a.outMu.Unlock()

			if weRequested {
				go a.Accept(remote)
				break
			}

			a.pendingMu.Lock()
			if _, exists := a.pending[remote]; !exists {
				a.pending[remote] = struct{}{}
				log.Printf("Incoming request from %s (use /accept %s or /decline %s)", remote, remote, remote)
			}
			a.pendingMu.Unlock()

		case proto.TypeAccept:
			var p proto.AcceptPayload
			b, _ := json.Marshal(env.Payload)
			_ = json.Unmarshal(b, &p)
			remote := env.From
			
			if p.PublicKey != "" {
				pubKey, err := a.Identity.ParsePublicKeyFromString(p.PublicKey)
				if err != nil {
					log.Printf("Invalid public key from %s in accept: %v", remote, err)
				} else {
					a.peerKeysMu.Lock()
					a.peerKeys[remote] = pubKey
					a.peerKeysMu.Unlock()
					log.Printf("Stored public key for %s from accept", remote)
				}
			}
			
		case proto.TypeOffer:
			remote := env.From
			peer, _ := a.ensurePeer(remote)
			var p proto.SDPPayload
			b, _ := json.Marshal(env.Payload)
			_ = json.Unmarshal(b, &p)
			answer, err := peer.ApplyRemoteOfferAndCreateAnswer(context.Background(), p.SDP)
			if err != nil {
				log.Printf("offer err: %v", err)
				continue
			}
			a.send(proto.Envelope{Type: proto.TypeAnswer, To: remote, At: time.Now(), Payload: proto.SDPPayload{SDP: answer}})

		case proto.TypeAnswer:
			remote := env.From
			peer := a.getPeer(remote)
			if peer == nil {
				log.Printf("got answer for unknown peer %s", remote)
				continue
			}
			var p proto.SDPPayload
			b, _ := json.Marshal(env.Payload)
			_ = json.Unmarshal(b, &p)
			if err := peer.ApplyAnswer(p.SDP); err != nil {
				log.Printf("apply answer: %v", err)
			}

		case proto.TypeICE:
			remote := env.From
			peer := a.getPeer(remote)
			if peer == nil {
				var created bool
				peer, created = a.ensurePeer(remote)
				if peer == nil {
					log.Printf("cannot create peer for %s", remote)
					continue
				}
				_ = created
			}
			var ip proto.ICEPayload
			b, _ := json.Marshal(env.Payload)
			_ = json.Unmarshal(b, &ip)
			_ = peer.AddICECandidate(ip.Candidate)

		case proto.TypeError:
			b, _ := json.Marshal(env.Payload)
			log.Printf("server error: %s", string(b))
		case proto.TypeWhoResult:
		}
	}
}

func (a *ClientApp) send(env proto.Envelope) {
	_ = a.ServerWS.WriteJSON(env)
}

func (a *ClientApp) ensurePeer(remote string) (*Peer, bool) {
	a.peersMu.Lock()
	defer a.peersMu.Unlock()
	if p, ok := a.peers[remote]; ok {
		return p, false
	}
	p, err := NewPeer(context.Background(), remote)
	if err != nil {
		log.Printf("peer create: %v", err)
		return nil, false
	}
	p.pc.OnICECandidate(func(c *webrtc.ICECandidate) {
		if c != nil {
			a.send(proto.Envelope{Type: proto.TypeICE, To: remote, At: time.Now(), Payload: proto.ICEPayload{Candidate: c.ToJSON().Candidate}})
		}
	})
	p.pc.OnDataChannel(func(dc *webrtc.DataChannel) {
		p.SetDataChannel(dc)
		dc.OnOpen(func() { 
			log.Printf("[%s] datachannel open", remote)
			go func() {
				time.Sleep(1 * time.Second)
				a.initiateKeyExchange(remote)
				a.exchangePeerLists(remote)
				a.notifyPeersAboutNewConnection(remote)
			}()
		})
		dc.OnMessage(func(msg webrtc.DataChannelMessage) { 
			a.handlePeerMessage(remote, string(msg.Data))
		})
	})

	a.peers[remote] = p
	return p, true
}

func (a *ClientApp) getPeer(remote string) *Peer {
	a.peersMu.RLock()
	defer a.peersMu.RUnlock()
	return a.peers[remote]
}

func (a *ClientApp) Connect(remote string) {
	if remote == a.Username {
		log.Printf("cannot connect to yourself")
		return
	}
	if a.getPeer(remote) != nil {
		log.Printf("already connected to %s", remote)
		return
	}
	a.pendingMu.Lock()
	_, hasIncoming := a.pending[remote]
	a.pendingMu.Unlock()
	if hasIncoming {
		log.Printf("%s already requested you; use /accept %s", remote, remote)
		return
	}
	a.outMu.Lock()
	if _, exists := a.outgoing[remote]; exists {
		a.outMu.Unlock()
		log.Printf("already requesting %s", remote)
		return
	}
	a.outgoing[remote] = struct{}{}
	a.outMu.Unlock()

	a.send(proto.Envelope{Type: proto.TypeConnect, At: time.Now(), Payload: proto.ConnectPayload{To: remote}})
}

func (a *ClientApp) Accept(remote string) {
	if a.getPeer(remote) != nil {
		log.Printf("already connected to %s", remote)
		return
	}

	a.pendingMu.Lock()
	_, hasPendingRequest := a.pending[remote]
	if !hasPendingRequest {
		a.pendingMu.Unlock()
		log.Printf("no pending connection request from %s", remote)
		return
	}
	delete(a.pending, remote)
	a.pendingMu.Unlock()

	peer, _ := a.ensurePeer(remote)

	if dc, err := peer.CreateDataChannel("chat"); err != nil {
		log.Printf("create dc: %v", err)
	} else {
		peer.SetDataChannel(dc)
		dc.OnOpen(func() { 
			log.Printf("[%s] datachannel open", remote)
			go func() {
				time.Sleep(1 * time.Second)
				a.exchangePeerLists(remote)
				a.notifyPeersAboutNewConnection(remote)
			}()
		})
		dc.OnMessage(func(msg webrtc.DataChannelMessage) {
			a.handlePeerMessage(remote, string(msg.Data))
		})
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	sdp, err := peer.CreateOffer(ctx)
	if err != nil {
		log.Printf("create offer: %v", err)
		return
	}
	a.send(proto.Envelope{Type: proto.TypeAccept, To: remote, At: time.Now(), Payload: proto.AcceptPayload{PublicKey: a.Identity.PublicKeyToString()}})
	a.send(proto.Envelope{Type: proto.TypeOffer, To: remote, At: time.Now(), Payload: proto.SDPPayload{SDP: sdp}})
}

func (a *ClientApp) Decline(remote string) {
	a.pendingMu.Lock()
	delete(a.pending, remote)
	a.pendingMu.Unlock()
	a.send(proto.Envelope{Type: proto.TypeDecline, To: remote, At: time.Now(), Payload: proto.AcceptDeclinePayload{To: remote}})
}

func (a *ClientApp) Drop(remote string) {
	if p := a.getPeer(remote); p != nil {
		_ = p.Close()
	}
	a.peersMu.Lock()
	delete(a.peers, remote)
	a.peersMu.Unlock()
	
	a.knownMu.Lock()
	delete(a.known, remote)
	a.knownMu.Unlock()
	
	a.routesMu.Lock()
	for user, via := range a.routes {
		if via == remote {
			delete(a.routes, user)
			delete(a.routePaths, user)
		}
	}
	a.routesMu.Unlock()
	
	a.send(proto.Envelope{Type: proto.TypeDrop, To: remote, At: time.Now(), Payload: proto.AcceptDeclinePayload{To: remote}})
	log.Printf("dropped %s", remote)
}

func (a *ClientApp) Who() {
	a.peersMu.RLock()
	var directList []string
	for k := range a.peers {
		directList = append(directList, k)
	}
	a.peersMu.RUnlock()
	
	if len(directList) > 0 {
		log.Printf("directly connected: %v", directList)
	} else {
		log.Printf("directly connected: none")
	}
	
	a.routesMu.RLock()
	var routedPaths []string
	for user, via := range a.routes {
		if a.getPeer(user) == nil {
			path := a.buildRoutePath(user, via)
			routedPaths = append(routedPaths, path)
		}
	}
	a.routesMu.RUnlock()
	
	if len(routedPaths) > 0 {
		log.Printf("reachable via routing:")
		for _, path := range routedPaths {
			log.Printf("  %s", path)
		}
	} else {
		log.Printf("reachable via routing: none")
	}
	
	a.pendingMu.Lock()
	var pend []string
	for k := range a.pending {
		pend = append(pend, k)
	}
	a.pendingMu.Unlock()
	
	if len(pend) > 0 {
		log.Printf("pending connections: %v", pend)
	} else {
		log.Printf("pending connections: none")
	}
}

func (a *ClientApp) buildRoutePath(targetUser, nextHop string) string {
	path := []string{a.Username}
	
	a.routesMu.RLock()
	storedPath, exists := a.routePaths[targetUser]
	a.routesMu.RUnlock()
	
	if exists && len(storedPath) > 0 {
		path = append(path, storedPath...)
	} else {
		path = append(path, nextHop, targetUser)
	}
	
	return strings.Join(path, " -> ")
}

func (a *ClientApp) SendTo(user, msg string) error {
	p := a.getPeer(user)
	if p != nil {
		a.sessionsMu.RLock()
		_, hasSession := a.sessions[user]
		a.sessionsMu.RUnlock()
		
		if hasSession {
			return a.SendSecureMessage(user, msg)
		} else {
			log.Printf("Warning: sending unencrypted message to %s (no secure session)", user)
			return p.Send(msg)
		}
	}
	
	if a.SendToViaRoute(user, msg) {
		return nil
	}
	
	return fmt.Errorf("no connection to %s (neither direct nor routed)", user)
}

func (a *ClientApp) SendLocalcast(msg string) {
	now := time.Now().Format("15:04:05")
	
	a.peersMu.RLock()
	defer a.peersMu.RUnlock()
	for name, p := range a.peers {
		if p == nil {
			continue
		}
		
		a.sessionsMu.RLock()
		_, hasSession := a.sessions[name]
		a.sessionsMu.RUnlock()
		
		if hasSession {
			encryptedMsg, err := a.encryptMessage(name, msg)
			if err == nil {
				signature, sigErr := a.Identity.SignMessage([]byte(encryptedMsg))
				if sigErr == nil {
					securePayload := proto.SecureMessagePayload{
						EncryptedContent: []byte(encryptedMsg),
						Signature:        []byte(signature),
						MessageID:        fmt.Sprintf("localcast-%d", time.Now().UnixNano()),
					}
					
					data, _ := json.Marshal(securePayload)
					if err := p.Send("SECURE_LOCALCAST:" + string(data)); err != nil {
						log.Printf("secure localcast to %s: %v", name, err)
					}
					continue
				}
			}
			localcastMsg := fmt.Sprintf("%s [LOCALCAST] %s: %s", now, a.Username, msg)
			if err := p.Send(localcastMsg); err != nil {
				log.Printf("localcast to %s: %v", name, err)
			}
		} else {
			localcastMsg := fmt.Sprintf("%s [LOCALCAST] %s: %s", now, a.Username, msg)
			if err := p.Send(localcastMsg); err != nil {
				log.Printf("localcast to %s: %v", name, err)
			}
		}
	}
}

func (a *ClientApp) SendBroadcast(msg string) {
	now := time.Now().Format("15:04:05")
	
	a.peersMu.RLock()
	for name, p := range a.peers {
		if p == nil {
			continue
		}
		
		a.sessionsMu.RLock()
		_, hasSession := a.sessions[name]
		a.sessionsMu.RUnlock()
		
		var messageToSend string
		if hasSession {
			encryptedMsg, err := a.encryptMessage(name, msg)
			if err == nil {

				messageToSend = fmt.Sprintf("%s [SECURE-BROADCAST] %s: <encrypted>", now, a.Username)
				if err := p.Send(messageToSend + "|ENCRYPTED|" + encryptedMsg); err != nil {
					log.Printf("secure broadcast to %s: %v", name, err)
				}
				continue
			} else {
			}
		}
		
		messageToSend = fmt.Sprintf("%s [BROADCAST] %s: %s", now, a.Username, msg)
		if err := p.Send(messageToSend); err != nil {
			log.Printf("broadcast to %s: %v", name, err)
		}
	}
	a.peersMu.RUnlock()
	
	broadcastMsg := fmt.Sprintf("%s [BROADCAST] %s: %s", now, a.Username, msg)
	
	a.routesMu.RLock()
	for user, nextHop := range a.routes {
		if a.getPeer(user) != nil {
			continue
		}
		
		a.peerKeysMu.RLock()
		_, hasKey := a.peerKeys[user]
		a.peerKeysMu.RUnlock()
		
		var payload proto.RouteMessagePayload
		
		a.sessionsMu.RLock()
		_, hasSession := a.sessions[user]
		a.sessionsMu.RUnlock()
		
		
		if hasKey && hasSession {
			encryptedMsg, err := a.encryptMessage(user, msg)
			if err == nil {
				secureBroadcastMsg := fmt.Sprintf("%s [SECURE-BROADCAST] %s: <encrypted>", now, a.Username)
				payload = proto.RouteMessagePayload{
					OriginalSender: a.Username,
					TargetUser:     user,
					Message:        secureBroadcastMsg,
					EncryptedContent: encryptedMsg,
					IsEncrypted:    true,
				}
			} else {
				payload = proto.RouteMessagePayload{
					OriginalSender: a.Username,
					TargetUser:     user,
					Message:        broadcastMsg,
					IsEncrypted:    false,
				}
			}
		} else {
			if !hasKey {
				a.requestPublicKey(user)
			}
			payload = proto.RouteMessagePayload{
				OriginalSender: a.Username,
				TargetUser:     user,
				Message:        broadcastMsg,
				IsEncrypted:    false,
			}
		}
		
		data, _ := json.Marshal(payload)
		if peer := a.getPeer(nextHop); peer != nil {
			if err := peer.Send("ROUTE_MESSAGE:" + string(data)); err != nil {
				log.Printf("Failed to send broadcast route to %s via %s: %v", user, nextHop, err)
			}
		}
	}
	a.routesMu.RUnlock()
}

func (a *ClientApp) handleNewConnection(from string, payload proto.NewConnectionPayload) {
	newPeer := payload.NewPeer
	
	if newPeer != a.Username {
		a.routesMu.Lock()
		wasNew := false
		if _, exists := a.routes[newPeer]; !exists {
			a.routes[newPeer] = from
			
			if len(payload.Path) > 0 {
				a.routePaths[newPeer] = append([]string{from}, payload.Path...)
			} else {
				a.routePaths[newPeer] = []string{from, newPeer}
			}
			
			wasNew = true
		}
		a.routesMu.Unlock()
		
		if wasNew {
			go func() {
				time.Sleep(200 * time.Millisecond)
				a.propagateNewPeerToOthersWithPath(newPeer, from)
			}()
		}
	}
}

func (a *ClientApp) propagateNewPeerToOthersWithPath(newPeer string, excludePeer string) {
	
	a.peersMu.RLock()
	var peersToNotify []string
	for peerName := range a.peers {
		if peerName != excludePeer && peerName != newPeer {
			peersToNotify = append(peersToNotify, peerName)
		}
	}
	a.peersMu.RUnlock()

	a.routesMu.RLock()
	path, exists := a.routePaths[newPeer]
	a.routesMu.RUnlock()
	
	if !exists {
		return
	}

	payload := proto.NewConnectionPayload{
		NewPeer: newPeer,
		Path:    path,
	}
	
	b, _ := json.Marshal(payload)
	for _, peerName := range peersToNotify {
		if peer := a.getPeer(peerName); peer != nil {
			_ = peer.Send("NEW_CONNECTION:" + string(b))
		}
	}
}

func (a *ClientApp) handleRouteMessage(payload proto.RouteMessagePayload) {	
	if payload.TargetUser == a.Username {		
		if payload.Message == "[PUBLIC_KEY_REQUEST]" {
			a.handlePublicKeyRequest(payload)
			return
		}
		if payload.Message == "[PUBLIC_KEY_RESPONSE]" {
			a.handlePublicKeyResponse(payload)
			return
		}
		
		if payload.IsEncrypted && payload.EncryptedContent != "" {
			decryptedMsg, err := a.decryptMessage(payload.OriginalSender, payload.EncryptedContent)
			if err != nil {
				log.Printf("Failed to decrypt routed message from %s: %v", payload.OriginalSender, err)
				now := time.Now().Format("15:04:05")
				if strings.Contains(payload.Message, "[SECURE-BROADCAST]") {
					fmt.Printf("%s [SECURE-BROADCAST] %s: <decryption failed>\n", now, payload.OriginalSender)
				} else {
					fmt.Printf("%s [SECURE-ROUTED] %s: <decryption failed>\n", now, payload.OriginalSender)
				}
			} else {
				now := time.Now().Format("15:04:05")
				if strings.Contains(payload.Message, "[SECURE-BROADCAST]") {
					fmt.Printf("%s [SECURE-BROADCAST] %s: %s\n", now, payload.OriginalSender, decryptedMsg)
				} else {
					fmt.Printf("%s [SECURE-ROUTED] %s: %s\n", now, payload.OriginalSender, decryptedMsg)
				}
			}
		} else {
			fmt.Printf("%s\n", payload.Message)
		}
	} else {		
		if directPeer := a.getPeer(payload.TargetUser); directPeer != nil {
			data, _ := json.Marshal(payload)
			if err := directPeer.Send("ROUTE_MESSAGE:" + string(data)); err != nil {
				log.Printf("Failed to forward route message directly: %v", err)
			} else {
			}
			return
		}
		
		a.routesMu.RLock()
		nextHop, exists := a.routes[payload.TargetUser]
		a.routesMu.RUnlock()
		
		if exists {
			if forwardPeer := a.getPeer(nextHop); forwardPeer != nil {
				data, _ := json.Marshal(payload)
				if err := forwardPeer.Send("ROUTE_MESSAGE:" + string(data)); err != nil {
					log.Printf("Failed to forward route message: %v", err)
				} else {
				}
			} else {
			}
		} else {
		}
	}
}

func (a *ClientApp) SendToViaRoute(user, msg string) bool {
	a.routesMu.RLock()
	nextHop, exists := a.routes[user]
	a.routesMu.RUnlock()
	
	if !exists {
		return false
	}
	
	peer := a.getPeer(nextHop)
	if peer == nil {
		return false
	}
	
	a.peerKeysMu.RLock()
	_, hasTargetKey := a.peerKeys[user]
	a.peerKeysMu.RUnlock()
	
	if !hasTargetKey {
		a.requestPublicKey(user)
		go func() {
			time.Sleep(2 * time.Second)
			a.SendToViaRoute(user, msg)
		}()
		return true
	}
	
	var routeMsg string
	now := time.Now().Format("15:04:05")
	
	a.sessionsMu.RLock()
	_, hasTargetSession := a.sessions[user]
	a.sessionsMu.RUnlock()
	
	if hasTargetSession {
		encryptedMsg, err := a.encryptMessage(user, msg)
		if err == nil {
			routeMsg = fmt.Sprintf("%s [SECURE-ROUTED] %s: <encrypted>", now, a.Username)
			payload := proto.RouteMessagePayload{
				OriginalSender: a.Username,
				TargetUser:     user,
				Message:        routeMsg,
				EncryptedContent: encryptedMsg,
				IsEncrypted:     true,
			}
			
			data, err := json.Marshal(payload)
			if err != nil {
				return false
			}
			
			return peer.Send("ROUTE_MESSAGE:"+string(data)) == nil
		}
	}
	
	routeMsg = fmt.Sprintf("%s [ROUTED] %s: %s", now, a.Username, msg)
	
	payload := proto.RouteMessagePayload{
		OriginalSender: a.Username,
		TargetUser:     user,
		Message:        routeMsg,
		IsEncrypted:    false,  
	}
	
	data, err := json.Marshal(payload)
	if err != nil {
		return false
	}
	
	return peer.Send("ROUTE_MESSAGE:"+string(data)) == nil
}

func (a *ClientApp) GetRoutedUsers() map[string]string {
	a.routesMu.RLock()
	defer a.routesMu.RUnlock()
	
	result := make(map[string]string)
	for user, nextHop := range a.routes {
		result[user] = nextHop
	}
	return result
}

func (a *ClientApp) handlePeerMessage(from string, message string) {
	if strings.HasPrefix(message, "KEY_EXCHANGE:") {
		data := strings.TrimPrefix(message, "KEY_EXCHANGE:")
		var payload proto.KeyExchangePayload
		if err := json.Unmarshal([]byte(data), &payload); err != nil {
			log.Printf("failed to parse key exchange: %v", err)
			return
		}
		a.handleKeyExchange(from, payload)
	} else if strings.HasPrefix(message, "SECURE_MESSAGE:") {
		data := strings.TrimPrefix(message, "SECURE_MESSAGE:")
		var payload proto.SecureMessagePayload
		if err := json.Unmarshal([]byte(data), &payload); err != nil {
			log.Printf("failed to parse secure message: %v", err)
			return
		}
		a.handleSecureMessage(from, payload)
	} else if strings.HasPrefix(message, "SECURE_LOCALCAST:") {
		data := strings.TrimPrefix(message, "SECURE_LOCALCAST:")
		var payload proto.SecureMessagePayload
		if err := json.Unmarshal([]byte(data), &payload); err != nil {
			log.Printf("failed to parse secure localcast: %v", err)
			return
		}
		a.handleSecureLocalcast(from, payload)
	} else if strings.HasPrefix(message, "NEW_CONNECTION:") {
		data := strings.TrimPrefix(message, "NEW_CONNECTION:")
		var payload proto.NewConnectionPayload
		if err := json.Unmarshal([]byte(data), &payload); err != nil {
			log.Printf("failed to parse new connection: %v", err)
			return
		}
		a.handleNewConnection(from, payload)
	} else if strings.HasPrefix(message, "PEER_LIST:") {
		data := strings.TrimPrefix(message, "PEER_LIST:")
		var payload proto.PeerListPayload
		if err := json.Unmarshal([]byte(data), &payload); err != nil {
			log.Printf("failed to parse peer list: %v", err)
			return
		}
		a.handlePeerList(from, payload)
	} else if strings.HasPrefix(message, "ROUTE_MESSAGE:") {
		data := strings.TrimPrefix(message, "ROUTE_MESSAGE:")
		var payload proto.RouteMessagePayload
		if err := json.Unmarshal([]byte(data), &payload); err != nil {
			log.Printf("failed to parse route message: %v", err)
			return
		}
		a.handleRouteMessage(payload)
	} else {
		if strings.Contains(message, "[SECURE-BROADCAST]") && strings.Contains(message, "<encrypted>") && strings.Contains(message, "|ENCRYPTED|") {
			parts := strings.SplitN(message, "|ENCRYPTED|", 2)
			if len(parts) == 2 {
				displayMessage := parts[0]
				encryptedContent := parts[1]
				
				decryptedMsg, err := a.decryptMessage(from, encryptedContent)
				if err == nil {
					decryptedDisplay := strings.Replace(displayMessage, "<encrypted>", decryptedMsg, 1)
					fmt.Printf("%s\n", decryptedDisplay)
				} else {
					fmt.Printf("%s\n", displayMessage)
				}
			} else {
				fmt.Printf("%s\n", message)
			}
		} else if strings.Contains(message, "[LOCALCAST]") || strings.Contains(message, "[BROADCAST]") {
			fmt.Printf("%s\n", message)
		} else {
			now := time.Now().Format("15:04:05")
			fmt.Printf("%s [DIRECT] %s: %s\n", now, from, message)
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (a *ClientApp) notifyPeersAboutNewConnection(newPeer string) {
	
	a.peersMu.RLock()
	var peersToNotify []string
	for peerName := range a.peers {
		if peerName != newPeer {
			peersToNotify = append(peersToNotify, peerName)
		}
	}
	a.peersMu.RUnlock()

	payload := proto.NewConnectionPayload{
		NewPeer: newPeer,
		Path:    []string{newPeer},
	}
	
	b, _ := json.Marshal(payload)
	for _, peerName := range peersToNotify {
		if peer := a.getPeer(peerName); peer != nil {
			_ = peer.Send("NEW_CONNECTION:" + string(b))
		}
	}
	
	go func() {
		time.Sleep(500 * time.Millisecond)
		a.shareReachableUsersViaNewPeer(newPeer)
	}()
}

func (a *ClientApp) shareReachableUsersViaNewPeer(newPeer string) {
	a.routesMu.RLock()
	var usersViaNewPeer []string
	for user, via := range a.routes {
		if via == newPeer {
			usersViaNewPeer = append(usersViaNewPeer, user)
		}
	}
	a.routesMu.RUnlock()
	
	if len(usersViaNewPeer) == 0 {
		return
	}
		
	a.peersMu.RLock()
	var peersToNotify []string
	for peerName := range a.peers {
		if peerName != newPeer {
			peersToNotify = append(peersToNotify, peerName)
		}
	}
	a.peersMu.RUnlock()

	a.routesMu.RLock()
	for _, user := range usersViaNewPeer {
		fullPath, exists := a.routePaths[user]
		if !exists {
			fullPath = []string{newPeer, user}
		}
		
		payload := proto.NewConnectionPayload{
			NewPeer: user,
			Path:    fullPath,
		}
		
		b, _ := json.Marshal(payload)
		for _, peerName := range peersToNotify {
			if peer := a.getPeer(peerName); peer != nil {
				_ = peer.Send("NEW_CONNECTION:" + string(b))
			}
		}
	}
	a.routesMu.RUnlock()
}

func (a *ClientApp) exchangePeerLists(peerName string) {
	a.peersMu.RLock()
	var allKnownPeers []string
	for user := range a.peers {
		if user != peerName {
			allKnownPeers = append(allKnownPeers, user)
		}
	}
	a.peersMu.RUnlock()
	
	a.routesMu.RLock()
	for user := range a.routes {
		if user != peerName {
			found := false
			for _, existing := range allKnownPeers {
				if existing == user {
					found = true
					break
				}
			}
			if !found {
				allKnownPeers = append(allKnownPeers, user)
			}
		}
	}
	a.routesMu.RUnlock()
	
	if len(allKnownPeers) > 0 {
		var peerInfos []proto.PeerInfo
		for _, peerName := range allKnownPeers {
			a.routesMu.RLock()
			if path, exists := a.routePaths[peerName]; exists {
				peerInfos = append(peerInfos, proto.PeerInfo{
					Name: peerName,
					Path: path,
				})
			} else {
				peerInfos = append(peerInfos, proto.PeerInfo{
					Name: peerName,
					Path: []string{peerName},
				})
			}
			a.routesMu.RUnlock()
		}
		
		payload := proto.PeerListPayload{
			Peers: peerInfos,
		}
		
		b, _ := json.Marshal(payload)
		if peer := a.getPeer(peerName); peer != nil {
			_ = peer.Send("PEER_LIST:" + string(b))
		}
	}
}

func (a *ClientApp) handlePeerList(from string, payload proto.PeerListPayload) {
	
	a.routesMu.Lock()
	newPeersAdded := []string{}
	for _, peerInfo := range payload.Peers {
		if peerInfo.Name != a.Username {
			if _, exists := a.routes[peerInfo.Name]; !exists {
				a.routes[peerInfo.Name] = from 
				a.routePaths[peerInfo.Name] = append([]string{from}, peerInfo.Path...)
				newPeersAdded = append(newPeersAdded, peerInfo.Name)
			}
		}
	}
	a.routesMu.Unlock()
	
	if len(newPeersAdded) > 0 {
		go func() {
			time.Sleep(200 * time.Millisecond)
			for _, newPeer := range newPeersAdded {
				a.propagateNewPeerToOthersWithPath(newPeer, from)
			}
		}()
	}
}

func (a *ClientApp) initiateKeyExchange(peerName string) {
	a.peerKeysMu.RLock()
	peerPublicKey, hasKey := a.peerKeys[peerName]
	a.peerKeysMu.RUnlock()
	
	if hasKey {
	}
	
	if !hasKey {
		log.Printf("No public key for %s, skipping key exchange", peerName)
		return
	}
	
	sessionKey, err := crypto.NewSessionKey([]byte(a.Identity.PrivateKey), []byte(peerPublicKey))
	if err != nil {
		log.Printf("Failed to create session key for %s: %v", peerName, err)
		return
	}
	
	a.sessionsMu.Lock()
	a.sessions[peerName] = sessionKey
	a.sessionsMu.Unlock()
	
	keyExchangePayload := proto.KeyExchangePayload{
		EphemeralPublicKey: a.Identity.PublicKeyToString(),
	}
	
	a.sendToPeer(peerName, proto.Envelope{
		Type:    proto.TypeKeyExchange,
		From:    a.Username,
		To:      peerName,
		At:      time.Now(),
		Payload: keyExchangePayload,
	})
	
	log.Printf("Initiated key exchange with %s", peerName)
}

func (a *ClientApp) handleKeyExchange(from string, payload proto.KeyExchangePayload) {
	peerPublicKey, err := a.Identity.ParsePublicKeyFromString(payload.EphemeralPublicKey)
	if err != nil {
		log.Printf("Invalid public key in key exchange from %s: %v", from, err)
		return
	}
	
	a.peerKeysMu.Lock()
	a.peerKeys[from] = peerPublicKey
	a.peerKeysMu.Unlock()
	
	sessionKey, err := crypto.NewSessionKey([]byte(a.Identity.PrivateKey), []byte(peerPublicKey))
	if err != nil {
		log.Printf("Failed to create session key from exchange with %s: %v", from, err)
		return
	}
	a.sessionsMu.Lock()
	a.sessions[from] = sessionKey
	a.sessionsMu.Unlock()
	
	log.Printf("Established secure session with %s", from)
}

func (a *ClientApp) encryptMessage(peerName string, message string) (string, error) {
	a.sessionsMu.RLock()
	sessionKey, exists := a.sessions[peerName]
	a.sessionsMu.RUnlock()
	
	if !exists {
		return "", fmt.Errorf("no session key for peer %s", peerName)
	}
	
	return sessionKey.Encrypt(message)
}

func (a *ClientApp) decryptMessage(peerName string, encryptedMessage string) (string, error) {
	a.sessionsMu.RLock()
	sessionKey, exists := a.sessions[peerName]
	a.sessionsMu.RUnlock()
	
	if !exists {
		return "", fmt.Errorf("no session key for peer %s", peerName)
	}
	
	return sessionKey.Decrypt(encryptedMessage)
}

func (a *ClientApp) handleSecureMessage(from string, payload proto.SecureMessagePayload) {
	decryptedMessage, err := a.decryptMessage(from, string(payload.EncryptedContent))
	if err != nil {
		log.Printf("Failed to decrypt message from %s: %v", from, err)
		return
	}
	
	if !a.Identity.VerifySignature(string(payload.Signature), payload.EncryptedContent, a.peerKeys[from]) {
		log.Printf("Invalid signature on message from %s", from)
		return
	}
	
	now := time.Now().Format("15:04:05")
	fmt.Printf("%s [SECURE-MESSAGE] %s: %s\n", now, from, decryptedMessage)
}

func (a *ClientApp) handleSecureLocalcast(from string, payload proto.SecureMessagePayload) {
	decryptedMessage, err := a.decryptMessage(from, string(payload.EncryptedContent))
	if err != nil {
		log.Printf("Failed to decrypt localcast from %s: %v", from, err)
		return
	}
	
	if !a.Identity.VerifySignature(string(payload.Signature), payload.EncryptedContent, a.peerKeys[from]) {
		log.Printf("Invalid signature on localcast from %s", from)
		return
	}
	
	now := time.Now().Format("15:04:05")
	fmt.Printf("%s [SECURE-LOCALCAST] %s: %s\n", now, from, decryptedMessage)
}

func (a *ClientApp) requestPublicKey(username string) {
	
	a.peerKeysMu.RLock()
	_, hasKey := a.peerKeys[username]
	a.peerKeysMu.RUnlock()
	
	if hasKey {
		return
	}
	
	request := proto.PublicKeyRequestPayload{
		RequestedUser: username,
		RequesterUser: a.Username,
	}
	
	payload := proto.RouteMessagePayload{
		OriginalSender: a.Username,
		TargetUser:     username,
		Message:        "[PUBLIC_KEY_REQUEST]",
		IsEncrypted:    false,
	}
	
	requestData, _ := json.Marshal(request)
	payload.EncryptedContent = string(requestData)
	
	a.routesMu.RLock()
	nextHop, exists := a.routes[username]
	a.routesMu.RUnlock()
	
	if exists {
		data, _ := json.Marshal(payload)
		if peer := a.getPeer(nextHop); peer != nil {
			_ = peer.Send("ROUTE_MESSAGE:" + string(data))
		}
	}
}

func (a *ClientApp) handlePublicKeyRequest(payload proto.RouteMessagePayload) {
	var request proto.PublicKeyRequestPayload
	if err := json.Unmarshal([]byte(payload.EncryptedContent), &request); err != nil {
		log.Printf("Failed to parse public key request: %v", err)
		return
	}
		response := proto.PublicKeyResponsePayload{
		User:      a.Username,
		PublicKey: a.Identity.PublicKeyToString(),
		Requester: request.RequesterUser,
	}
	
	responsePayload := proto.RouteMessagePayload{
		OriginalSender: a.Username,
		TargetUser:     request.RequesterUser,
		Message:        "[PUBLIC_KEY_RESPONSE]",
		IsEncrypted:    false,
	}
	
	responseData, _ := json.Marshal(response)
	responsePayload.EncryptedContent = string(responseData)
	
	a.routesMu.RLock()
	nextHop, exists := a.routes[request.RequesterUser]
	a.routesMu.RUnlock()
	
	if exists {
		data, _ := json.Marshal(responsePayload)
		if peer := a.getPeer(nextHop); peer != nil {
			_ = peer.Send("ROUTE_MESSAGE:" + string(data))
		}
	}
	
	a.requestPublicKey(request.RequesterUser)
}

func (a *ClientApp) handlePublicKeyResponse(payload proto.RouteMessagePayload) {
	var response proto.PublicKeyResponsePayload
	if err := json.Unmarshal([]byte(payload.EncryptedContent), &response); err != nil {
		log.Printf("Failed to parse public key response: %v", err)
		return
	}
	
	pubKey, err := a.Identity.ParsePublicKeyFromString(response.PublicKey)
	if err != nil {
		log.Printf("Invalid public key in response from %s: %v", response.User, err)
		return
	}
	
	a.peerKeysMu.Lock()
	a.peerKeys[response.User] = pubKey
	a.peerKeysMu.Unlock()
	
	sessionKey, err := crypto.NewSessionKey([]byte(a.Identity.PrivateKey), []byte(pubKey))
	if err != nil {
		log.Printf("Failed to create session key for %s: %v", response.User, err)
		return
	}
	
	a.sessionsMu.Lock()
	a.sessions[response.User] = sessionKey
	a.sessionsMu.Unlock()
	
	log.Printf("Established secure session with %s via public key exchange", response.User)
}

func (a *ClientApp) sendToPeer(peerName string, envelope proto.Envelope) error {
	peer := a.getPeer(peerName)
	if peer == nil {
		return fmt.Errorf("no connection to peer %s", peerName)
	}
	
	var message string
	switch envelope.Type {
	case proto.TypeKeyExchange:
		data, err := json.Marshal(envelope.Payload)
		if err != nil {
			return fmt.Errorf("failed to marshal key exchange: %w", err)
		}
		message = "KEY_EXCHANGE:" + string(data)
	case proto.TypeSecureMessage:
		data, err := json.Marshal(envelope.Payload)
		if err != nil {
			return fmt.Errorf("failed to marshal secure message: %w", err)
		}
		message = "SECURE_MESSAGE:" + string(data)
	default:
		return fmt.Errorf("unsupported message type for sendToPeer: %s", envelope.Type)
	}
	
	return peer.Send(message)
}

func (a *ClientApp) SendSecureMessage(peerName string, message string) error {
	a.sessionsMu.RLock()
	_, hasSession := a.sessions[peerName]
	a.sessionsMu.RUnlock()
	
	if !hasSession {
		return fmt.Errorf("no secure session with %s", peerName)
	}
	
	encryptedMessage, err := a.encryptMessage(peerName, message)
	if err != nil {
		return fmt.Errorf("failed to encrypt message: %w", err)
	}
	
	signature, err := a.Identity.SignMessage([]byte(encryptedMessage))
	if err != nil {
		return fmt.Errorf("failed to sign message: %w", err)
	}
	
	securePayload := proto.SecureMessagePayload{
		EncryptedContent: []byte(encryptedMessage),
		Signature:        []byte(signature),
		MessageID:        fmt.Sprintf("%d", time.Now().UnixNano()),
	}
	
	envelope := proto.Envelope{
		Type:    proto.TypeSecureMessage,
		From:    a.Username,
		To:      peerName,
		At:      time.Now(),
		Payload: securePayload,
	}
	
	return a.sendToPeer(peerName, envelope)
}

func (a *ClientApp) ShowSecurityStatus() {
	fmt.Printf("\n=== Security Status ===\n")
	fmt.Printf("Your identity: %s\n", a.Username)
	fmt.Printf("Your public key fingerprint: %s\n", a.Identity.GetFingerprint())
	
	fmt.Printf("\nPeer public keys:\n")
	a.peerKeysMu.RLock()
	if len(a.peerKeys) == 0 {
		fmt.Printf("  (none)\n")
	} else {
		for peerName, pubKey := range a.peerKeys {
			fingerprint := a.Identity.GetFingerprintFromPublicKey(pubKey)
			fmt.Printf("  %s: %s\n", peerName, fingerprint)
		}
	}
	a.peerKeysMu.RUnlock()
	
	fmt.Printf("\nSecure sessions:\n")
	a.sessionsMu.RLock()
	if len(a.sessions) == 0 {
		fmt.Printf("  (none)\n")
	} else {
		for peerName := range a.sessions {
			fmt.Printf("  %s: ✓ Active\n", peerName)
		}
	}
	a.sessionsMu.RUnlock()
	
	fmt.Printf("=======================\n\n")
}
