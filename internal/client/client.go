package client

import (
	"context"
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
	"github.com/vlah02/whisper/internal/proto"
)

type ClientApp struct {
	Username string
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
}

func NewClient(ctx context.Context, signalingURL, username string) (*ClientApp, error) {
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
		ServerWS:   c,
		peers:      make(map[string]*Peer),
		pending:    make(map[string]struct{}),
		outgoing:   make(map[string]struct{}),
		routes:     make(map[string]string),
		routePaths: make(map[string][]string),
		known:      make(map[string]map[string]struct{}),
	}
	reg := proto.Envelope{Type: proto.TypeRegister, At: time.Now(), Payload: proto.RegisterPayload{Username: username}}
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
	a.send(proto.Envelope{Type: proto.TypeAccept, To: remote, At: time.Now(), Payload: proto.AcceptDeclinePayload{To: remote}})
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
		return p.Send(msg)
	}
	
	if a.SendToViaRoute(user, msg) {
		return nil
	}
	
	return fmt.Errorf("no connection to %s (neither direct nor routed)", user)
}

func (a *ClientApp) SendLocalcast(msg string) {
	now := time.Now().Format("15:04:05")
	localcastMsg := fmt.Sprintf("%s [LOCALCAST] %s: %s", now, a.Username, msg)
	
	a.peersMu.RLock()
	defer a.peersMu.RUnlock()
	for name, p := range a.peers {
		if p == nil {
			continue
		}
		if err := p.Send(localcastMsg); err != nil {
			log.Printf("localcast to %s: %v", name, err)
		}
	}
}

func (a *ClientApp) SendBroadcast(msg string) {
	now := time.Now().Format("15:04:05")
	
	broadcastMsg := fmt.Sprintf("%s [BROADCAST] %s: %s", now, a.Username, msg)
	a.peersMu.RLock()
	for name, p := range a.peers {
		if p == nil {
			continue
		}
		if err := p.Send(broadcastMsg); err != nil {
			log.Printf("broadcast to %s: %v", name, err)
		}
	}
	a.peersMu.RUnlock()
	
	a.routesMu.RLock()
	for user, nextHop := range a.routes {
		if a.getPeer(user) == nil {
			payload := proto.RouteMessagePayload{
				From:     a.Username,
				To:       user,
				Content:  fmt.Sprintf("[BROADCAST] %s", msg),
				HopCount: 0,
			}
			
			b, _ := json.Marshal(payload)
			if peer := a.getPeer(nextHop); peer != nil {
				_ = peer.Send("ROUTE_MESSAGE:" + string(b))
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
	if payload.To == a.Username {
		now := time.Now().Format("15:04:05")
		
		if strings.HasPrefix(payload.Content, "[BROADCAST]") {
			content := strings.TrimPrefix(payload.Content, "[BROADCAST] ")
			fmt.Printf("%s [BROADCAST] %s: %s\n", now, payload.From, content)
		} else {
			fmt.Printf("%s [ROUTED] %s: %s\n", now, payload.From, payload.Content)
		}
		return
	}

	if payload.HopCount >= 5 {
		log.Printf("dropping message: hop count exceeded")
		return
	}

	if directPeer := a.getPeer(payload.To); directPeer != nil {
		routedMsg := proto.RouteMessagePayload{
			From:     payload.From,
			To:       payload.To,
			Content:  payload.Content,
			HopCount: payload.HopCount,
		}
		b, _ := json.Marshal(routedMsg)
		_ = directPeer.Send("ROUTE_MESSAGE:" + string(b))
		return
	}

	a.routesMu.RLock()
	nextHop, exists := a.routes[payload.To]
	a.routesMu.RUnlock()

	if !exists {
		log.Printf("no route to %s", payload.To)
		return
	}

	payload.HopCount++
	b, _ := json.Marshal(payload)
	if peer := a.getPeer(nextHop); peer != nil {
		_ = peer.Send("ROUTE_MESSAGE:" + string(b))
	}
}

func (a *ClientApp) SendToViaRoute(user, msg string) bool {
	a.routesMu.RLock()
	nextHop, exists := a.routes[user]
	a.routesMu.RUnlock()

	if !exists {
		return false
	}

	payload := proto.RouteMessagePayload{
		From:     a.Username,
		To:       user,
		Content:  msg,
		HopCount: 0,
	}

	b, _ := json.Marshal(payload)
	if peer := a.getPeer(nextHop); peer != nil {
		_ = peer.Send("ROUTE_MESSAGE:" + string(b))
		return true
	}
	return false
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
	if strings.HasPrefix(message, "NEW_CONNECTION:") {
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
		if strings.Contains(message, "[LOCALCAST]") || strings.Contains(message, "[BROADCAST]") {
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
	
	log.Printf("[DEBUG] %s sharing users reachable via %s: %v", a.Username, newPeer, usersViaNewPeer)
	
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
