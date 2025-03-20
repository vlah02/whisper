package network

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"whisper/crypto"
	"whisper/crypto/encryption"
	"whisper/message"
)

// PeerConnection represents a connection with a remote peer.
type PeerConnection struct {
	Conn       net.Conn
	SessionKey []byte
	RemoteID   string
}

// Peer represents a node in the Whisper Chat network.
type Peer struct {
	ID             string
	Address        string
	listener       net.Listener
	peers          map[string]*PeerConnection
	pending        map[string]*PeerConnection
	lastDiscovered map[string]time.Time
	autoAccept     bool
	mu             sync.Mutex
	gossip         *GossipManager
	StartTime      time.Time
}

// NewPeer creates a new Peer with the given address and autoConnect flag.
func NewPeer(address string, autoConnect bool) (*Peer, error) {
	return &Peer{
		ID:             address,
		Address:        address,
		peers:          make(map[string]*PeerConnection),
		pending:        make(map[string]*PeerConnection),
		autoAccept:     autoConnect,
		lastDiscovered: make(map[string]time.Time),
		gossip:         NewGossipManager(30 * time.Second),
		StartTime:      time.Now(),
	}, nil
}

// Listen starts a TCP listener for incoming peer connections.
// It accepts new connections, performs the handshake, and then either
// auto-accepts or queues the connection for manual acceptance.
func (p *Peer) Listen() error {
	ln, err := net.Listen("tcp", p.Address)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %v", p.Address, err)
	}
	p.listener = ln
	fmt.Printf("Peer %s listening on %s\n", p.ID, p.Address)

	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Printf("error accepting connection: %v\n", err)
			continue
		}

		// Process handshake for the incoming connection.
		sessionKey, remoteID, incomingConnType, err := HandshakeResponder(conn, p.ID)
		if err != nil {
			fmt.Printf("handshake failed with %s: %v\n", conn.RemoteAddr().String(), err)
			conn.Close()
			continue
		}
		p.processIncomingConnection(conn, sessionKey, remoteID, incomingConnType)
	}
}

// processIncomingConnection handles an incoming connection based on its type.
// If auto acceptance is enabled, the connection is immediately handled;
// otherwise, it is added to the pending queue for manual acceptance.
func (p *Peer) processIncomingConnection(conn net.Conn, sessionKey []byte, remoteID, connType string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if connType == "explicit" || !p.autoAccept {
		if _, exists := p.pending[remoteID]; exists {
			conn.Close()
			fmt.Printf("Duplicate pending connection from %s detected; closing.\n", remoteID)
			return
		}
		p.pending[remoteID] = &PeerConnection{
			Conn:       conn,
			SessionKey: sessionKey,
			RemoteID:   remoteID,
		}
		fmt.Printf("Incoming connection from %s is pending acceptance. Use /accept or /reject.\n", remoteID)
	} else {
		if _, exists := p.peers[remoteID]; exists {
			conn.Close()
			fmt.Printf("Duplicate connection from %s detected; closing.\n", remoteID)
			return
		}
		p.peers[remoteID] = &PeerConnection{
			Conn:       conn,
			SessionKey: sessionKey,
			RemoteID:   remoteID,
		}
		fmt.Printf("Auto accepted connection from %s\n", remoteID)
		go p.handleConnection(remoteID, conn, sessionKey)
	}
}

// handleConnection manages communication with a connected peer.
// It reads messages from the connection and dispatches them to the proper handlers.
func (p *Peer) handleConnection(remoteID string, conn net.Conn, sessionKey []byte) {
	defer p.cleanupConnection(remoteID, conn)

	fmt.Printf("New connection from: %s\n", remoteID)
	reader := bufio.NewReader(conn)

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			fmt.Printf("Error reading from connection %s: %v\n", remoteID, err)
			return
		}
		line = strings.TrimSpace(line)

		// If the remote peer rejects the connection.
		if line == "REJECT" {
			fmt.Printf("Connection from %s was rejected by remote.\n", remoteID)
			return
		}

		// Check if the message is an onion-routed message.
		if strings.HasPrefix(line, "ONION:") {
			p.processOnionMessage(remoteID, line)
		} else {
			p.processStandardMessage(remoteID, line, sessionKey)
		}
	}
}

// cleanupConnection removes the connection from the active peers and closes it.
func (p *Peer) cleanupConnection(remoteID string, conn net.Conn) {
	p.mu.Lock()
	delete(p.peers, remoteID)
	p.mu.Unlock()
	conn.Close()
	fmt.Printf("Connection closed: %s\n", remoteID)
}

// processOnionMessage handles onion-routed messages, including decryption and forwarding.
func (p *Peer) processOnionMessage(remoteID, line string) {
	nextHop, innerPayload, isFinal, err := crypto.ProcessOnionMessage(line)
	if err != nil {
		fmt.Printf("Failed to process onion message from %s: %v\n", remoteID, err)
		return
	}

	if isFinal {
		// Final onion message: try to deserialize and display it.
		msg, err := message.DeserializeMessage([]byte(innerPayload))
		if err != nil {
			fmt.Printf("[Onion Final] %s\n", innerPayload)
		} else {
			fmt.Printf("[Onion Final][%s] %s: %s\n", msg.Timestamp.Format("15:04:05"), msg.Sender, msg.Content)
		}
	} else {
		// Forward the onion message to the next hop.
		fmt.Printf("Forwarding onion message to %s\n", nextHop)
		p.mu.Lock()
		pc, ok := p.peers[nextHop]
		p.mu.Unlock()
		if ok {
			if _, err = fmt.Fprintf(pc.Conn, "ONION:%s\n", innerPayload); err != nil {
				fmt.Printf("Error forwarding onion message to %s: %v\n", nextHop, err)
			}
		} else {
			fmt.Printf("Not connected to next hop %s. Cannot forward onion message.\n", nextHop)
		}
	}
}

// processStandardMessage decrypts and processes a standard (non-onion) message.
func (p *Peer) processStandardMessage(remoteID, line string, sessionKey []byte) {
	var sym encryption.Symmetric
	plaintext, err := sym.Decrypt(line, sessionKey)
	if err != nil {
		fmt.Printf("Failed to decrypt message from %s: %v\n", remoteID, err)
		fmt.Printf("Raw message: %s\n", line)
		return
	}

	msg, err := message.DeserializeMessage(plaintext)
	if err != nil {
		fmt.Printf("Failed to deserialize message from %s: %v\n", remoteID, err)
		return
	}

	if p.gossip.Seen(msg.ID) {
		return
	}

	p.gossip.MarkSeen(msg.ID)
	fmt.Printf("[%s] %s: %s\n", msg.Timestamp.Format("15:04:05"), msg.Sender, msg.Content)
	p.BroadcastMessage(msg)
}

// Connect initiates a connection to a remote peer at the specified address.
// It performs the handshake and either auto-accepts the connection or adds it to the pending queue.
func (p *Peer) Connect(address string, auto bool) error {
	p.mu.Lock()
	if _, exists := p.peers[address]; exists {
		p.mu.Unlock()
		return nil
	}
	if _, exists := p.pending[address]; exists {
		p.mu.Unlock()
		return nil
	}
	p.mu.Unlock()

	conn, err := net.Dial("tcp", address)
	if err != nil {
		return fmt.Errorf("failed to connect to %s: %v", address, err)
	}

	var connType string
	if auto && p.autoAccept {
		connType = "auto"
	} else {
		connType = "explicit"
	}

	sessionKey, remoteID, err := HandshakeInitiator(conn, p.ID, connType)
	if err != nil {
		conn.Close()
		return fmt.Errorf("handshake failed with %s: %v", address, err)
	}

	if connType == "auto" {
		p.mu.Lock()
		if _, exists := p.peers[remoteID]; exists {
			p.mu.Unlock()
			conn.Close()
			fmt.Printf("Duplicate connection to %s detected; closing new connection.\n", remoteID)
			return nil
		}
		p.peers[remoteID] = &PeerConnection{
			Conn:       conn,
			SessionKey: sessionKey,
			RemoteID:   remoteID,
		}
		p.mu.Unlock()
		go p.handleConnection(remoteID, conn, sessionKey)
		fmt.Printf("Connected to peer %s at %s\n", remoteID, address)
	} else {
		p.mu.Lock()
		if _, exists := p.pending[remoteID]; exists {
			p.mu.Unlock()
			conn.Close()
			fmt.Printf("Duplicate pending connection to %s detected; closing new connection.\n", remoteID)
			return nil
		}
		p.pending[remoteID] = &PeerConnection{
			Conn:       conn,
			SessionKey: sessionKey,
			RemoteID:   remoteID,
		}
		p.mu.Unlock()
		fmt.Printf("Connection request sent to peer %s at %s. Awaiting acceptance...\n", remoteID, address)
		go p.waitForAcceptance(remoteID, conn, sessionKey)
	}
	return nil
}

// waitForAcceptance waits for the remote peer to respond to a connection request.
// On acceptance, the connection is moved from pending to active peers.
func (p *Peer) waitForAcceptance(remoteID string, conn net.Conn, sessionKey []byte) {
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		fmt.Printf("Error waiting for acceptance from %s: %v\n", remoteID, err)
		p.mu.Lock()
		delete(p.pending, remoteID)
		p.mu.Unlock()
		conn.Close()
		return
	}
	line = strings.TrimSpace(line)
	if line == "ACCEPT" {
		p.mu.Lock()
		pc, exists := p.pending[remoteID]
		if exists {
			delete(p.pending, remoteID)
			p.peers[remoteID] = pc
		}
		p.mu.Unlock()
		fmt.Printf("Peer %s accepted the connection.\n", remoteID)
		go p.handleConnection(remoteID, conn, sessionKey)
	} else {
		p.mu.Lock()
		delete(p.pending, remoteID)
		p.mu.Unlock()
		fmt.Printf("Peer %s rejected the connection.\n", remoteID)
		conn.Close()
	}
}

// AcceptConnection manually accepts a pending connection from a remote peer.
func (p *Peer) AcceptConnection(remoteID string) error {
	p.mu.Lock()
	pc, ok := p.pending[remoteID]
	if !ok {
		p.mu.Unlock()
		return fmt.Errorf("no pending connection for %s", remoteID)
	}
	p.peers[remoteID] = pc
	delete(p.pending, remoteID)
	p.mu.Unlock()
	if _, err := fmt.Fprintf(pc.Conn, "ACCEPT\n"); err != nil {
		return fmt.Errorf("failed to send acceptance message: %v", err)
	}
	go p.handleConnection(remoteID, pc.Conn, pc.SessionKey)
	fmt.Printf("Accepted connection from %s\n", remoteID)
	return nil
}

// RejectConnection manually rejects a pending connection from a remote peer.
func (p *Peer) RejectConnection(remoteID string) error {
	p.mu.Lock()
	pc, ok := p.pending[remoteID]
	if !ok {
		p.mu.Unlock()
		return fmt.Errorf("no pending connection for %s", remoteID)
	}
	delete(p.pending, remoteID)
	p.mu.Unlock()
	fmt.Fprintf(pc.Conn, "REJECT\n")
	pc.Conn.Close()
	fmt.Printf("Rejected connection from %s\n", remoteID)
	return nil
}

// Close shuts down the peer by closing the listener and all active connections.
func (p *Peer) Close() {
	if p.listener != nil {
		_ = p.listener.Close()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for addr, pc := range p.peers {
		_ = pc.Conn.Close()
		delete(p.peers, addr)
	}
	fmt.Println("Peer shutdown completed.")
}

// BroadcastMessage encrypts and sends a message to all connected peers.
func (p *Peer) BroadcastMessage(msg message.Message) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.gossip.Seen(msg.ID) {
		return
	}
	p.gossip.MarkSeen(msg.ID)
	var sym encryption.Symmetric
	serialized, err := msg.Serialize()
	if err != nil {
		fmt.Printf("Error serializing message: %v\n", err)
		return
	}
	for addr, pc := range p.peers {
		encrypted, err := sym.Encrypt(serialized, pc.SessionKey)
		if err != nil {
			fmt.Printf("Error encrypting message for %s: %v\n", addr, err)
			continue
		}
		if _, err = fmt.Fprintf(pc.Conn, "%s\n", encrypted); err != nil {
			fmt.Printf("Error sending to %s: %v\n", addr, err)
		}
	}
}

// BroadcastRaw sends a raw string message to all connected peers.
func (p *Peer) BroadcastRaw(raw string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for addr, pc := range p.peers {
		if _, err := fmt.Fprintf(pc.Conn, "%s\n", raw); err != nil {
			fmt.Printf("Error sending raw message to %s: %v\n", addr, err)
		}
	}
}

// SendOnionMessage sends an onion-routed message to the first hop.
// If the first hop is not connected, it attempts to connect.
func (p *Peer) SendOnionMessage(onionMsg, firstHop string) {
	p.mu.Lock()
	pc, ok := p.peers[firstHop]
	p.mu.Unlock()
	if !ok {
		fmt.Printf("Not connected to first hop %s, attempting to connect...\n", firstHop)
		if err := p.Connect(firstHop, true); err != nil {
			fmt.Printf("Failed to connect to first hop %s: %v\n", firstHop, err)
			return
		}
		p.mu.Lock()
		pc, ok = p.peers[firstHop]
		p.mu.Unlock()
		if !ok {
			fmt.Printf("Still not connected to first hop %s\n", firstHop)
			return
		}
	}
	if _, err := fmt.Fprintf(pc.Conn, "%s\n", onionMsg); err != nil {
		fmt.Printf("Error sending onion message to %s: %v\n", firstHop, err)
	}
}
