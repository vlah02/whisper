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

type PeerConnection struct {
	Conn       net.Conn
	SessionKey []byte
	RemoteID   string
}

type Peer struct {
	ID       string
	Address  string
	listener net.Listener
	peers    map[string]*PeerConnection
	pending  map[string]*PeerConnection
	mu       sync.Mutex
	gossip   *GossipManager
}

func NewPeer(address string) (*Peer, error) {
	return &Peer{
		ID:      address,
		Address: address,
		peers:   make(map[string]*PeerConnection),
		pending: make(map[string]*PeerConnection),
		gossip:  NewGossipManager(30 * time.Second),
	}, nil
}

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
		sessionKey, remoteID, err := HandshakeResponder(conn, p.ID)
		if err != nil {
			fmt.Printf("handshake failed with %s: %v\n", conn.RemoteAddr().String(), err)
			conn.Close()
			continue
		}
		p.mu.Lock()
		if _, exists := p.peers[remoteID]; exists {
			p.mu.Unlock()
			conn.Close()
			fmt.Printf("Duplicate connection from %s detected; closing.\n", remoteID)
			continue
		}
		p.pending[remoteID] = &PeerConnection{
			Conn:       conn,
			SessionKey: sessionKey,
			RemoteID:   remoteID,
		}
		p.mu.Unlock()
		fmt.Printf("Incoming connection from %s. Use /accept %s to accept or /reject %s to reject.\n", remoteID, remoteID, remoteID)
	}
}

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
	go p.handleConnection(remoteID, pc.Conn, pc.SessionKey)
	fmt.Printf("Accepted connection from %s\n", remoteID)
	return nil
}

func (p *Peer) RejectConnection(remoteID string) error {
	p.mu.Lock()
	pc, ok := p.pending[remoteID]
	if !ok {
		p.mu.Unlock()
		return fmt.Errorf("no pending connection for %s", remoteID)
	}
	delete(p.pending, remoteID)
	p.mu.Unlock()
	pc.Conn.Close()
	fmt.Printf("Rejected connection from %s\n", remoteID)
	return nil
}

func (p *Peer) handleConnection(remoteID string, conn net.Conn, sessionKey []byte) {
	defer func() {
		p.mu.Lock()
		delete(p.peers, remoteID)
		p.mu.Unlock()
		err := conn.Close()
		if err != nil {
			return
		}
		fmt.Printf("Connection closed: %s\n", remoteID)
	}()

	fmt.Printf("New connection from: %s\n", remoteID)
	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			fmt.Printf("Error reading from connection: %v\n", err)
			return
		}
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ONION:") {
			nextHop, innerPayload, isFinal, err := crypto.ProcessOnionMessage(line)
			if err != nil {
				fmt.Printf("Failed to process onion message from %s: %v\n", remoteID, err)
				continue
			}
			if isFinal {
				var msg message.Message
				msg, err = message.DeserializeMessage([]byte(innerPayload))
				if err != nil {
					fmt.Printf("[Onion Final] %s\n", innerPayload)
				} else {
					fmt.Printf("[Onion Final][%s] %s: %s\n", msg.Timestamp.Format("15:04:05"), msg.Sender, msg.Content)
				}
			} else {
				fmt.Printf("Forwarding onion message to %s\n", nextHop)
				p.mu.Lock()
				pc, ok := p.peers[nextHop]
				p.mu.Unlock()
				if ok {
					_, err = fmt.Fprintf(pc.Conn, "ONION:%s\n", innerPayload)
					if err != nil {
						fmt.Printf("Error forwarding onion message to %s: %v\n", nextHop, err)
					}
				} else {
					fmt.Printf("Not connected to next hop %s. Cannot forward onion message.\n", nextHop)
				}
			}
		} else {
			var sym encryption.Symmetric
			plaintext, err := sym.Decrypt(line, sessionKey)
			if err != nil {
				fmt.Printf("Failed to decrypt message from %s: %v\n", remoteID, err)
				fmt.Printf("Raw message: %s\n", line)
				continue
			}
			msg, err := message.DeserializeMessage(plaintext)
			if err != nil {
				fmt.Printf("Failed to deserialize message from %s: %v\n", remoteID, err)
				continue
			}
			if p.gossip.Seen(msg.ID) {
				continue
			}
			p.gossip.MarkSeen(msg.ID)
			fmt.Printf("[%s] %s: %s\n", msg.Timestamp.Format("15:04:05"), msg.Sender, msg.Content)
			p.BroadcastMessage(msg)
		}
	}
}

func (p *Peer) Close() {
	if p.listener != nil {
		if err := p.listener.Close(); err != nil {
			return
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for addr, pc := range p.peers {
		err := pc.Conn.Close()
		if err != nil {
			return
		}
		delete(p.peers, addr)
	}
	fmt.Println("Peer shutdown completed.")
}

func (p *Peer) Connect(address string) error {
	conn, err := net.Dial("tcp", address)
	if err != nil {
		return fmt.Errorf("failed to connect to %s: %v", address, err)
	}
	sessionKey, remoteID, err := HandshakeInitiator(conn, p.ID)
	if err != nil {
		err := conn.Close()
		if err != nil {
			return err
		}
		return fmt.Errorf("handshake failed with %s: %v", address, err)
	}
	p.mu.Lock()
	if _, exists := p.peers[remoteID]; exists {
		p.mu.Unlock()
		err := conn.Close()
		if err != nil {
			return err
		}
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
	return nil
}

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
		_, err = fmt.Fprintf(pc.Conn, "%s\n", encrypted)
		if err != nil {
			fmt.Printf("Error sending to %s: %v\n", addr, err)
		}
	}
}

func (p *Peer) BroadcastRaw(raw string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for addr, pc := range p.peers {
		_, err := fmt.Fprintf(pc.Conn, "%s\n", raw)
		if err != nil {
			fmt.Printf("Error sending raw message to %s: %v\n", addr, err)
		}
	}
}

func (p *Peer) SendOnionMessage(onionMsg, firstHop string) {
	p.mu.Lock()
	pc, ok := p.peers[firstHop]
	p.mu.Unlock()
	if !ok {
		fmt.Printf("Not connected to first hop %s, attempting to connect...\n", firstHop)
		if err := p.Connect(firstHop); err != nil {
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
	_, err := fmt.Fprintf(pc.Conn, "%s\n", onionMsg)
	if err != nil {
		fmt.Printf("Error sending onion message to %s: %v\n", firstHop, err)
	}
}
