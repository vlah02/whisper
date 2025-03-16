package network

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"whisper/crypto"
	"whisper/message"
)

type PeerConnection struct {
	Conn       net.Conn
	SessionKey []byte
}

type Peer struct {
	ID       string
	Address  string
	listener net.Listener
	peers    map[string]*PeerConnection
	mu       sync.Mutex

	gossip *GossipManager
}

func NewPeer(address string) (*Peer, error) {
	return &Peer{
		ID:      address,
		Address: address,
		peers:   make(map[string]*PeerConnection),
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
		sessionKey, err := HandshakeResponder(conn)
		if err != nil {
			fmt.Printf("handshake failed with %s: %v\n", conn.RemoteAddr().String(), err)
			err := conn.Close()
			if err != nil {
				return err
			}
			continue
		}
		peerAddr := conn.RemoteAddr().String()
		p.mu.Lock()
		p.peers[peerAddr] = &PeerConnection{
			Conn:       conn,
			SessionKey: sessionKey,
		}
		p.mu.Unlock()
		go p.handleConnection(conn, sessionKey)
	}
}

func (p *Peer) handleConnection(conn net.Conn, sessionKey []byte) {
	defer func() {
		p.mu.Lock()
		delete(p.peers, conn.RemoteAddr().String())
		p.mu.Unlock()
		err := conn.Close()
		if err != nil {
			return
		}
		fmt.Printf("Connection closed: %s\n", conn.RemoteAddr().String())
	}()

	fmt.Printf("New connection from: %s\n", conn.RemoteAddr().String())
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
				fmt.Printf("Failed to process onion message from %s: %v\n", conn.RemoteAddr().String(), err)
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
			msg, err := crypto.DecryptMessage(line, sessionKey)
			if err != nil {
				fmt.Printf("Failed to decrypt message from %s: %v\n", conn.RemoteAddr().String(), err)
				fmt.Printf("Raw message: %s\n", line)
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
		err := p.listener.Close()
		if err != nil {
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
	sessionKey, err := HandshakeInitiator(conn)
	if err != nil {
		err := conn.Close()
		if err != nil {
			return err
		}
		return fmt.Errorf("handshake failed with %s: %v", address, err)
	}
	p.mu.Lock()
	p.peers[address] = &PeerConnection{
		Conn:       conn,
		SessionKey: sessionKey,
	}
	p.mu.Unlock()
	go p.handleConnection(conn, sessionKey)
	fmt.Printf("Connected to peer at %s\n", address)
	return nil
}

func (p *Peer) BroadcastMessage(msg message.Message) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.gossip.Seen(msg.ID) {
		return
	}
	p.gossip.MarkSeen(msg.ID)
	for addr, pc := range p.peers {
		encrypted, err := crypto.EncryptMessage(msg, pc.SessionKey)
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
