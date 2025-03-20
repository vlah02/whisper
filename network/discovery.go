package network

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

const (
	multicastAddress = "224.0.0.1:9999"
	discoveryPrefix  = "WHISPER_DISCOVER:"
	discoveryTTL     = 30 * time.Second
)

// multicastBroadcast periodically sends discovery messages over UDP multicast.
// Each message includes the local address and a timestamp.
func (p *Peer) multicastBroadcast(myAddress string) {
	udpAddr, err := net.ResolveUDPAddr("udp", multicastAddress)
	if err != nil {
		fmt.Printf("Error resolving multicast address: %v\n", err)
		return
	}
	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		fmt.Printf("Error dialing multicast address: %v\n", err)
		return
	}
	defer conn.Close()

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		// Build the discovery message with the current timestamp.
		message := discoveryPrefix + myAddress + ":" + strconv.FormatInt(time.Now().UnixNano(), 10)
		_, err := conn.Write([]byte(message))
		if err != nil {
			fmt.Printf("Error sending multicast message: %v\n", err)
		}
	}
}

// parseDiscoveryMessage parses a discovery message string, returning the discovered
// peer's address and the timestamp embedded in the message.
func parseDiscoveryMessage(msg string) (string, int64, error) {
	// Remove the discovery prefix.
	content := strings.TrimPrefix(msg, discoveryPrefix)
	parts := strings.Split(content, ":")
	if len(parts) < 2 {
		return "", 0, fmt.Errorf("malformed discovery message: %s", msg)
	}
	// The last part is the timestamp.
	tsStr := parts[len(parts)-1]
	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return "", 0, fmt.Errorf("error parsing timestamp in discovery message: %v", err)
	}
	// Reconstruct the discovered address (in case the address itself contains ':').
	discoveredAddr := strings.Join(parts[:len(parts)-1], ":")
	return discoveredAddr, ts, nil
}

// multicastListen listens for UDP multicast discovery messages.
// It parses incoming messages and, if a new peer is discovered, calls the handler to process it.
func (p *Peer) multicastListen(myAddress string) {
	udpAddr, err := net.ResolveUDPAddr("udp", multicastAddress)
	if err != nil {
		fmt.Printf("Error resolving multicast address: %v\n", err)
		return
	}
	conn, err := net.ListenMulticastUDP("udp", nil, udpAddr)
	if err != nil {
		fmt.Printf("Error listening on multicast UDP: %v\n", err)
		return
	}
	defer conn.Close()

	if err = conn.SetReadBuffer(1024); err != nil {
		return
	}
	buf := make([]byte, 1024)

	for {
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			fmt.Printf("Error reading from multicast UDP: %v\n", err)
			continue
		}
		msg := string(buf[:n])
		if !strings.HasPrefix(msg, discoveryPrefix) {
			continue
		}
		discoveredAddr, ts, err := parseDiscoveryMessage(msg)
		if err != nil {
			fmt.Printf("%v\n", err)
			continue
		}
		// Skip processing if the discovered address is our own.
		if discoveredAddr == myAddress {
			continue
		}
		p.handleDiscoveredPeer(discoveredAddr, ts, src, myAddress)
	}
}

// handleDiscoveredPeer processes the discovered peer's address and timestamp.
// It checks if the peer is already known or if it was recently discovered (within TTL).
// If not, and if the current node started before the discovered peer, it initiates a connection.
func (p *Peer) handleDiscoveredPeer(discoveredAddr string, ts int64, src *net.UDPAddr, myAddress string) {
	p.mu.Lock()
	_, inPeers := p.peers[discoveredAddr]
	_, inPending := p.pending[discoveredAddr]
	last, exists := p.lastDiscovered[discoveredAddr]
	if exists && time.Since(last) < discoveryTTL {
		p.mu.Unlock()
		return
	}
	if p.lastDiscovered == nil {
		p.lastDiscovered = make(map[string]time.Time)
	}
	p.lastDiscovered[discoveredAddr] = time.Now()
	p.mu.Unlock()

	// Check if this node started before the discovered peer.
	if p.StartTime.UnixNano() < ts {
		if !inPeers && !inPending {
			fmt.Printf("Discovered new peer: %s (from %s), initiating connection as older node...\n", discoveredAddr, src.String())
			go p.Connect(discoveredAddr, true)
		}
	}
}

// StartMulticastDiscovery starts both the multicast broadcast and listener in separate goroutines.
func (p *Peer) StartMulticastDiscovery(myAddress string) {
	go p.multicastBroadcast(myAddress)
	go p.multicastListen(myAddress)
}
