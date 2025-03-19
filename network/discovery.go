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

	message := discoveryPrefix + myAddress + ":" + strconv.FormatInt(time.Now().UnixNano(), 10)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		_, err = conn.Write([]byte(message))
		if err != nil {
			fmt.Printf("Error sending multicast message: %v\n", err)
		}
	}
}

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
		if strings.HasPrefix(msg, discoveryPrefix) {
			content := strings.TrimPrefix(msg, discoveryPrefix)
			parts := strings.Split(content, ":")
			if len(parts) < 2 {
				fmt.Printf("Malformed discovery message: %s\n", msg)
				continue
			}
			discoveredTimestampStr := parts[len(parts)-1]
			discoveredTimestamp, err := strconv.ParseInt(discoveredTimestampStr, 10, 64)
			if err != nil {
				fmt.Printf("Error parsing timestamp in discovery message: %v\n", err)
				continue
			}
			discoveredAddr := strings.Join(parts[:len(parts)-1], ":")

			if discoveredAddr != myAddress {
				p.mu.Lock()
				_, inPeers := p.peers[discoveredAddr]
				_, inPending := p.pending[discoveredAddr]
				last, exists := p.lastDiscovered[discoveredAddr]
				if exists && time.Since(last) < discoveryTTL {
					p.mu.Unlock()
					continue
				}
				if p.lastDiscovered == nil {
					p.lastDiscovered = make(map[string]time.Time)
				}
				p.lastDiscovered[discoveredAddr] = time.Now()
				p.mu.Unlock()

				if p.StartTime.UnixNano() < discoveredTimestamp {
					if !inPeers && !inPending {
						fmt.Printf("Discovered new peer: %s (from %s), initiating connection as older node...\n", discoveredAddr, src.String())
						go p.Connect(discoveredAddr, true)
					}
				}
			}
		}
	}
}

func (p *Peer) StartMulticastDiscovery(myAddress string) {
	go p.multicastBroadcast(myAddress)
	go p.multicastListen(myAddress)
}
