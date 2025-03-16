package network

import (
	"fmt"
	"net"
	"strings"
	"time"
)

const (
	multicastAddress = "224.0.0.1:9999"
	discoveryPrefix  = "WHISPER_DISCOVER:"
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

	message := discoveryPrefix + myAddress
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

	conn.SetReadBuffer(1024)
	buf := make([]byte, 1024)

	for {
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			fmt.Printf("Error reading from multicast UDP: %v\n", err)
			continue
		}
		msg := string(buf[:n])
		if strings.HasPrefix(msg, discoveryPrefix) {
			discoveredAddr := strings.TrimPrefix(msg, discoveryPrefix)
			if discoveredAddr != myAddress {
				p.mu.Lock()
				_, exists := p.peers[discoveredAddr]
				p.mu.Unlock()
				if !exists {
					fmt.Printf("Discovered new peer: %s (from %s)\n", discoveredAddr, src.String())
					go p.Connect(discoveredAddr)
				}
			}
		}
	}
}

func (p *Peer) StartMulticastDiscovery(myAddress string) {
	go p.multicastBroadcast(myAddress)
	go p.multicastListen(myAddress)
}
