package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"whisper/crypto"
	"whisper/message"
	"whisper/network"
)

func main() {
	crypto.LoadSharedOnionKeys()

	address := "localhost:9001"
	peer, err := network.NewPeer(address)
	if err != nil {
		log.Fatalf("Failed to create peer: %v", err)
	}

	go func() {
		if err := peer.Listen(); err != nil {
			log.Fatalf("Error while listening: %v", err)
		}
	}()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		fmt.Println("\nReceived shutdown signal, closing peer...")
		peer.Close()
		os.Exit(0)
	}()

	reader := bufio.NewReader(os.Stdin)
	fmt.Println("Welcome to Whisper Chat!")
	fmt.Println("Use /connect <address> to connect to another peer.")
	fmt.Println("Use /onion <hop1,hop2,...> <message> to send an onion-routed message.")
	for {
		fmt.Print("Enter message or command: ")
		text, err := reader.ReadString('\n')
		if err != nil {
			log.Printf("Error reading input: %v", err)
			continue
		}
		text = strings.TrimSpace(text)
		if text == "" {
			continue
		}

		if strings.HasPrefix(text, "/") {
			parts := strings.Fields(text)
			switch parts[0] {
			case "/connect":
				if len(parts) != 2 {
					fmt.Println("Usage: /connect <address>")
					continue
				}
				if err := peer.Connect(parts[1]); err != nil {
					fmt.Printf("Failed to connect: %v\n", err)
				}
			case "/onion":
				if len(parts) < 3 {
					fmt.Println("Usage: /onion <hop1,hop2,...> <message>")
					continue
				}
				route := strings.Split(parts[1], ",")
				finalMessage := strings.Join(parts[2:], " ")
				onionMsg, err := crypto.BuildOnionMessage(route, finalMessage)
				if err != nil {
					fmt.Printf("Failed to build onion message: %v\n", err)
					continue
				}
				peer.BroadcastRaw(onionMsg)
			default:
				fmt.Println("Unknown command.")
			}
		} else {
			msg := message.NewMessage(peer.ID, text)
			peer.BroadcastMessage(msg)
		}
	}
}
