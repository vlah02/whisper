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
	crypto.GenerateOnionKeys()

	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Enable auto discovery? (y/n): ")
	autoDiscChoice, err := reader.ReadString('\n')
	if err != nil {
		log.Printf("Error reading auto discovery option: %v", err)
	}
	autoDiscChoice = strings.TrimSpace(strings.ToLower(autoDiscChoice))
	autoDiscovery := autoDiscChoice == "y"

	var autoConnect bool
	if autoDiscovery {
		fmt.Print("Enable auto connect (incoming connections auto-accepted)? (y/n): ")
		autoConnChoice, err := reader.ReadString('\n')
		if err != nil {
			log.Printf("Error reading auto connect option: %v", err)
		}
		autoConnChoice = strings.TrimSpace(strings.ToLower(autoConnChoice))
		autoConnect = autoConnChoice == "y"
	} else {
		autoConnect = false
		fmt.Println("Auto discovery is disabled, so auto connect is skipped.")
	}

	address := "localhost:9000"
	peer, err := network.NewPeer(address, autoConnect)
	if err != nil {
		log.Fatalf("Failed to create peer: %v", err)
	}

	go func() {
		if err := peer.Listen(); err != nil {
			log.Fatalf("Error while listening: %v", err)
		}
	}()

	if autoDiscovery {
		peer.StartMulticastDiscovery(address)
		fmt.Println("Auto discovery enabled.")
	} else {
		fmt.Println("Auto discovery disabled. Use /connect <address> to connect manually.")
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		fmt.Println("\nReceived shutdown signal, closing peer...")
		peer.Close()
		os.Exit(0)
	}()

	fmt.Println("Welcome to Whisper Chat!")
	fmt.Println("Commands:")
	fmt.Println("  /connect <address> - Connect manually")
	fmt.Println("  /accept <remoteID> - Accept a pending connection")
	fmt.Println("  /reject <remoteID> - Reject a pending connection")
	fmt.Println("  /onion <hop1,hop2,...> <message> - Send an onion-routed message")

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
				if err := peer.Connect(parts[1], false); err != nil {
					fmt.Printf("Failed to connect: %v\n", err)
				}
			case "/accept":
				if len(parts) != 2 {
					fmt.Println("Usage: /accept <remoteID>")
					continue
				}
				if err := peer.AcceptConnection(parts[1]); err != nil {
					fmt.Printf("Error accepting connection: %v\n", err)
				}
			case "/reject":
				if len(parts) != 2 {
					fmt.Println("Usage: /reject <remoteID>")
					continue
				}
				if err := peer.RejectConnection(parts[1]); err != nil {
					fmt.Printf("Error rejecting connection: %v\n", err)
				}
			case "/onion":
				if len(parts) < 3 {
					fmt.Println("Usage: /onion <hop1,hop2,...> <message>")
					continue
				}
				route := strings.Split(parts[1], ",")
				finalContent := strings.Join(parts[2:], " ")
				msg := message.NewMessage(peer.ID, finalContent)
				serializedMsg, err := msg.Serialize()
				if err != nil {
					fmt.Printf("Failed to serialize message: %v\n", err)
					continue
				}
				onionMsg, err := crypto.BuildOnionMessage(route, string(serializedMsg))
				if err != nil {
					fmt.Printf("Failed to build onion message: %v\n", err)
					continue
				}
				firstHop := route[0]
				peer.SendOnionMessage(onionMsg, firstHop)
			default:
				fmt.Println("Unknown command.")
			}
		} else {
			msg := message.NewMessage(peer.ID, text)
			peer.BroadcastMessage(msg)
		}
	}
}
