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

// main is the entry point for the Whisper Chat application.
// It sets up the cryptographic keys, network peer, and user interface.
func main() {
	// Generate RSA keys for onion routing.
	crypto.GenerateOnionKeys()

	// Create a buffered reader for user input.
	reader := bufio.NewReader(os.Stdin)

	// Retrieve user preferences for auto discovery and auto connect.
	autoDiscovery, autoConnect := getAutoDiscoveryOptions(reader)

	// Define the local address for this peer.
	address := "localhost:9001"
	peer, err := network.NewPeer(address, autoConnect)
	if err != nil {
		log.Fatalf("Failed to create peer: %v", err)
	}

	// Start the TCP listener for incoming connections in a separate goroutine.
	go startListening(peer)

	// Start multicast discovery if enabled.
	if autoDiscovery {
		peer.StartMulticastDiscovery(address)
		fmt.Println("Auto discovery enabled.")
	} else {
		fmt.Println("Auto discovery disabled. Use /connect <address> to connect manually.")
	}

	// Setup graceful shutdown handling.
	go handleShutdown(peer)

	// Print welcome message and available commands.
	printWelcomeMessage()

	// Enter the main loop to process user input.
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
		// Check if input is a command (prefixed with '/')
		if strings.HasPrefix(text, "/") {
			if err := dispatchCommand(peer, text); err != nil {
				fmt.Println("Command error:", err)
			}
		} else {
			// Create a new chat message and broadcast it.
			msg := message.NewMessage(peer.ID, text)
			peer.BroadcastMessage(msg)
		}
	}
}

// getAutoDiscoveryOptions prompts the user for auto discovery and auto connect preferences.
// Returns two booleans indicating whether auto discovery and auto connect are enabled.
func getAutoDiscoveryOptions(reader *bufio.Reader) (autoDiscovery bool, autoConnect bool) {
	fmt.Print("Enable auto discovery? (y/n): ")
	autoDiscChoice, err := reader.ReadString('\n')
	if err != nil {
		log.Printf("Error reading auto discovery option: %v", err)
	}
	autoDiscChoice = strings.TrimSpace(strings.ToLower(autoDiscChoice))
	autoDiscovery = autoDiscChoice == "y"

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
	return
}

// startListening starts the peer's TCP listener to accept incoming connections.
func startListening(peer *network.Peer) {
	if err := peer.Listen(); err != nil {
		log.Fatalf("Error while listening: %v", err)
	}
}

// handleShutdown listens for termination signals and gracefully shuts down the peer.
func handleShutdown(peer *network.Peer) {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs
	fmt.Println("\nReceived shutdown signal, closing peer...")
	peer.Close()
	os.Exit(0)
}

// printWelcomeMessage displays the welcome banner and available commands to the user.
func printWelcomeMessage() {
	fmt.Println("Welcome to Whisper Chat!")
	fmt.Println("Commands:")
	fmt.Println("  /connect <address>                - Connect manually")
	fmt.Println("  /accept <remoteID>                - Accept a pending connection")
	fmt.Println("  /reject <remoteID>                - Reject a pending connection")
	fmt.Println("  /onion <hop1,hop2,...> <message>   - Send an onion-routed message")
}

// commandHandler defines the signature for command handler functions.
type commandHandler func(args []string, peer *network.Peer) error

// commandMap maps command strings to their corresponding handler functions.
var commandMap = map[string]commandHandler{
	"/connect": handleConnectCommand,
	"/accept":  handleAcceptCommand,
	"/reject":  handleRejectCommand,
	"/onion":   handleOnionCommand,
}

// dispatchCommand parses the input command and dispatches it to the appropriate handler.
func dispatchCommand(peer *network.Peer, input string) error {
	parts := strings.Fields(input)
	if len(parts) == 0 {
		return nil
	}
	cmd := parts[0]
	handler, exists := commandMap[cmd]
	if !exists {
		return fmt.Errorf("unknown command")
	}
	return handler(parts, peer)
}

// handleConnectCommand processes the /connect command to establish a connection to a peer.
func handleConnectCommand(args []string, peer *network.Peer) error {
	if len(args) != 2 {
		return fmt.Errorf("Usage: /connect <address>")
	}
	if err := peer.Connect(args[1], false); err != nil {
		return fmt.Errorf("failed to connect: %v", err)
	}
	return nil
}

// handleAcceptCommand processes the /accept command to accept a pending connection.
func handleAcceptCommand(args []string, peer *network.Peer) error {
	if len(args) != 2 {
		return fmt.Errorf("Usage: /accept <remoteID>")
	}
	if err := peer.AcceptConnection(args[1]); err != nil {
		return fmt.Errorf("error accepting connection: %v", err)
	}
	return nil
}

// handleRejectCommand processes the /reject command to reject a pending connection.
func handleRejectCommand(args []string, peer *network.Peer) error {
	if len(args) != 2 {
		return fmt.Errorf("Usage: /reject <remoteID>")
	}
	if err := peer.RejectConnection(args[1]); err != nil {
		return fmt.Errorf("error rejecting connection: %v", err)
	}
	return nil
}

// handleOnionCommand processes the /onion command to send an onion-routed message.
// It expects a comma-separated list of hops and the message content.
func handleOnionCommand(args []string, peer *network.Peer) error {
	if len(args) < 3 {
		return fmt.Errorf("Usage: /onion <hop1,hop2,...> <message>")
	}
	route := strings.Split(args[1], ",")
	finalContent := strings.Join(args[2:], " ")

	// Create a new message for the onion payload.
	msg := message.NewMessage(peer.ID, finalContent)
	serializedMsg, err := msg.Serialize()
	if err != nil {
		return fmt.Errorf("failed to serialize message: %v", err)
	}

	// Build the onion message by wrapping the payload through the provided route.
	onionMsg, err := crypto.BuildOnionMessage(route, string(serializedMsg))
	if err != nil {
		return fmt.Errorf("failed to build onion message: %v", err)
	}

	// Send the onion message to the first hop in the route.
	firstHop := route[0]
	peer.SendOnionMessage(onionMsg, firstHop)
	return nil
}
