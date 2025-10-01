package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/vlah02/whisper/internal/client"
	"github.com/vlah02/whisper/internal/ui"
)

func main() {
	server := flag.String("server", "ws://localhost:8080/ws", "signaling ws url")
	flag.Parse()

	username := promptUsername()
	app, err := client.NewClient(nil, *server, username)
	if err != nil {
		log.Fatalf("connect: %v", err)
	}
	ui.RunCLI(app)
}

func promptUsername() string {
	fmt.Print("Enter unique username: ")
	var s string
	_, _ = fmt.Fscan(os.Stdin, &s)
	s = strings.TrimSpace(s)
	if s == "" {
		fmt.Println("using 'user' by default")
		s = "user"
	}
	return s
}
