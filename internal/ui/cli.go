package ui

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/vlah02/whisper/internal/client"
)

func RunCLI(app *client.ClientApp) {
	in := bufio.NewReader(os.Stdin)
	fmt.Println("Commands: /connect [user], /accept [user], /decline [user], /who, /drop [user], /msg [user] [message], /localcast [message], /broadcast [message], /security, /quit")
	for {
		line, err := in.ReadString('\n')
		if err != nil {
			log.Printf("read: %v", err)
			return
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "/") {
			parts := strings.Fields(line)
			cmd := parts[0]
			switch cmd {
			case "/connect":
				if len(parts) < 2 {
					fmt.Println("usage: /connect USER")
					break
				}
				if parts[1] == app.Username {
					fmt.Println("cannot connect to yourself")
					break
				}
				app.Connect(parts[1])
			case "/accept":
				if len(parts) < 2 {
					fmt.Println("usage: /accept USER")
					break
				}
				if parts[1] == app.Username {
					fmt.Println("cannot accept yourself")
					break
				}
				app.Accept(parts[1])
			case "/decline":
				if len(parts) < 2 {
					fmt.Println("usage: /decline USER")
				} else {
					app.Decline(parts[1])
				}
			case "/who":
				app.Who()
			case "/drop":
				if len(parts) < 2 {
					fmt.Println("usage: /drop USER")
				} else {
					app.Drop(parts[1])
				}
			case "/msg":
				if len(parts) < 3 {
					fmt.Println("usage: /msg USER MESSAGE")
				} else {
					user := parts[1]
					msg := strings.Join(parts[2:], " ")
					if err := app.SendTo(user, msg); err != nil {
						fmt.Printf("error sending to %s: %v\n", user, err)
					}
				}
			case "/localcast":
				if len(parts) < 2 {
					fmt.Println("usage: /localcast MESSAGE")
				} else {
					msg := strings.Join(parts[1:], " ")
					app.SendLocalcast(msg)
				}
			case "/broadcast":
				if len(parts) < 2 {
					fmt.Println("usage: /broadcast MESSAGE")
				} else {
					msg := strings.Join(parts[1:], " ")
					app.SendBroadcast(msg)
				}
			case "/security":
				app.ShowSecurityStatus()
			case "/quit":
				fmt.Println("bye")
				return
			default:
				fmt.Println("unknown command")
			}
			continue
		}
		fmt.Println("Unknown input. Use /msg or /broadcast to send messages.")
	}
}
