package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/vlah02/whisper/internal/signalhub"
)

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	flag.Parse()

	hub := signalhub.NewHub()
	http.HandleFunc("/ws", hub.ServeWS)
	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { fmt.Fprintln(w, "ok") })

	srv := &http.Server{Addr: *addr}
	go func() { log.Printf("signaling server listening on %s", *addr); log.Fatal(srv.ListenAndServe()) }()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	<-ctx.Done()
	stop()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
	log.Println("server stopped")
}
