// Command clawshield-hub runs the ClawShield enterprise fleet management hub.
// It provides a REST API for agent enrollment, check-in, policy management,
// key distribution, and fleet monitoring.
package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/SleuthCo/clawshield/hub/internal/api"
	"github.com/SleuthCo/clawshield/hub/internal/store"
)

func main() {
	listenAddr := flag.String("listen", ":18800", "address to listen on")
	dbPath := flag.String("db", "hub.db", "path to SQLite database file")
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Lshortfile)

	s, err := store.NewStore(*dbPath)
	if err != nil {
		log.Fatalf("failed to initialize store: %v", err)
	}
	defer s.Close()

	// Initialize all schema extensions
	if err := s.InitPolicySchema(); err != nil {
		log.Fatalf("failed to initialize policy schema: %v", err)
	}
	if err := s.InitKeySchema(); err != nil {
		log.Fatalf("failed to initialize key schema: %v", err)
	}
	if err := s.InitUpdateSchema(); err != nil {
		log.Fatalf("failed to initialize update schema: %v", err)
	}

	hub := api.NewHub(s)
	mux := http.NewServeMux()
	hub.RegisterRoutes(mux)
	hub.RegisterPolicyRoutes(mux)
	hub.RegisterKeyRoutes(mux)
	hub.RegisterUpdateRoutes(mux)
	hub.RegisterDashboardRoutes(mux)

	server := &http.Server{
		Addr:    *listenAddr,
		Handler: mux,
	}

	// Graceful shutdown
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		log.Println("shutting down hub server...")
		server.Close()
	}()

	log.Printf("ClawShield Management Hub listening on %s", *listenAddr)
	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalf("server error: %v", err)
	}
}
