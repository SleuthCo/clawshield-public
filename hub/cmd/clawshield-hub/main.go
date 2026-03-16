// Command clawshield-hub runs the ClawShield enterprise fleet management hub.
// It provides a REST API for agent enrollment, check-in, policy management,
// key distribution, and fleet monitoring, plus a web-based admin dashboard.
package main

import (
	"embed"
	"flag"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/SleuthCo/clawshield/hub/internal/api"
	"github.com/SleuthCo/clawshield/hub/internal/store"
)

//go:embed static
var staticFiles embed.FS

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

	apiKey := os.Getenv("CLAWSHIELD_HUB_API_KEY")
	if apiKey == "" {
		log.Println("WARNING: CLAWSHIELD_HUB_API_KEY not set — management API endpoints will reject all requests")
	}
	hub := api.NewHub(s, apiKey)
	mux := http.NewServeMux()
	hub.RegisterRoutes(mux)
	hub.RegisterPolicyRoutes(mux)
	hub.RegisterKeyRoutes(mux)
	hub.RegisterUpdateRoutes(mux)
	hub.RegisterDashboardRoutes(mux)

	// Serve embedded static files and dashboard
	staticFS, err := fs.Sub(staticFiles, "static")
	if err != nil {
		log.Fatalf("failed to create static filesystem: %v", err)
	}
	// Serve root dashboard and static assets via a single catch-all handler
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			data, err := fs.ReadFile(staticFS, "index.html")
			if err != nil {
				http.Error(w, "dashboard not found", 500)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write(data)
			return
		}
		http.NotFound(w, r)
	})

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
	log.Printf("Admin dashboard: http://localhost%s", *listenAddr)
	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalf("server error: %v", err)
	}
}
