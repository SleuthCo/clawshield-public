package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/SleuthCo/clawshield/shared/bus"
)

func main() {
	socketPath := flag.String("socket", bus.DefaultSocketPath, "Unix socket path for event publishing")
	pollInterval := flag.Duration("poll-interval", 1*time.Second, "Polling interval for procfs monitor")
	flag.Parse()

	log.SetPrefix("[clawshield-ebpf] ")
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	// Check eBPF availability
	ebpfOK, reason := CheckEBPFAvailable()
	if ebpfOK {
		log.Printf("eBPF capability check: PASSED (%s)", reason)
		// In production, this would load the CO-RE compiled eBPF program:
		// monitor = NewEBPFMonitor(config)
		// For now, fall through to procfs as the eBPF loader is a build-time
		// dependency on cilium/ebpf that requires bpf2go code generation.
		log.Printf("NOTE: CO-RE eBPF loader not yet compiled; using procfs fallback")
	} else {
		log.Printf("eBPF capability check: FAILED (%s)", reason)
		log.Printf("Falling back to procfs-based monitoring (degraded mode)")
	}

	// Create procfs monitor
	config := DefaultConfig()
	config.PollInterval = *pollInterval

	monitor := NewProcfsMonitor(config)
	if !monitor.Available() {
		log.Fatalf("FATAL: Neither eBPF nor procfs monitoring available on this system")
	}

	// Connect to event bus
	writer := bus.NewSocketWriter(*socketPath)
	if err := writer.Connect(); err != nil {
		log.Printf("WARNING: Cannot connect to event bus at %s: %v", *socketPath, err)
		log.Printf("Events will be queued until connection is established")
	}
	defer writer.Close()

	// Start monitoring
	if err := monitor.Start(writer); err != nil {
		log.Fatalf("Failed to start monitor: %v", err)
	}

	log.Printf("ClawShield kernel monitor running (backend=%s)", monitor.Name())

	// Wait for signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Periodic stats logging
	statsTicker := time.NewTicker(60 * time.Second)
	defer statsTicker.Stop()

	for {
		select {
		case sig := <-sigCh:
			log.Printf("Received signal %v, shutting down...", sig)
			monitor.Stop()
			stats := monitor.Stats()
			log.Printf("Final stats: backend=%s published=%d dropped=%d uptime=%s",
				stats.Backend, stats.EventsPublished, stats.EventsDropped,
				time.Since(stats.StartTime).Round(time.Second))
			fmt.Println("Shutdown complete.")
			os.Exit(0)
		case <-statsTicker.C:
			stats := monitor.Stats()
			log.Printf("Stats: backend=%s published=%d dropped=%d detections=%v",
				stats.Backend, stats.EventsPublished, stats.EventsDropped, stats.Detections)
		}
	}
}
