package bus

import (
	"bufio"
	"encoding/json"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/SleuthCo/clawshield/shared/types"
)

// DefaultSocketPath is the default Unix socket path for cross-layer communication.
const DefaultSocketPath = "/tmp/clawshield-events.sock"

// SocketListener listens on a Unix domain socket for incoming SecurityEvents
// (from eBPF or other external producers) and publishes them to a local EventBus.
type SocketListener struct {
	socketPath string
	bus        *EventBus
	listener   net.Listener
	wg         sync.WaitGroup
	quit       chan struct{}
}

// NewSocketListener creates a SocketListener that publishes incoming events to the given bus.
func NewSocketListener(socketPath string, bus *EventBus) *SocketListener {
	if socketPath == "" {
		socketPath = DefaultSocketPath
	}
	return &SocketListener{
		socketPath: socketPath,
		bus:        bus,
		quit:       make(chan struct{}),
	}
}

// Start begins listening for connections on the Unix socket.
// Each connection is handled in its own goroutine, reading newline-delimited JSON events.
func (sl *SocketListener) Start() error {
	// Remove stale socket file if it exists
	if err := os.Remove(sl.socketPath); err != nil && !os.IsNotExist(err) {
		return err
	}

	ln, err := net.Listen("unix", sl.socketPath)
	if err != nil {
		return err
	}
	sl.listener = ln

	// Make socket world-writable so eBPF (running as root) and proxy can both access it
	if err := os.Chmod(sl.socketPath, 0666); err != nil {
		log.Printf("WARNING: failed to chmod event socket: %v", err)
	}

	sl.wg.Add(1)
	go sl.acceptLoop()

	log.Printf("Event bus socket listener started on %s", sl.socketPath)
	return nil
}

// Stop gracefully shuts down the socket listener.
func (sl *SocketListener) Stop() {
	close(sl.quit)
	if sl.listener != nil {
		sl.listener.Close()
	}
	// Clean up socket file
	os.Remove(sl.socketPath)
	sl.wg.Wait()
}

func (sl *SocketListener) acceptLoop() {
	defer sl.wg.Done()

	for {
		conn, err := sl.listener.Accept()
		if err != nil {
			select {
			case <-sl.quit:
				return // Normal shutdown
			default:
				log.Printf("Event socket accept error: %v", err)
				time.Sleep(100 * time.Millisecond)
				continue
			}
		}

		sl.wg.Add(1)
		go sl.handleConnection(conn)
	}
}

func (sl *SocketListener) handleConnection(conn net.Conn) {
	defer sl.wg.Done()
	defer conn.Close()

	scanner := bufio.NewScanner(conn)
	// Allow up to 64KB per event line
	scanner.Buffer(make([]byte, 0, 65536), 65536)

	for scanner.Scan() {
		select {
		case <-sl.quit:
			return
		default:
		}

		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var event types.SecurityEvent
		if err := json.Unmarshal(line, &event); err != nil {
			log.Printf("Event socket: invalid JSON event: %v", err)
			continue
		}

		// Ensure timestamp is set
		if event.Timestamp.IsZero() {
			event.Timestamp = time.Now()
		}

		sl.bus.Publish(&event)
	}

	if err := scanner.Err(); err != nil {
		select {
		case <-sl.quit:
			// Normal shutdown
		default:
			log.Printf("Event socket read error: %v", err)
		}
	}
}

// SocketWriter connects to the Unix domain socket and sends SecurityEvents.
// Used by components that need to publish events to the bus from a separate process
// (e.g., the eBPF monitor running as a separate Python process).
type SocketWriter struct {
	socketPath string
	conn       net.Conn
	mu         sync.Mutex
}

// NewSocketWriter creates a SocketWriter that connects to the event bus socket.
func NewSocketWriter(socketPath string) *SocketWriter {
	if socketPath == "" {
		socketPath = DefaultSocketPath
	}
	return &SocketWriter{
		socketPath: socketPath,
	}
}

// Connect establishes a connection to the Unix socket.
// Retries up to 3 times with exponential backoff.
func (sw *SocketWriter) Connect() error {
	sw.mu.Lock()
	defer sw.mu.Unlock()

	var lastErr error
	for i := 0; i < 3; i++ {
		conn, err := net.DialTimeout("unix", sw.socketPath, 2*time.Second)
		if err == nil {
			sw.conn = conn
			return nil
		}
		lastErr = err
		time.Sleep(time.Duration(1<<uint(i)) * 100 * time.Millisecond) // 100ms, 200ms, 400ms
	}
	return lastErr
}

// Write sends a SecurityEvent to the event bus socket as a newline-delimited JSON line.
// Returns an error if the connection is not established or the write fails.
// Automatically attempts reconnection on write failure.
func (sw *SocketWriter) Write(event *types.SecurityEvent) error {
	sw.mu.Lock()
	defer sw.mu.Unlock()

	if sw.conn == nil {
		// Try to connect
		conn, err := net.DialTimeout("unix", sw.socketPath, 1*time.Second)
		if err != nil {
			return err
		}
		sw.conn = conn
	}

	data, err := json.Marshal(event)
	if err != nil {
		return err
	}
	data = append(data, '\n')

	if _, err := sw.conn.Write(data); err != nil {
		// Connection broken — close and let next call reconnect
		sw.conn.Close()
		sw.conn = nil
		return err
	}

	return nil
}

// Close closes the socket connection.
func (sw *SocketWriter) Close() error {
	sw.mu.Lock()
	defer sw.mu.Unlock()

	if sw.conn != nil {
		err := sw.conn.Close()
		sw.conn = nil
		return err
	}
	return nil
}
