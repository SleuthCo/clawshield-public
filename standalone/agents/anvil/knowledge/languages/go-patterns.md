---
framework: "Go"
version: "1.0"
domain: "Programming Languages"
agent: "friday"
tags: ["go", "golang", "interfaces", "goroutines", "channels", "generics", "testing"]
last_updated: "2025-06-01"
chunk_strategy: "heading"
---

# Go Patterns and Idioms

## Interfaces

Go interfaces are satisfied implicitly. Any type that implements all methods of an interface satisfies it without explicit declaration. Keep interfaces small (1-3 methods).

```go
// Define interfaces where they are consumed, not where they are implemented
type Reader interface {
    Read(p []byte) (n int, err error)
}

type Writer interface {
    Write(p []byte) (n int, err error)
}

// Compose interfaces
type ReadWriter interface {
    Reader
    Writer
}

// Accept interfaces, return structs
type UserStore interface {
    GetUser(ctx context.Context, id string) (*User, error)
    SaveUser(ctx context.Context, user *User) error
}

// Concrete implementation
type PostgresUserStore struct {
    db *sql.DB
}

func (s *PostgresUserStore) GetUser(ctx context.Context, id string) (*User, error) {
    row := s.db.QueryRowContext(ctx, "SELECT id, name, email FROM users WHERE id = $1", id)
    var u User
    err := row.Scan(&u.ID, &u.Name, &u.Email)
    if err != nil {
        return nil, fmt.Errorf("get user %s: %w", id, err)
    }
    return &u, nil
}

// Interface assertion
func process(r Reader) {
    if rc, ok := r.(io.ReadCloser); ok {
        defer rc.Close()
    }
}

// Empty interface vs any (Go 1.18+)
// `any` is an alias for `interface{}`
func printValue(v any) {
    fmt.Printf("%v\n", v)
}

// Verify interface compliance at compile time
var _ UserStore = (*PostgresUserStore)(nil)
```

## Goroutines and Channels

Goroutines are lightweight threads managed by the Go runtime. Channels are typed conduits for communication between goroutines.

```go
// Basic goroutine with WaitGroup
func processItems(items []string) {
    var wg sync.WaitGroup
    for _, item := range items {
        wg.Add(1)
        go func(item string) {
            defer wg.Done()
            process(item)
        }(item)
    }
    wg.Wait()
}

// Bounded concurrency with semaphore channel
func processWithLimit(items []string, maxConcurrency int) {
    sem := make(chan struct{}, maxConcurrency)
    var wg sync.WaitGroup

    for _, item := range items {
        wg.Add(1)
        sem <- struct{}{} // acquire
        go func(item string) {
            defer wg.Done()
            defer func() { <-sem }() // release
            process(item)
        }(item)
    }
    wg.Wait()
}

// Fan-out / fan-in pattern
func fanOutFanIn(input <-chan int, workers int) <-chan int {
    channels := make([]<-chan int, workers)
    for i := 0; i < workers; i++ {
        channels[i] = worker(input)
    }
    return merge(channels...)
}

func worker(input <-chan int) <-chan int {
    out := make(chan int)
    go func() {
        defer close(out)
        for n := range input {
            out <- n * n
        }
    }()
    return out
}

func merge(channels ...<-chan int) <-chan int {
    var wg sync.WaitGroup
    merged := make(chan int)
    for _, ch := range channels {
        wg.Add(1)
        go func(c <-chan int) {
            defer wg.Done()
            for v := range c {
                merged <- v
            }
        }(ch)
    }
    go func() {
        wg.Wait()
        close(merged)
    }()
    return merged
}

// Select for multiplexing
func withTimeout(ch <-chan string, timeout time.Duration) (string, error) {
    select {
    case msg := <-ch:
        return msg, nil
    case <-time.After(timeout):
        return "", fmt.Errorf("timeout after %v", timeout)
    }
}

// Done channel pattern for cancellation
func doWork(done <-chan struct{}) <-chan int {
    out := make(chan int)
    go func() {
        defer close(out)
        for i := 0; ; i++ {
            select {
            case <-done:
                return
            case out <- i:
            }
        }
    }()
    return out
}
```

## Context Propagation

`context.Context` carries deadlines, cancellation signals, and request-scoped values across API boundaries and goroutines. Always pass context as the first parameter.

```go
import "context"

// Creating contexts
func main() {
    // With cancellation
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    // With timeout
    ctx, cancel = context.WithTimeout(ctx, 5*time.Second)
    defer cancel()

    // With deadline
    deadline := time.Now().Add(30 * time.Second)
    ctx, cancel = context.WithDeadline(ctx, deadline)
    defer cancel()

    // With value (use sparingly, prefer function parameters)
    ctx = context.WithValue(ctx, requestIDKey, "req-123")
}

// Typed context keys to avoid collisions
type contextKey string

const requestIDKey contextKey = "requestID"

func RequestIDFromContext(ctx context.Context) (string, bool) {
    id, ok := ctx.Value(requestIDKey).(string)
    return id, ok
}

// Respecting context in long-running operations
func fetchAll(ctx context.Context, urls []string) ([]string, error) {
    results := make([]string, 0, len(urls))
    for _, url := range urls {
        select {
        case <-ctx.Done():
            return results, ctx.Err()
        default:
        }
        body, err := fetchURL(ctx, url)
        if err != nil {
            return nil, err
        }
        results = append(results, body)
    }
    return results, nil
}

// HTTP middleware injecting context
func requestIDMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        id := r.Header.Get("X-Request-ID")
        if id == "" {
            id = uuid.New().String()
        }
        ctx := context.WithValue(r.Context(), requestIDKey, id)
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}
```

## Error Handling Patterns

Go errors are values. Use `fmt.Errorf` with `%w` for wrapping, `errors.Is` and `errors.As` for inspection.

```go
import (
    "errors"
    "fmt"
)

// Sentinel errors
var (
    ErrNotFound     = errors.New("not found")
    ErrUnauthorized = errors.New("unauthorized")
    ErrConflict     = errors.New("conflict")
)

// Custom error type
type ValidationError struct {
    Field   string
    Message string
}

func (e *ValidationError) Error() string {
    return fmt.Sprintf("validation failed on %s: %s", e.Field, e.Message)
}

// Wrapping errors for context
func GetUser(ctx context.Context, id string) (*User, error) {
    user, err := db.FindUser(ctx, id)
    if err != nil {
        return nil, fmt.Errorf("get user %s: %w", id, err)
    }
    return user, nil
}

// Checking wrapped errors
func handleError(err error) {
    if errors.Is(err, ErrNotFound) {
        // handle not found
    }

    var validationErr *ValidationError
    if errors.As(err, &validationErr) {
        fmt.Printf("Field: %s\n", validationErr.Field)
    }
}

// Error handling with cleanup
func processFile(path string) (err error) {
    f, err := os.Open(path)
    if err != nil {
        return fmt.Errorf("open file: %w", err)
    }
    defer func() {
        if cerr := f.Close(); cerr != nil && err == nil {
            err = fmt.Errorf("close file: %w", cerr)
        }
    }()

    // process file...
    return nil
}

// Multi-error collection (Go 1.20+ errors.Join)
func validateUser(u *User) error {
    var errs []error
    if u.Name == "" {
        errs = append(errs, &ValidationError{Field: "name", Message: "required"})
    }
    if u.Email == "" {
        errs = append(errs, &ValidationError{Field: "email", Message: "required"})
    }
    return errors.Join(errs...)
}
```

## Table-Driven Tests

Table-driven tests are the standard Go testing pattern. They provide clear test structure and easy addition of new cases.

```go
func TestAdd(t *testing.T) {
    tests := []struct {
        name     string
        a, b     int
        expected int
    }{
        {name: "positive", a: 1, b: 2, expected: 3},
        {name: "negative", a: -1, b: -2, expected: -3},
        {name: "zero", a: 0, b: 0, expected: 0},
        {name: "mixed", a: -1, b: 1, expected: 0},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            result := Add(tt.a, tt.b)
            if result != tt.expected {
                t.Errorf("Add(%d, %d) = %d, want %d", tt.a, tt.b, result, tt.expected)
            }
        })
    }
}

// Table-driven tests with error cases
func TestParseConfig(t *testing.T) {
    tests := []struct {
        name    string
        input   string
        want    *Config
        wantErr bool
    }{
        {
            name:  "valid",
            input: `{"port": 8080}`,
            want:  &Config{Port: 8080},
        },
        {
            name:    "invalid json",
            input:   `{invalid`,
            wantErr: true,
        },
        {
            name:    "missing port",
            input:   `{}`,
            wantErr: true,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got, err := ParseConfig([]byte(tt.input))
            if (err != nil) != tt.wantErr {
                t.Fatalf("ParseConfig() error = %v, wantErr %v", err, tt.wantErr)
            }
            if !tt.wantErr && !reflect.DeepEqual(got, tt.want) {
                t.Errorf("ParseConfig() = %v, want %v", got, tt.want)
            }
        })
    }
}

// Parallel subtests
func TestSlowOperation(t *testing.T) {
    tests := []struct{ name, input, expected string }{
        {"case1", "a", "A"},
        {"case2", "b", "B"},
    }

    for _, tt := range tests {
        tt := tt // capture range variable (not needed in Go 1.22+)
        t.Run(tt.name, func(t *testing.T) {
            t.Parallel()
            result := SlowOperation(tt.input)
            if result != tt.expected {
                t.Errorf("got %s, want %s", result, tt.expected)
            }
        })
    }
}
```

## Dependency Injection

Go favors explicit dependency injection through constructor functions. Avoid global state and `init()` functions.

```go
// Constructor injection (the Go way)
type OrderService struct {
    repo    OrderRepository
    notifier Notifier
    logger  *slog.Logger
}

func NewOrderService(repo OrderRepository, notifier Notifier, logger *slog.Logger) *OrderService {
    return &OrderService{
        repo:     repo,
        notifier: notifier,
        logger:   logger,
    }
}

// Functional options pattern for complex configuration
type ServerOption func(*Server)

func WithPort(port int) ServerOption {
    return func(s *Server) { s.port = port }
}

func WithTLS(certFile, keyFile string) ServerOption {
    return func(s *Server) {
        s.certFile = certFile
        s.keyFile = keyFile
    }
}

func WithLogger(logger *slog.Logger) ServerOption {
    return func(s *Server) { s.logger = logger }
}

func NewServer(opts ...ServerOption) *Server {
    s := &Server{
        port:   8080,
        logger: slog.Default(),
    }
    for _, opt := range opts {
        opt(s)
    }
    return s
}

// Usage
server := NewServer(
    WithPort(9090),
    WithTLS("cert.pem", "key.pem"),
)

// Wire up in main()
func main() {
    db := connectDB()
    repo := NewPostgresOrderRepo(db)
    notifier := NewEmailNotifier(smtpConfig)
    logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
    service := NewOrderService(repo, notifier, logger)
    handler := NewHTTPHandler(service)

    http.ListenAndServe(":8080", handler)
}
```

## Go Modules

Go modules are the standard dependency management system since Go 1.11. The `go.mod` file declares the module path and dependencies.

```
module github.com/myorg/myservice

go 1.22

require (
    github.com/gin-gonic/gin v1.9.1
    github.com/jackc/pgx/v5 v5.5.0
    go.uber.org/zap v1.26.0
)

require (
    // indirect dependencies are managed automatically
    golang.org/x/sys v0.15.0 // indirect
)
```

Key module commands:

```bash
go mod init github.com/myorg/myservice  # Initialize module
go mod tidy                              # Add missing, remove unused deps
go mod vendor                            # Copy deps into vendor/
go mod graph                             # Print dependency graph
go get github.com/pkg/errors@v0.9.1     # Add/upgrade specific version
go get github.com/pkg/errors@latest     # Upgrade to latest
go list -m all                           # List all dependencies
go list -m -versions github.com/gin-gonic/gin  # List available versions
```

Multi-module workspaces (Go 1.18+) allow working on multiple modules simultaneously:

```
// go.work
go 1.22

use (
    ./api
    ./shared
    ./worker
)
```

## Generics (Go 1.18+)

Go generics use type parameters with constraints. Prefer generics for utility functions and data structures; avoid overusing them for simple code.

```go
// Type constraint using interface
type Number interface {
    ~int | ~int32 | ~int64 | ~float32 | ~float64
}

func Sum[T Number](values []T) T {
    var total T
    for _, v := range values {
        total += v
    }
    return total
}

// The ~ operator includes underlying types
type Celsius float64
Sum([]Celsius{20.0, 25.5}) // works because ~float64 matches Celsius

// Generic data structures
type Stack[T any] struct {
    items []T
}

func (s *Stack[T]) Push(item T) {
    s.items = append(s.items, item)
}

func (s *Stack[T]) Pop() (T, bool) {
    if len(s.items) == 0 {
        var zero T
        return zero, false
    }
    item := s.items[len(s.items)-1]
    s.items = s.items[:len(s.items)-1]
    return item, true
}

// Constrained generics
type Ordered interface {
    ~int | ~int8 | ~int16 | ~int32 | ~int64 |
        ~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64 |
        ~float32 | ~float64 | ~string
}

func Max[T Ordered](a, b T) T {
    if a > b {
        return a
    }
    return b
}

// Generic Map/Filter/Reduce
func Map[T, U any](slice []T, fn func(T) U) []U {
    result := make([]U, len(slice))
    for i, v := range slice {
        result[i] = fn(v)
    }
    return result
}

func Filter[T any](slice []T, predicate func(T) bool) []T {
    var result []T
    for _, v := range slice {
        if predicate(v) {
            result = append(result, v)
        }
    }
    return result
}

// Use cmp.Ordered from stdlib (Go 1.21+)
import "cmp"

func Min[T cmp.Ordered](a, b T) T {
    return min(a, b) // built-in min/max in Go 1.21+
}
```

## Structured Logging with slog (Go 1.21+)

The `log/slog` package provides structured, leveled logging in the standard library.

```go
import "log/slog"

// Create a JSON logger
logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
    Level: slog.LevelInfo,
}))

// Structured logging
logger.Info("request processed",
    slog.String("method", "GET"),
    slog.String("path", "/api/users"),
    slog.Int("status", 200),
    slog.Duration("latency", elapsed),
)

// Group related attributes
logger.Info("user action",
    slog.Group("user",
        slog.String("id", "usr_123"),
        slog.String("role", "admin"),
    ),
    slog.Group("request",
        slog.String("ip", remoteAddr),
    ),
)

// Logger with persistent attributes
reqLogger := logger.With(
    slog.String("request_id", requestID),
    slog.String("service", "order-api"),
)
reqLogger.Info("processing order")
```
