package health

import (
	"encoding/json"
	"sync"
	"time"
)

// Status represents the health status of a layer.
type Status string

const (
	StatusHealthy  Status = "healthy"
	StatusDegraded Status = "degraded"
	StatusDown     Status = "down"
	StatusUnknown  Status = "unknown"
)

// LayerHealth reports the health of a single defense layer.
type LayerHealth struct {
	Name       string            `json:"name"`
	Layer      int               `json:"layer"`      // 1=proxy, 2=firewall, 3=ebpf
	Status     Status            `json:"status"`
	Backend    string            `json:"backend,omitempty"`   // e.g. "ebpf" or "procfs"
	Message    string            `json:"message,omitempty"`
	LastCheck  time.Time         `json:"last_check"`
	Uptime     time.Duration     `json:"uptime"`
	Metrics    map[string]int64  `json:"metrics,omitempty"`   // e.g. events_published, events_dropped
}

// SystemHealth aggregates health from all 3 defense layers.
type SystemHealth struct {
	Overall     Status        `json:"overall"`
	Timestamp   time.Time     `json:"timestamp"`
	Layers      []LayerHealth `json:"layers"`
}

// MarshalJSON serializes SystemHealth to JSON.
func (s *SystemHealth) JSON() ([]byte, error) {
	return json.MarshalIndent(s, "", "  ")
}

// HealthChecker aggregates health from all layers and provides a unified
// health endpoint.
type HealthChecker struct {
	mu         sync.RWMutex
	layers     map[int]*LayerHealth
	startTime  time.Time
}

// NewHealthChecker creates a new health checker.
func NewHealthChecker() *HealthChecker {
	return &HealthChecker{
		layers:    make(map[int]*LayerHealth),
		startTime: time.Now(),
	}
}

// UpdateLayer updates the health status of a specific layer.
// Thread-safe.
func (h *HealthChecker) UpdateLayer(layer int, health LayerHealth) {
	h.mu.Lock()
	defer h.mu.Unlock()
	health.Layer = layer
	health.LastCheck = time.Now()
	h.layers[layer] = &health
}

// SetLayerStatus is a convenience method to update just the status and message.
func (h *HealthChecker) SetLayerStatus(layer int, name string, status Status, message string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	existing, ok := h.layers[layer]
	if ok {
		existing.Status = status
		existing.Message = message
		existing.LastCheck = time.Now()
	} else {
		h.layers[layer] = &LayerHealth{
			Name:      name,
			Layer:     layer,
			Status:    status,
			Message:   message,
			LastCheck: time.Now(),
		}
	}
}

// Check returns the current system health across all layers.
func (h *HealthChecker) Check() *SystemHealth {
	h.mu.RLock()
	defer h.mu.RUnlock()

	result := &SystemHealth{
		Overall:   StatusHealthy,
		Timestamp: time.Now(),
	}

	// Default layers if not reported
	for _, layerNum := range []int{1, 2, 3} {
		if lh, ok := h.layers[layerNum]; ok {
			lh.Uptime = time.Since(h.startTime)
			result.Layers = append(result.Layers, *lh)
		} else {
			// Layer not registered — unknown status
			names := map[int]string{1: "proxy", 2: "firewall", 3: "ebpf"}
			result.Layers = append(result.Layers, LayerHealth{
				Name:      names[layerNum],
				Layer:     layerNum,
				Status:    StatusUnknown,
				Message:   "not registered",
				LastCheck: time.Time{},
			})
		}
	}

	// Overall status: worst of all layers (but unknown doesn't downgrade to down)
	for _, l := range result.Layers {
		switch l.Status {
		case StatusDown:
			result.Overall = StatusDown
		case StatusDegraded:
			if result.Overall != StatusDown {
				result.Overall = StatusDegraded
			}
		case StatusUnknown:
			if result.Overall == StatusHealthy {
				result.Overall = StatusDegraded
			}
		}
	}

	return result
}

// IsHealthy returns true if the overall system status is healthy.
func (h *HealthChecker) IsHealthy() bool {
	return h.Check().Overall == StatusHealthy
}
