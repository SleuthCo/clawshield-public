package iptables

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestDNSRefresher_InitialResolution(t *testing.T) {
	// Use a domain that's guaranteed to resolve
	domains := []string{"localhost"}
	var updated atomic.Bool

	refresher := NewDNSRefresher(domains, 100*time.Millisecond, func(domain string, oldIPs, newIPs []string) {
		updated.Store(true)
	})
	refresher.Start()
	defer refresher.Stop()

	// Initial resolution should populate IPs
	ips := refresher.CurrentIPs("localhost")
	if len(ips) == 0 {
		t.Fatal("expected localhost to resolve to at least one IP")
	}
}

func TestDNSRefresher_Stats(t *testing.T) {
	refresher := NewDNSRefresher([]string{"localhost"}, 50*time.Millisecond, nil)
	refresher.Start()
	time.Sleep(200 * time.Millisecond)
	refresher.Stop()

	refreshes, _, _ := refresher.Stats()
	if refreshes < 2 {
		t.Fatalf("expected at least 2 refreshes, got %d", refreshes)
	}
}

func TestIPsEqual(t *testing.T) {
	if !ipsEqual([]string{"1.1.1.1", "2.2.2.2"}, []string{"1.1.1.1", "2.2.2.2"}) {
		t.Fatal("expected equal")
	}
	if ipsEqual([]string{"1.1.1.1"}, []string{"1.1.1.1", "2.2.2.2"}) {
		t.Fatal("expected not equal")
	}
	if ipsEqual([]string{"1.1.1.1"}, []string{"2.2.2.2"}) {
		t.Fatal("expected not equal")
	}
	if !ipsEqual(nil, nil) {
		t.Fatal("expected nil equal")
	}
}

func TestDNSRefresher_StopSafety(t *testing.T) {
	refresher := NewDNSRefresher([]string{"localhost"}, 1*time.Second, nil)
	refresher.Start()
	refresher.Stop()
	// Should not panic
}
