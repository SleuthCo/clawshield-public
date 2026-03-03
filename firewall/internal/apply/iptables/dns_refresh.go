package iptables

import (
	"log"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// DNSRefresher periodically re-resolves domain names to IP addresses
// and updates firewall rules when the resolved IPs change.
// This prevents stale rules when CDN/cloud endpoints rotate IPs.
type DNSRefresher struct {
	domains    []string
	interval   time.Duration
	onUpdate   func(domain string, oldIPs, newIPs []string)
	stopCh     chan struct{}
	wg         sync.WaitGroup

	mu         sync.RWMutex
	resolved   map[string][]string // domain -> sorted IPs

	// Stats
	refreshCount int64
	updateCount  int64
	errorCount   int64
}

// NewDNSRefresher creates a DNS refresher for the given domains.
// onUpdate is called whenever a domain's resolved IPs change.
// interval is the time between re-resolution cycles (default: 60s).
func NewDNSRefresher(domains []string, interval time.Duration, onUpdate func(domain string, oldIPs, newIPs []string)) *DNSRefresher {
	if interval <= 0 {
		interval = 60 * time.Second
	}
	return &DNSRefresher{
		domains:  domains,
		interval: interval,
		onUpdate: onUpdate,
		stopCh:   make(chan struct{}),
		resolved: make(map[string][]string),
	}
}

// Start begins periodic DNS re-resolution. Performs an initial resolution
// immediately.
func (d *DNSRefresher) Start() {
	// Initial resolution
	d.refresh()

	d.wg.Add(1)
	go d.loop()

	log.Printf("DNS refresher started: %d domains, interval=%s", len(d.domains), d.interval)
}

// Stop stops the DNS refresher.
func (d *DNSRefresher) Stop() {
	close(d.stopCh)
	d.wg.Wait()
	log.Printf("DNS refresher stopped: refreshes=%d updates=%d errors=%d",
		d.refreshCount, d.updateCount, d.errorCount)
}

// CurrentIPs returns the currently resolved IPs for a domain.
func (d *DNSRefresher) CurrentIPs(domain string) []string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.resolved[domain]
}

// Stats returns refresh statistics.
func (d *DNSRefresher) Stats() (refreshes, updates, errors int64) {
	return d.refreshCount, d.updateCount, d.errorCount
}

func (d *DNSRefresher) loop() {
	defer d.wg.Done()
	ticker := time.NewTicker(d.interval)
	defer ticker.Stop()

	for {
		select {
		case <-d.stopCh:
			return
		case <-ticker.C:
			d.refresh()
		}
	}
}

func (d *DNSRefresher) refresh() {
	d.refreshCount++

	for _, domain := range d.domains {
		newIPs, err := resolveDomain(domain)
		if err != nil {
			d.errorCount++
			log.Printf("WARNING: DNS refresh failed for %s: %v (keeping previous IPs)", domain, err)
			continue
		}

		d.mu.Lock()
		oldIPs := d.resolved[domain]
		if !ipsEqual(oldIPs, newIPs) {
			d.resolved[domain] = newIPs
			d.updateCount++
			log.Printf("DNS update for %s: %s -> %s",
				domain, strings.Join(oldIPs, ","), strings.Join(newIPs, ","))

			if d.onUpdate != nil {
				d.onUpdate(domain, oldIPs, newIPs)
			}
		}
		d.mu.Unlock()
	}
}

// resolveDomain resolves a domain name to a sorted list of IPv4 addresses.
func resolveDomain(domain string) ([]string, error) {
	addrs, err := net.LookupHost(domain)
	if err != nil {
		return nil, err
	}

	// Filter to IPv4 only and deduplicate
	seen := make(map[string]bool)
	var ips []string
	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip == nil {
			continue
		}
		if ip.To4() == nil {
			continue // Skip IPv6 for now
		}
		if !seen[addr] {
			seen[addr] = true
			ips = append(ips, addr)
		}
	}

	sort.Strings(ips)
	return ips, nil
}

// ipsEqual returns true if two sorted IP lists are identical.
func ipsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
