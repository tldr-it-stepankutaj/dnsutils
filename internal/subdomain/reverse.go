package subdomain

import (
	"net"
	"sync"
)

// ReverseFinder handles reverse DNS (PTR) lookups
type ReverseFinder struct {
	MaxConcurrent int
}

// NewReverseFinder creates a new reverse DNS finder
func NewReverseFinder() *ReverseFinder {
	return &ReverseFinder{MaxConcurrent: 40}
}

// ReverseDNSResult represents the result of a reverse DNS lookup for a single IP
type ReverseDNSResult struct {
	IP        string   `json:"ip"`
	Hostnames []string `json:"hostnames"`
}

// ReverseLookup performs PTR lookups for a list of IPs concurrently
func (rf *ReverseFinder) ReverseLookup(ips []string) []ReverseDNSResult {
	var (
		mu      sync.Mutex
		wg      sync.WaitGroup
		results []ReverseDNSResult
	)

	sem := make(chan struct{}, rf.MaxConcurrent)

	for _, ip := range ips {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()

			// Acquire semaphore
			sem <- struct{}{}
			defer func() { <-sem }()

			names, err := net.LookupAddr(ip)
			if err != nil || len(names) == 0 {
				return
			}

			// Clean trailing dots from PTR records
			hostnames := make([]string, 0, len(names))
			for _, name := range names {
				if len(name) > 0 && name[len(name)-1] == '.' {
					name = name[:len(name)-1]
				}
				if name != "" {
					hostnames = append(hostnames, name)
				}
			}

			if len(hostnames) > 0 {
				mu.Lock()
				results = append(results, ReverseDNSResult{
					IP:        ip,
					Hostnames: hostnames,
				})
				mu.Unlock()
			}
		}(ip)
	}

	wg.Wait()
	return results
}
