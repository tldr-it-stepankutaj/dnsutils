package subdomain

import (
	"bufio"
	"fmt"
	"os"
	"sync"
)

// BruteFinder handles brute-force subdomain discovery
type BruteFinder struct {
	MaxConcurrent int
}

// NewBruteFinder creates a new brute-force subdomain finder
func NewBruteFinder() *BruteFinder {
	return &BruteFinder{
		MaxConcurrent: 40,
	}
}

// SubdomainResult represents a found subdomain
type SubdomainResult struct {
	Name string
	IP   string
}

// BruteForceSubdomains finds subdomains using brute force
func (bf *BruteFinder) BruteForceSubdomains(domain string, wordlistFile string) []SubdomainResult {
	var results []SubdomainResult

	// Get prefixes to test
	prefixes := bf.getSubdomainPrefixes(wordlistFile)

	// Create a channel for results
	resultChan := make(chan *SubdomainResult)

	// Create a wait group to track goroutines
	var wg sync.WaitGroup

	// Create semaphore for concurrency control
	sem := make(chan struct{}, bf.MaxConcurrent)

	// Create a CertFinder to use its CheckSubdomain method
	certFinder := NewCertFinder()

	// Launch goroutines for each prefix
	for _, prefix := range prefixes {
		wg.Add(1)
		go func(prefix string) {
			defer wg.Done()

			// Acquire semaphore
			sem <- struct{}{}
			defer func() { <-sem }()

			subdomain := fmt.Sprintf("%s.%s", prefix, domain)
			name, ip, err := certFinder.CheckSubdomain(subdomain)
			if err == nil {
				resultChan <- &SubdomainResult{
					Name: name,
					IP:   ip,
				}
			} else {
				resultChan <- nil
			}
		}(prefix)
	}

	// Collect results in a separate goroutine
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Process results
	for result := range resultChan {
		if result != nil {
			results = append(results, *result)
		}
	}

	return results
}

// getSubdomainPrefixes gets prefixes to use for subdomain brute forcing
func (bf *BruteFinder) getSubdomainPrefixes(wordlistFile string) []string {
	// Default common prefixes
	commonPrefixes := []string{
		"www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
		"smtp", "secure", "vpn", "m", "shop", "ftp", "mail2", "test", "portal",
		"dns", "ns", "ww1", "host", "support", "dev", "web", "bbs", "mx", "email",
		"cloud", "1", "2", "forum", "news", "app", "api", "stage", "gw", "admin",
		"store", "beta", "wap", "dns1", "cdn", "ssh", "auth", "new", "static", "3",
		"adm", "4", "old", "files", "5", "help", "login", "intranet", "media", "chat",
	}

	// If wordlist file is provided, use it
	if wordlistFile != "" {
		file, err := os.Open(wordlistFile)
		if err == nil {
			defer file.Close()

			var prefixes []string
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				prefixes = append(prefixes, scanner.Text())
			}

			if len(prefixes) > 0 {
				return prefixes
			}
		}
	}

	return commonPrefixes
}
