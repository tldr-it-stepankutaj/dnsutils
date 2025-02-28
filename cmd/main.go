package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/tldr-it-stepankutaj/dnsutils/internal/asn"
	"github.com/tldr-it-stepankutaj/dnsutils/internal/dns"
	"github.com/tldr-it-stepankutaj/dnsutils/internal/models"
	"github.com/tldr-it-stepankutaj/dnsutils/internal/output"
	"github.com/tldr-it-stepankutaj/dnsutils/internal/scanner"
	"github.com/tldr-it-stepankutaj/dnsutils/internal/ssl"
	"github.com/tldr-it-stepankutaj/dnsutils/internal/subdomain"
	"github.com/tldr-it-stepankutaj/dnsutils/pkg/utils"
)

// Flags for command-line arguments
var (
	domain       string
	outputFile   string
	wordlistFile string
	ports        portsFlag
	noCerts      bool
	noBruteforce bool
	dnsServer    string
	concurrency  int
	timeout      int
	verbose      bool
)

// Custom type for parsing port lists
type portsFlag []int

func (p *portsFlag) String() string {
	return fmt.Sprintf("%v", *p)
}

func (p *portsFlag) Set(value string) error {
	var port int
	_, err := fmt.Sscanf(value, "%d", &port)
	if err != nil {
		return err
	}
	*p = append(*p, port)
	return nil
}

func init() {
	// Default ports to scan
	ports = []int{80, 443, 22, 21, 25, 8080, 8443}

	// Parse flags
	flag.StringVar(&outputFile, "o", "", "Output file for results (JSON)")
	flag.StringVar(&wordlistFile, "w", "", "File with subdomain list for brute-force")
	flag.Var(&ports, "p", "Ports to scan (can be used multiple times, default: 80,443,22,21,25,8080,8443)")
	flag.BoolVar(&noCerts, "no-certs", false, "Skip subdomain discovery via certificates")
	flag.BoolVar(&noBruteforce, "no-bruteforce", false, "Skip brute-force subdomain discovery")
	flag.StringVar(&dnsServer, "dns", "8.8.8.8:53", "DNS server to use for queries")
	flag.IntVar(&concurrency, "c", 40, "Concurrency level for scans")
	flag.IntVar(&timeout, "t", 1, "Timeout in seconds for network operations")
	flag.BoolVar(&verbose, "v", false, "Verbose output")

	// Custom usage message
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] domain\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
	}
}

func main() {
	// Parse command-line arguments
	flag.Parse()

	// Get the domain from arguments
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(1)
	}
	domain = flag.Arg(0)

	// Validate the domain
	if !utils.ValidateDomain(domain) {
		fmt.Fprintf(os.Stderr, "Error: Invalid domain name: %s\n", domain)
		os.Exit(1)
	}

	// Create console output formatter
	console := output.NewConsole()
	console.PrintBanner()

	// Print scan parameters
	if verbose {
		console.PrintProgress(fmt.Sprintf("Domain: %s", domain))
		console.PrintProgress(fmt.Sprintf("Ports to scan: %v", ports))
		if wordlistFile != "" {
			console.PrintProgress(fmt.Sprintf("Wordlist file: %s", wordlistFile))
		}
	}

	// Set up graceful shutdown
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-signalChan
		console.PrintWarning("Scan interrupted by user. Exiting...")
		os.Exit(1)
	}()

	// Initialize results structure
	results := &models.Results{
		Domain:        domain,
		Records:       make(map[string]interface{}),
		SubdomainData: make(map[string]models.SubdomainDetails),
	}

	// Create DNS resolver and set DNS server
	dnsResolver := dns.NewResolver()
	dnsResolver.SetServer(dnsServer)

	// Start the scan
	console.PrintProgress("Starting DNS reconnaissance...")

	// 1. Get IP addresses for the domain
	console.PrintProgress("Getting IP addresses for the domain...")
	results.DomainIPs = dnsResolver.GetIPs(domain)
	if len(results.DomainIPs) > 0 {
		console.PrintSuccess(fmt.Sprintf("Found %d IP addresses for %s", len(results.DomainIPs), domain))
	} else {
		console.PrintWarning(fmt.Sprintf("Could not get IP addresses for %s", domain))
	}

	// 2. Get DNS records
	recordTypes := []string{"A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"}
	var wg sync.WaitGroup
	var mutex sync.Mutex

	for _, recordType := range recordTypes {
		wg.Add(1)
		go func(rt string) {
			defer wg.Done()

			console.PrintProgress(fmt.Sprintf("Looking for %s records...", rt))
			records, err := dnsResolver.GetDNSRecords(domain, rt)
			if err == nil && len(records) > 0 {
				mutex.Lock()
				results.Records[rt] = records
				mutex.Unlock()
				console.PrintSuccess(fmt.Sprintf("Found %d %s records", len(records), rt))
			}
		}(recordType)
	}

	wg.Wait()

	// 3. Find subdomains from certificates
	if !noCerts {
		console.PrintProgress("Looking for subdomains via certificates...")
		certFinder := subdomain.NewCertFinder()
		certSubdomains := certFinder.FindSubdomainsFromCertificates(domain)

		if len(certSubdomains) > 0 {
			results.CertSubdomains = certSubdomains
			console.PrintSuccess(fmt.Sprintf("Found %d subdomains via certificates", len(certSubdomains)))

			// Get IP addresses for these subdomains
			validSubdomains := processSubdomains(certSubdomains, certFinder, results, console)
			console.PrintSuccess(fmt.Sprintf("Verified %d active subdomains from certificates", len(validSubdomains)))
		} else {
			console.PrintWarning("No subdomains found via certificates")
		}
	}

	// 4. Brute-force subdomains
	if !noBruteforce {
		console.PrintProgress("Starting brute-force subdomain discovery...")
		bruteFinder := subdomain.NewBruteFinder()
		bruteFinder.MaxConcurrent = concurrency

		bruteResults := bruteFinder.BruteForceSubdomains(domain, wordlistFile)

		if len(bruteResults) > 0 {
			// Extract subdomain names for the results
			var bruteSubdomains []string
			for _, result := range bruteResults {
				bruteSubdomains = append(bruteSubdomains, result.Name)

				// Add to main results
				results.Subdomains = append(results.Subdomains, models.SubdomainInfo{
					Name: result.Name,
					IP:   result.IP,
				})
			}

			results.BruteSubdomains = bruteSubdomains
			console.PrintSuccess(fmt.Sprintf("Found %d subdomains via brute-force", len(bruteResults)))
		} else {
			console.PrintWarning("No subdomains found via brute-force")
		}
	}

	// 5. Gather detailed information for each subdomain
	if len(results.Subdomains) > 0 {
		console.PrintProgress("Gathering detailed information about subdomains...")

		// Initialize components
		portScanner := scanner.NewScanner()
		portScanner.Timeout = time.Duration(timeout) * time.Second
		portScanner.MaxConcurrent = concurrency

		sslCert := ssl.NewCertificate()
		asnLookup := asn.NewLookup()

		// Process each subdomain
		subdomainDetailsChan := make(chan struct {
			name    string
			details models.SubdomainDetails
		})

		var detailsWg sync.WaitGroup
		semaphore := make(chan struct{}, concurrency)

		for _, sub := range results.Subdomains {
			detailsWg.Add(1)
			go func(sub models.SubdomainInfo) {
				defer detailsWg.Done()

				// Acquire semaphore
				semaphore <- struct{}{}
				defer func() { <-semaphore }()

				details := models.SubdomainDetails{
					IP: sub.IP,
				}

				// Get ASN information
				details.ASN = asnLookup.GetASNInfo(sub.IP)

				// Scan ports
				openPorts := portScanner.PortScan(sub.IP, ports)

				// Get service details for open ports
				for _, port := range openPorts {
					serviceDetail := portScanner.GetServiceDetails(sub.IP, port)
					if serviceDetail != "" {
						details.OpenServices = append(details.OpenServices, serviceDetail)
					}
				}

				// Get SSL information (443 is standard HTTPS port)
				sslInfo := sslCert.GetSSLInfo(sub.Name, 443)
				if sslInfo != nil {
					details.SSLInfo = sslInfo
				}

				// Send results to channel
				subdomainDetailsChan <- struct {
					name    string
					details models.SubdomainDetails
				}{sub.Name, details}

			}(sub)
		}

		// Collect results in a separate goroutine
		go func() {
			detailsWg.Wait()
			close(subdomainDetailsChan)
		}()

		// Process the results
		for result := range subdomainDetailsChan {
			results.SubdomainData[result.name] = result.details
		}

		console.PrintSuccess(fmt.Sprintf("Gathered detailed information for %d subdomains", len(results.SubdomainData)))
	}

	// Print results
	console.PrintResults(results)

	// Save results to file if requested
	if outputFile != "" {
		jsonOutput := output.NewJSON()
		err := jsonOutput.SaveResultsToJSON(results, outputFile)
		if err != nil {
			console.PrintError(fmt.Sprintf("Failed to save results to file: %s", err))
		} else {
			console.PrintSuccess(fmt.Sprintf("Results saved to file: %s", outputFile))
		}
	}
}

// processSubdomains checks which subdomains are valid and adds them to results
func processSubdomains(subdomains []string, certFinder *subdomain.CertFinder, results *models.Results, _ *output.Console) []string {
	var validSubdomains []string
	var wg sync.WaitGroup
	var mutex sync.Mutex
	semaphore := make(chan struct{}, concurrency)

	resultChan := make(chan *models.SubdomainInfo)

	for _, sub := range subdomains {
		wg.Add(1)
		go func(subdomain string) {
			defer wg.Done()

			// Acquire semaphore
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			name, ip, err := certFinder.CheckSubdomain(subdomain)
			if err == nil {
				resultChan <- &models.SubdomainInfo{
					Name: name,
					IP:   ip,
				}
			} else {
				resultChan <- nil
			}
		}(sub)
	}

	// Collect results in a separate goroutine
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Process results
	for result := range resultChan {
		if result != nil {
			mutex.Lock()
			results.Subdomains = append(results.Subdomains, *result)
			validSubdomains = append(validSubdomains, result.Name)
			mutex.Unlock()
		}
	}

	return validSubdomains
}
