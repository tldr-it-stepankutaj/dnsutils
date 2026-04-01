package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/olekukonko/tablewriter"
	"github.com/tldr-it-stepankutaj/dnsutils/internal/asn"
	"github.com/tldr-it-stepankutaj/dnsutils/internal/cloud"
	"github.com/tldr-it-stepankutaj/dnsutils/internal/dns"
	"github.com/tldr-it-stepankutaj/dnsutils/internal/httpinfo"
	"github.com/tldr-it-stepankutaj/dnsutils/internal/models"
	"github.com/tldr-it-stepankutaj/dnsutils/internal/output"
	"github.com/tldr-it-stepankutaj/dnsutils/internal/scanner"
	"github.com/tldr-it-stepankutaj/dnsutils/internal/security"
	"github.com/tldr-it-stepankutaj/dnsutils/internal/ssl"
	"github.com/tldr-it-stepankutaj/dnsutils/internal/subdomain"
	"github.com/tldr-it-stepankutaj/dnsutils/internal/tui"
	"github.com/tldr-it-stepankutaj/dnsutils/internal/whois"
	"github.com/tldr-it-stepankutaj/dnsutils/pkg/utils"
)

// Flags for command-line arguments
var (
	domain       string
	outputFile   string
	htmlFile     string
	wordlistFile string
	ports        portsFlag
	noCerts      bool
	noBruteforce bool
	noPassive    bool
	dnsServer    string
	concurrency  int
	timeout      int
	verbose      bool
	noSecurity   bool
	noCloud      bool
	noWhois      bool
	noZoneXfer   bool
	noDNSSEC     bool
	noTakeover   bool
	noHeaders    bool
	noReverse    bool
	noCacheSnoop bool
	noRecursive  bool
	useTUI       bool
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
	ports = []int{80, 443, 22, 21, 25, 8080, 8443, 53}

	// Parse flags
	flag.StringVar(&outputFile, "o", "", "Output file for results (JSON)")
	flag.StringVar(&htmlFile, "html", "", "Output file for HTML report")
	flag.StringVar(&wordlistFile, "w", "", "File with subdomain list for brute-force")
	flag.Var(&ports, "p", "Ports to scan (can be used multiple times, default: 80,443,22,21,25,8080,8443)")
	flag.BoolVar(&noCerts, "no-certs", false, "Skip subdomain discovery via certificates")
	flag.BoolVar(&noBruteforce, "no-bruteforce", false, "Skip brute-force subdomain discovery")
	flag.BoolVar(&noPassive, "no-passive", false, "Skip passive subdomain discovery")
	flag.StringVar(&dnsServer, "dns", "8.8.8.8:53", "DNS server to use for queries")
	flag.IntVar(&concurrency, "c", 40, "Concurrency level for scans")
	flag.IntVar(&timeout, "t", 1, "Timeout in seconds for network operations")
	flag.BoolVar(&verbose, "v", false, "Verbose output")
	flag.BoolVar(&noSecurity, "no-security", false, "Skip email security configuration analysis")
	flag.BoolVar(&noCloud, "no-cloud", false, "Skip cloud infrastructure detection")
	flag.BoolVar(&noWhois, "no-whois", false, "Skip WHOIS lookup")
	flag.BoolVar(&noZoneXfer, "no-axfr", false, "Skip DNS zone transfer test")
	flag.BoolVar(&noDNSSEC, "no-dnssec", false, "Skip DNSSEC validation")
	flag.BoolVar(&noTakeover, "no-takeover", false, "Skip subdomain takeover detection")
	flag.BoolVar(&noHeaders, "no-headers", false, "Skip HTTP security header analysis")
	flag.BoolVar(&noReverse, "no-reverse", false, "Skip reverse DNS lookups")
	flag.BoolVar(&noCacheSnoop, "no-cachesnoop", false, "Skip DNS cache snooping")
	flag.BoolVar(&noRecursive, "no-recursive", false, "Skip recursive subdomain discovery")
	flag.BoolVar(&useTUI, "tui", false, "Spustit v TUI režimu (terminálové rozhraní)")

	// Custom usage message
	flag.Usage = func() {
		_, err := fmt.Fprintf(os.Stderr, "Usage: %s [options] domain\n\n", os.Args[0])
		if err != nil {
			return
		}
		_, err = fmt.Fprintf(os.Stderr, "Options:\n")
		if err != nil {
			return
		}
		flag.PrintDefaults()
	}
}

func main() {
	// Parse command-line arguments
	flag.Parse()

	if useTUI {
		tui.RunTUI()
		return
	}

	// Get the domain from arguments
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(1)
	}
	domain = flag.Arg(0)

	// Validate the domain
	if !utils.ValidateDomain(domain) {
		_, err := fmt.Fprintf(os.Stderr, "Error: Invalid domain name: %s\n", domain)
		if err != nil {
			return
		}
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

	// ──────────────────────────────────────────────────
	// 1. Get IP addresses for the domain
	// ──────────────────────────────────────────────────
	console.PrintProgress("Getting IP addresses for the domain...")
	results.DomainIPs = dnsResolver.GetIPs(domain)
	if len(results.DomainIPs) > 0 {
		console.PrintSuccess(fmt.Sprintf("Found %d IP addresses for %s", len(results.DomainIPs), domain))
	} else {
		console.PrintWarning(fmt.Sprintf("Could not get IP addresses for %s", domain))
	}

	// ──────────────────────────────────────────────────
	// 2. Get DNS records
	// ──────────────────────────────────────────────────
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

	// ──────────────────────────────────────────────────
	// 3. WHOIS Lookup
	// ──────────────────────────────────────────────────
	if !noWhois {
		console.PrintProgress("Performing WHOIS lookup...")
		whoisLookup := whois.NewLookup()
		whoisInfo, err := whoisLookup.GetWhoisInfo(domain)
		if err == nil && whoisInfo != nil {
			results.WhoisInfo = whoisInfo
			console.PrintSuccess(fmt.Sprintf("WHOIS: Registrar=%s, Expires=%s", whoisInfo.Registrar, whoisInfo.ExpiryDate))
		} else if err != nil {
			console.PrintWarning(fmt.Sprintf("WHOIS lookup failed: %s", err))
		}
	}

	// ──────────────────────────────────────────────────
	// 4. Zone Transfer (AXFR) Test
	// ──────────────────────────────────────────────────
	if !noZoneXfer {
		console.PrintProgress("Testing DNS zone transfer (AXFR)...")
		ztResults := dnsResolver.TestZoneTransfer(domain)
		if len(ztResults) > 0 {
			results.ZoneTransfer = ztResults
			vulnCount := 0
			for _, zt := range ztResults {
				if zt.Vulnerable {
					vulnCount++
				}
			}
			if vulnCount > 0 {
				console.PrintError(fmt.Sprintf("CRITICAL: %d nameserver(s) allow zone transfer!", vulnCount))
			} else {
				console.PrintSuccess("No nameservers allow zone transfer")
			}
		}
	}

	// ──────────────────────────────────────────────────
	// 5. DNSSEC Validation
	// ──────────────────────────────────────────────────
	if !noDNSSEC {
		console.PrintProgress("Checking DNSSEC configuration...")
		dnssecResult := dnsResolver.CheckDNSSEC(domain)
		if dnssecResult != nil {
			results.DNSSEC = dnssecResult
			if dnssecResult.Enabled {
				if dnssecResult.Valid {
					console.PrintSuccess("DNSSEC is enabled and valid")
				} else {
					console.PrintWarning("DNSSEC is enabled but has validation issues")
				}
			} else {
				console.PrintWarning("DNSSEC is not enabled")
			}
		}
	}

	// ──────────────────────────────────────────────────
	// 6. Email Security Analysis
	// ──────────────────────────────────────────────────
	var secResult *models.SecurityResult
	var secErr error
	if !noSecurity {
		console.PrintProgress("Analyzing email security configuration...")
		secAnalyzer := security.NewAnalyzer(dnsServer)
		secResult, secErr = secAnalyzer.AnalyzeDomain(domain)

		if secErr == nil && secResult != nil {
			results.SecurityAnalysis = secResult
			recCount := len(secResult.Recommendations)
			if recCount > 0 {
				console.PrintSuccess(fmt.Sprintf("Found %d mail security recommendations", recCount))
			} else {
				console.PrintSuccess("Mail security configuration appears optimal")
			}
		} else if secErr != nil {
			console.PrintWarning(fmt.Sprintf("Could not perform security analysis: %s", secErr))
		}
	}

	// ──────────────────────────────────────────────────
	// 7. Wildcard DNS Detection (before subdomain discovery)
	// ──────────────────────────────────────────────────
	console.PrintProgress("Checking for wildcard DNS...")
	wildcardDetector := subdomain.NewWildcardDetector()
	wildcardResult := wildcardDetector.DetectWildcard(domain)
	if wildcardResult.IsWildcard {
		console.PrintWarning(fmt.Sprintf("Wildcard DNS detected! IPs: %s — brute-force results will be filtered", strings.Join(wildcardResult.WildcardIP, ", ")))
	} else {
		console.PrintSuccess("No wildcard DNS detected")
	}

	// ──────────────────────────────────────────────────
	// 8. Subdomain Discovery: Certificates
	// ──────────────────────────────────────────────────
	if !noCerts {
		console.PrintProgress("Looking for subdomains via certificates...")
		certFinder := subdomain.NewCertFinder()
		certSubdomains := certFinder.FindSubdomainsFromCertificates(domain)

		if len(certSubdomains) > 0 {
			results.CertSubdomains = certSubdomains
			console.PrintSuccess(fmt.Sprintf("Found %d subdomains via certificates", len(certSubdomains)))

			validSubdomains := processSubdomains(certSubdomains, certFinder, results, console)
			console.PrintSuccess(fmt.Sprintf("Verified %d active subdomains from certificates", len(validSubdomains)))
		} else {
			console.PrintWarning("No subdomains found via certificates")
		}
	}

	// ──────────────────────────────────────────────────
	// 9. Subdomain Discovery: Passive Sources
	// ──────────────────────────────────────────────────
	if !noPassive {
		console.PrintProgress("Querying passive subdomain sources...")
		passiveFinder := subdomain.NewPassiveFinder()
		passiveSubs := passiveFinder.FindSubdomains(domain)

		if len(passiveSubs) > 0 {
			results.PassiveSubdomains = passiveSubs
			console.PrintSuccess(fmt.Sprintf("Found %d subdomains via passive sources", len(passiveSubs)))

			// Add to main subdomains (deduplicate)
			certFinder := subdomain.NewCertFinder()
			newCount := 0
			existingMap := make(map[string]bool)
			for _, s := range results.Subdomains {
				existingMap[s.Name] = true
			}
			for _, sub := range passiveSubs {
				if !existingMap[sub] {
					name, ip, err := certFinder.CheckSubdomain(sub)
					if err == nil {
						// Filter wildcard IPs
						if wildcardResult.IsWildcard && containsString(wildcardResult.WildcardIP, ip) {
							continue
						}
						results.Subdomains = append(results.Subdomains, models.SubdomainInfo{Name: name, IP: ip})
						existingMap[name] = true
						newCount++
					}
				}
			}
			if newCount > 0 {
				console.PrintSuccess(fmt.Sprintf("Verified %d new active subdomains from passive sources", newCount))
			}
		} else {
			console.PrintWarning("No subdomains found via passive sources")
		}
	}

	// ──────────────────────────────────────────────────
	// 10. Subdomain Discovery: Brute-force
	// ──────────────────────────────────────────────────
	if !noBruteforce {
		console.PrintProgress("Starting brute-force subdomain discovery...")
		bruteFinder := subdomain.NewBruteFinder()
		bruteFinder.MaxConcurrent = concurrency

		bruteResults := bruteFinder.BruteForceSubdomains(domain, wordlistFile)

		if len(bruteResults) > 0 {
			var bruteSubdomains []string
			existingMap := make(map[string]bool)
			for _, s := range results.Subdomains {
				existingMap[s.Name] = true
			}

			for _, result := range bruteResults {
				bruteSubdomains = append(bruteSubdomains, result.Name)

				// Filter wildcard IPs
				if wildcardResult.IsWildcard && containsString(wildcardResult.WildcardIP, result.IP) {
					continue
				}

				if !existingMap[result.Name] {
					results.Subdomains = append(results.Subdomains, models.SubdomainInfo{
						Name: result.Name,
						IP:   result.IP,
					})
					existingMap[result.Name] = true
				}
			}

			results.BruteSubdomains = bruteSubdomains
			console.PrintSuccess(fmt.Sprintf("Found %d subdomains via brute-force", len(bruteResults)))
		} else {
			console.PrintWarning("No subdomains found via brute-force")
		}
	}

	// ──────────────────────────────────────────────────
	// 11. Recursive Subdomain Discovery
	// ──────────────────────────────────────────────────
	if !noRecursive && len(results.Subdomains) > 0 {
		console.PrintProgress("Running recursive subdomain discovery...")
		certFinder := subdomain.NewCertFinder()
		existingMap := make(map[string]bool)
		for _, s := range results.Subdomains {
			existingMap[s.Name] = true
		}

		// For each found subdomain, try to discover sub-subdomains via CT
		var newSubs []models.SubdomainInfo
		for _, sub := range results.Subdomains {
			// Only recurse on subdomains that are one level deep
			parts := strings.Split(sub.Name, ".")
			domainParts := strings.Split(domain, ".")
			if len(parts) <= len(domainParts)+1 {
				deepSubs := certFinder.FindSubdomainsFromCertificates(sub.Name)
				for _, ds := range deepSubs {
					if !existingMap[ds] {
						name, ip, err := certFinder.CheckSubdomain(ds)
						if err == nil {
							if wildcardResult.IsWildcard && containsString(wildcardResult.WildcardIP, ip) {
								continue
							}
							newSubs = append(newSubs, models.SubdomainInfo{Name: name, IP: ip})
							existingMap[name] = true
						}
					}
				}
			}
		}

		if len(newSubs) > 0 {
			results.Subdomains = append(results.Subdomains, newSubs...)
			console.PrintSuccess(fmt.Sprintf("Found %d additional subdomains via recursive discovery", len(newSubs)))
		}
	}

	// ──────────────────────────────────────────────────
	// 12. Cloud Infrastructure Detection
	// ──────────────────────────────────────────────────
	if !noCloud {
		console.PrintProgress("Analyzing cloud infrastructure...")
		cloudDetector := cloud.NewDetector(dnsServer)
		cloudResult, err := cloudDetector.AnalyzeCloudInfrastructure(domain, results)
		if err != nil {
			console.PrintWarning(fmt.Sprintf("Could not perform cloud infrastructure analysis: %s", err))
		} else {
			if cloudResult.TotalProviders > 0 {
				console.PrintSuccess(fmt.Sprintf("Found %d cloud providers with %d services",
					cloudResult.TotalProviders, cloudResult.TotalServices))
				if cloudResult.TotalOrphaned > 0 {
					console.PrintWarning(fmt.Sprintf("Detected %d potential orphaned cloud resources",
						cloudResult.TotalOrphaned))
				}
			} else {
				console.PrintSuccess("No cloud infrastructure detected")
			}
			results.CloudAnalysis = cloudResult
		}
	}

	// ──────────────────────────────────────────────────
	// 13. Subdomain Takeover Detection
	// ──────────────────────────────────────────────────
	if !noTakeover && len(results.Subdomains) > 0 {
		console.PrintProgress("Checking for subdomain takeover vulnerabilities...")
		takeoverChecker := subdomain.NewTakeoverChecker()
		takeoverResults := takeoverChecker.CheckSubdomains(results.Subdomains, dnsServer)
		if len(takeoverResults) > 0 {
			results.TakeoverResults = takeoverResults
			vulnCount := 0
			for _, tr := range takeoverResults {
				if tr.Vulnerable {
					vulnCount++
				}
			}
			if vulnCount > 0 {
				console.PrintError(fmt.Sprintf("CRITICAL: %d subdomain(s) may be vulnerable to takeover!", vulnCount))
			} else {
				console.PrintSuccess(fmt.Sprintf("Checked %d subdomains, no takeover vulnerabilities found", len(takeoverResults)))
			}
		}
	}

	// ──────────────────────────────────────────────────
	// 14. Reverse DNS (PTR) Lookups
	// ──────────────────────────────────────────────────
	if !noReverse {
		// Collect all unique IPs
		ipSet := make(map[string]bool)
		for _, ip := range results.DomainIPs {
			ipSet[ip] = true
		}
		for _, sub := range results.Subdomains {
			if sub.IP != "" {
				ipSet[sub.IP] = true
			}
		}
		var allIPs []string
		for ip := range ipSet {
			allIPs = append(allIPs, ip)
		}

		if len(allIPs) > 0 {
			console.PrintProgress(fmt.Sprintf("Performing reverse DNS lookups for %d IPs...", len(allIPs)))
			reverseFinder := subdomain.NewReverseFinder()
			reverseFinder.MaxConcurrent = concurrency
			reverseResults := reverseFinder.ReverseLookup(allIPs)
			if len(reverseResults) > 0 {
				// Convert to models type
				for _, rr := range reverseResults {
					results.ReverseDNS = append(results.ReverseDNS, models.ReverseDNSResult{
						IP:        rr.IP,
						Hostnames: rr.Hostnames,
					})
				}
				totalHostnames := 0
				for _, rr := range reverseResults {
					totalHostnames += len(rr.Hostnames)
				}
				console.PrintSuccess(fmt.Sprintf("Found %d reverse DNS entries for %d IPs", totalHostnames, len(reverseResults)))
			}
		}
	}

	// ──────────────────────────────────────────────────
	// 15. Detailed subdomain analysis (ports, SSL, ASN)
	// ──────────────────────────────────────────────────
	if len(results.Subdomains) > 0 {
		console.PrintProgress("Gathering detailed information about subdomains...")

		portScanner := scanner.NewScanner()
		portScanner.Timeout = time.Duration(timeout) * time.Second
		portScanner.MaxConcurrent = concurrency

		sslCert := ssl.NewCertificate()
		asnLookup := asn.NewLookup()

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

				semaphore <- struct{}{}
				defer func() { <-semaphore }()

				details := models.SubdomainDetails{
					IP: sub.IP,
				}

				details.ASN = asnLookup.GetASNInfo(sub.IP)

				openPorts := portScanner.PortScan(sub.IP, ports)
				for _, port := range openPorts {
					serviceDetail := portScanner.GetServiceDetails(sub.IP, port)
					if serviceDetail != "" {
						details.OpenServices = append(details.OpenServices, serviceDetail)
					}
				}

				sslInfo := sslCert.GetSSLInfo(sub.Name, 443)
				if sslInfo != nil {
					details.SSLInfo = sslInfo
				}

				subdomainDetailsChan <- struct {
					name    string
					details models.SubdomainDetails
				}{sub.Name, details}

			}(sub)
		}

		go func() {
			detailsWg.Wait()
			close(subdomainDetailsChan)
		}()

		for result := range subdomainDetailsChan {
			results.SubdomainData[result.name] = result.details
		}

		console.PrintSuccess(fmt.Sprintf("Gathered detailed information for %d subdomains", len(results.SubdomainData)))
	}

	// ──────────────────────────────────────────────────
	// 16. HTTP Security Headers Analysis
	// ──────────────────────────────────────────────────
	if !noHeaders && len(results.Subdomains) > 0 {
		console.PrintProgress("Analyzing HTTP security headers...")
		headerAnalyzer := httpinfo.NewAnalyzer()
		headerResults := headerAnalyzer.AnalyzeSubdomains(results.Subdomains, concurrency)
		if len(headerResults) > 0 {
			results.HeaderAnalysis = headerResults
			totalFindings := 0
			for _, ha := range headerResults {
				totalFindings += len(ha.Findings)
			}
			console.PrintSuccess(fmt.Sprintf("Analyzed headers for %d hosts, found %d findings", len(headerResults), totalFindings))
		}
	}

	// ──────────────────────────────────────────────────
	// 17. DNS Cache Snooping
	// ──────────────────────────────────────────────────
	if !noCacheSnoop {
		// Get nameservers to snoop on
		snoopDomains := []string{"google.com", "facebook.com", "amazon.com", "microsoft.com", "github.com"}
		if nsRecords, ok := results.Records["NS"].([]interface{}); ok && len(nsRecords) > 0 {
			for _, nsRec := range nsRecords {
				if ns, ok := nsRec.(*models.NSRecord); ok {
					nsServer := strings.TrimSuffix(ns.NameServer, ".") + ":53"
					console.PrintProgress(fmt.Sprintf("DNS cache snooping on %s...", nsServer))
					snoopResults := dnsResolver.CacheSnoop(nsServer, snoopDomains)
					if len(snoopResults) > 0 {
						for _, sr := range snoopResults {
							results.CacheSnoop = append(results.CacheSnoop, sr)
						}
					}
					break // Only snoop on first NS
				}
			}
		}
		if len(results.CacheSnoop) > 0 {
			cachedCount := 0
			for _, cs := range results.CacheSnoop {
				if cs.Cached {
					cachedCount++
				}
			}
			if cachedCount > 0 {
				console.PrintSuccess(fmt.Sprintf("DNS cache snooping: %d/%d domains cached on nameserver", cachedCount, len(results.CacheSnoop)))
			}
		}
	}

	// ──────────────────────────────────────────────────
	// Print results
	// ──────────────────────────────────────────────────
	console.PrintResults(results)

	// Print WHOIS results
	if results.WhoisInfo != nil {
		printWhoisResults(results.WhoisInfo, domain)
	}

	// Print Zone Transfer results
	if len(results.ZoneTransfer) > 0 {
		printZoneTransferResults(results.ZoneTransfer, domain)
	}

	// Print DNSSEC results
	if results.DNSSEC != nil {
		printDNSSECResults(results.DNSSEC, domain)
	}

	// Print Takeover results
	if len(results.TakeoverResults) > 0 {
		printTakeoverResults(results.TakeoverResults, domain)
	}

	// Print HTTP Header results
	if len(results.HeaderAnalysis) > 0 {
		printHeaderResults(results.HeaderAnalysis, domain)
	}

	// Print Reverse DNS results
	if len(results.ReverseDNS) > 0 {
		printReverseDNSResults(results.ReverseDNS, domain)
	}

	// Print security results
	if !noSecurity && secErr == nil && secResult != nil {
		printSecurityResults(secResult, domain)
	}

	if !noCloud && results.CloudAnalysis != nil {
		console.PrintCloudResults(results.CloudAnalysis, domain)
	}

	// Print cache snoop results
	if len(results.CacheSnoop) > 0 {
		printCacheSnoopResults(results.CacheSnoop, domain)
	}

	// Save results to JSON
	if outputFile != "" {
		jsonOutput := output.NewJSON()
		err := jsonOutput.SaveResultsToJSON(results, outputFile)
		if err != nil {
			console.PrintError(fmt.Sprintf("Failed to save results to file: %s", err))
		} else {
			console.PrintSuccess(fmt.Sprintf("Results saved to JSON: %s", outputFile))
		}
	}

	// Save results to HTML
	if htmlFile != "" {
		htmlOutput := output.NewHTML()
		err := htmlOutput.SaveResultsToHTML(results, htmlFile)
		if err != nil {
			console.PrintError(fmt.Sprintf("Failed to save HTML report: %s", err))
		} else {
			console.PrintSuccess(fmt.Sprintf("HTML report saved to: %s", htmlFile))
		}
	}
}

// ─────────────────────────────────────────────────────
// Print functions for new modules
// ─────────────────────────────────────────────────────

func printWhoisResults(info *models.WhoisInfo, domain string) {
	fmt.Printf("\n%s%sWHOIS Information for %s:%s\n",
		output.ColorBold, output.ColorBlue, domain, output.ColorReset)

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Field", "Value"})
	table.SetBorder(true)
	table.SetAutoWrapText(false)
	table.SetColWidth(60)

	if info.Registrar != "" {
		table.Append([]string{"Registrar", info.Registrar})
	}
	if info.CreatedDate != "" {
		table.Append([]string{"Created", info.CreatedDate})
	}
	if info.ExpiryDate != "" {
		table.Append([]string{"Expires", info.ExpiryDate})
	}
	if info.UpdatedDate != "" {
		table.Append([]string{"Updated", info.UpdatedDate})
	}
	if info.Organization != "" {
		table.Append([]string{"Organization", info.Organization})
	}
	if info.Country != "" {
		table.Append([]string{"Country", info.Country})
	}
	if info.DNSSEC != "" {
		table.Append([]string{"DNSSEC", info.DNSSEC})
	}
	if len(info.NameServers) > 0 {
		table.Append([]string{"Name Servers", strings.Join(info.NameServers, ", ")})
	}

	table.Render()
}

func printZoneTransferResults(ztResults []models.ZoneTransferResult, domain string) {
	fmt.Printf("\n%s%sZone Transfer (AXFR) Results for %s:%s\n",
		output.ColorBold, output.ColorBlue, domain, output.ColorReset)

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Nameserver", "Vulnerable", "Records"})
	table.SetBorder(true)

	for _, zt := range ztResults {
		vuln := "No"
		if zt.Vulnerable {
			vuln = fmt.Sprintf("%sYES%s", output.ColorRed, output.ColorReset)
		}
		recordCount := fmt.Sprintf("%d", len(zt.Records))
		if zt.Error != "" {
			recordCount = zt.Error
		}
		table.Append([]string{zt.Nameserver, vuln, recordCount})
	}

	table.Render()
}

func printDNSSECResults(result *models.DNSSECResult, domain string) {
	fmt.Printf("\n%s%sDNSSEC Validation for %s:%s\n",
		output.ColorBold, output.ColorBlue, domain, output.ColorReset)

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Property", "Value"})
	table.SetBorder(true)

	enabled := "No"
	if result.Enabled {
		enabled = fmt.Sprintf("%sYes%s", output.ColorGreen, output.ColorReset)
	}
	table.Append([]string{"Enabled", enabled})

	if result.Enabled {
		valid := fmt.Sprintf("%sNo%s", output.ColorRed, output.ColorReset)
		if result.Valid {
			valid = fmt.Sprintf("%sYes%s", output.ColorGreen, output.ColorReset)
		}
		table.Append([]string{"Valid", valid})
		table.Append([]string{"Algorithm", result.Algorithm})
		table.Append([]string{"DNSKEY Records", fmt.Sprintf("%d", result.DNSKEYs)})
		table.Append([]string{"DS Records", fmt.Sprintf("%d", result.DSRecords)})
		if len(result.KeyTypes) > 0 {
			table.Append([]string{"Key Types", strings.Join(result.KeyTypes, ", ")})
		}
	}

	if len(result.Issues) > 0 {
		table.Append([]string{"Issues", strings.Join(result.Issues, "; ")})
	}

	table.Render()
}

func printTakeoverResults(takeoverResults []models.TakeoverResult, domain string) {
	fmt.Printf("\n%s%sSubdomain Takeover Analysis for %s:%s\n",
		output.ColorBold, output.ColorBlue, domain, output.ColorReset)

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Subdomain", "CNAME", "Service", "Vulnerable", "Risk"})
	table.SetBorder(true)
	table.SetAutoWrapText(false)

	for _, tr := range takeoverResults {
		vuln := "No"
		if tr.Vulnerable {
			vuln = fmt.Sprintf("%sYES%s", output.ColorRed, output.ColorReset)
		}
		riskColor := output.ColorGreen
		if tr.Risk == "High" {
			riskColor = output.ColorRed
		} else if tr.Risk == "Medium" {
			riskColor = output.ColorYellow
		}
		table.Append([]string{
			tr.Subdomain,
			tr.CNAME,
			tr.Service,
			vuln,
			fmt.Sprintf("%s%s%s", riskColor, tr.Risk, output.ColorReset),
		})
	}

	table.Render()
}

func printHeaderResults(headerResults map[string]*models.HeaderAnalysis, domain string) {
	fmt.Printf("\n%s%sHTTP Security Headers for %s:%s\n",
		output.ColorBold, output.ColorBlue, domain, output.ColorReset)

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Host", "Server", "Missing Headers", "Technologies"})
	table.SetBorder(true)
	table.SetAutoWrapText(false)
	table.SetColWidth(40)

	for host, ha := range headerResults {
		missing := strings.Join(ha.MissingHeaders, ", ")
		if len(missing) > 60 {
			missing = missing[:57] + "..."
		}
		techs := strings.Join(ha.Technologies, ", ")
		if len(techs) > 40 {
			techs = techs[:37] + "..."
		}
		table.Append([]string{host, ha.Server, missing, techs})
	}

	table.Render()
}

func printReverseDNSResults(reverseResults []models.ReverseDNSResult, domain string) {
	fmt.Printf("\n%s%sReverse DNS (PTR) Results for %s:%s\n",
		output.ColorBold, output.ColorBlue, domain, output.ColorReset)

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"IP Address", "Hostnames"})
	table.SetBorder(true)
	table.SetAutoWrapText(false)

	for _, rr := range reverseResults {
		table.Append([]string{rr.IP, strings.Join(rr.Hostnames, ", ")})
	}

	table.Render()
}

func printCacheSnoopResults(snoopResults []models.CacheSnoopResult, domain string) {
	fmt.Printf("\n%s%sDNS Cache Snooping for %s nameservers:%s\n",
		output.ColorBold, output.ColorBlue, domain, output.ColorReset)

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Server", "Domain", "Cached", "TTL"})
	table.SetBorder(true)

	for _, cs := range snoopResults {
		cached := "No"
		ttl := "-"
		if cs.Cached {
			cached = fmt.Sprintf("%sYes%s", output.ColorGreen, output.ColorReset)
			ttl = fmt.Sprintf("%d", cs.TTL)
		}
		table.Append([]string{cs.Server, cs.Domain, cached, ttl})
	}

	table.Render()
}

func printSecurityResults(result *models.SecurityResult, domain string) {
	securityRating := "Poor"
	if result.SecurityScore >= 70 {
		securityRating = "Excellent"
	} else if result.SecurityScore >= 50 {
		securityRating = "Good"
	} else if result.SecurityScore >= 30 {
		securityRating = "Fair"
	}

	fmt.Printf("\n%s%sEmail Security Analysis for %s:%s\n",
		output.ColorBold, output.ColorBlue, domain, output.ColorReset)

	summaryTable := tablewriter.NewWriter(os.Stdout)
	summaryTable.SetHeader([]string{"Security Rating", "Score"})
	summaryTable.Append([]string{securityRating, fmt.Sprintf("%d/100", result.SecurityScore)})
	summaryTable.SetBorder(true)
	summaryTable.Render()

	// SPF Record Table
	fmt.Printf("\n%s%sSPF Record:%s\n", output.ColorBold, output.ColorBlue, output.ColorReset)
	spfTable := tablewriter.NewWriter(os.Stdout)
	spfTable.SetHeader([]string{"Status", "Policy", "Record"})

	if result.SPFRecord != nil {
		status := "Invalid"
		if result.SPFRecord.Valid {
			status = "Valid"
		}
		spfTable.Append([]string{status, result.SPFRecord.Policy, result.SPFRecord.Record})
	} else {
		spfTable.Append([]string{"Not Found", "-", "-"})
	}
	spfTable.SetBorder(true)
	spfTable.Render()

	// DMARC Record Table
	fmt.Printf("\n%s%sDMARC Record:%s\n", output.ColorBold, output.ColorBlue, output.ColorReset)
	dmarcTable := tablewriter.NewWriter(os.Stdout)
	dmarcTable.SetHeader([]string{"Status", "Policy", "Percentage", "Record"})

	if result.DMARCRecord != nil {
		status := "Invalid"
		if result.DMARCRecord.Valid {
			status = "Valid"
		}
		dmarcTable.Append([]string{
			status,
			result.DMARCRecord.Policy,
			fmt.Sprintf("%d%%", result.DMARCRecord.Percentage),
			result.DMARCRecord.Record,
		})
	} else {
		dmarcTable.Append([]string{"Not Found", "-", "-", "-"})
	}
	dmarcTable.SetBorder(true)
	dmarcTable.Render()

	// DKIM Records Table
	fmt.Printf("\n%s%sDKIM Records:%s\n", output.ColorBold, output.ColorBlue, output.ColorReset)
	dkimTable := tablewriter.NewWriter(os.Stdout)
	dkimTable.SetHeader([]string{"Status", "Selectors"})

	if result.DKIMRecords != nil && len(result.DKIMRecords) > 0 {
		validCount := 0
		var selectors []string
		for _, dkim := range result.DKIMRecords {
			if dkim.Valid {
				validCount++
				selectors = append(selectors, dkim.Selector)
			}
		}
		if validCount > 0 {
			dkimTable.Append([]string{
				fmt.Sprintf("%d Valid", validCount),
				strings.Join(selectors, ", "),
			})
		} else {
			dkimTable.Append([]string{"Invalid", ""})
		}
	} else {
		dkimTable.Append([]string{"Not Found", "-"})
	}
	dkimTable.SetBorder(true)
	dkimTable.Render()

	// MX Security Table
	fmt.Printf("\n%s%sMX Security:%s\n", output.ColorBold, output.ColorBlue, output.ColorReset)
	mxTable := tablewriter.NewWriter(os.Stdout)
	mxTable.SetHeader([]string{"Security Status", "Backup MX", "Servers"})

	if result.MXAnalysis != nil && len(result.MXAnalysis.Servers) > 0 {
		securityStatus := "Partial/Unknown"
		if result.MXAnalysis.AllSecure {
			securityStatus = "Secure"
		}
		backupStatus := "No"
		if result.MXAnalysis.HasBackup {
			backupStatus = "Yes"
		}
		mxTable.Append([]string{
			securityStatus,
			backupStatus,
			strings.Join(result.MXAnalysis.Servers, ", "),
		})
	} else {
		mxTable.Append([]string{"Not Available", "-", "-"})
	}
	mxTable.SetBorder(true)
	mxTable.Render()

	// CAA Records Table
	fmt.Printf("\n%s%sCAA Records:%s\n", output.ColorBold, output.ColorBlue, output.ColorReset)
	caaTable := tablewriter.NewWriter(os.Stdout)
	caaTable.SetHeader([]string{"Status", "Issuers"})

	if result.CAAAnalysis != nil && len(result.CAAAnalysis.IssueCAs) > 0 {
		caaTable.Append([]string{
			"Configured",
			strings.Join(result.CAAAnalysis.IssueCAs, ", "),
		})
	} else {
		caaTable.Append([]string{"Not Found", "-"})
	}
	caaTable.SetBorder(true)
	caaTable.Render()

	// Recommendations
	if len(result.Recommendations) > 0 {
		fmt.Printf("\n%s%sRecommendations:%s\n", output.ColorBold, output.ColorBlue, output.ColorReset)

		recTable := tablewriter.NewWriter(os.Stdout)
		recTable.SetHeader([]string{"#", "Recommendation"})
		recTable.SetAutoWrapText(false)
		recTable.SetColWidth(80)

		maxToShow := 5
		numToShow := len(result.Recommendations)
		if numToShow > maxToShow {
			numToShow = maxToShow
		}

		for i, rec := range result.Recommendations[:numToShow] {
			recTable.Append([]string{fmt.Sprintf("%d", i+1), rec})
		}

		if len(result.Recommendations) > maxToShow {
			recTable.Append([]string{
				"...",
				fmt.Sprintf("And %d more recommendations", len(result.Recommendations)-maxToShow),
			})
		}

		recTable.SetBorder(true)
		recTable.Render()
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

	go func() {
		wg.Wait()
		close(resultChan)
	}()

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

// containsString checks if a string is in a slice
func containsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}
