package cloud

import (
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/tldr-it-stepankutaj/dnsutils/internal/dns"
	"github.com/tldr-it-stepankutaj/dnsutils/internal/models"
)

// Detector handles cloud infrastructure detection
type Detector struct {
	resolver *dns.Resolver
}

// NewDetector creates a new cloud infrastructure detector
func NewDetector(dnsServer string) *Detector {
	resolver := dns.NewResolver()
	resolver.SetServer(dnsServer)

	return &Detector{
		resolver: resolver,
	}
}

// AnalyzeCloudInfrastructure analyzes a domain's cloud infrastructure
func (d *Detector) AnalyzeCloudInfrastructure(domain string, results *models.Results) (*models.CloudAnalysisResult, error) {
	// Initialize the result
	analysisResult := &models.CloudAnalysisResult{
		Providers: make(map[string]*models.CloudProviderInfo),
		RiskLevel: "Low",
	}

	// Collect all subdomains and IPs
	var allSubdomains []string
	var allIPs []string

	// Add the main domain
	allSubdomains = append(allSubdomains, domain)
	allIPs = append(allIPs, results.DomainIPs...)

	// Add subdomains
	for _, sub := range results.Subdomains {
		allSubdomains = append(allSubdomains, sub.Name)
		if sub.IP != "" {
			allIPs = append(allIPs, sub.IP)
		}
	}

	// Generate a unique list of IPs
	uniqueIPs := make(map[string]bool)
	var uniqueIPsList []string
	for _, ip := range allIPs {
		if !uniqueIPs[ip] {
			uniqueIPs[ip] = true
			uniqueIPsList = append(uniqueIPsList, ip)
		}
	}

	// Check for cloud providers based on IP ranges
	d.detectProvidersFromIPs(uniqueIPsList, analysisResult)

	// Check for cloud providers based on DNS patterns
	d.detectProvidersFromDNS(allSubdomains, results, analysisResult)

	// Check for orphaned resources
	d.detectOrphanedResources(allSubdomains, results, analysisResult)

	// Generate recommendations based on findings
	d.generateRecommendations(analysisResult)

	// Calculate totals
	d.calculateTotals(analysisResult)

	// Calculate risk level
	d.calculateRiskLevel(analysisResult)

	return analysisResult, nil
}

// detectProvidersFromIPs detects cloud providers based on IP ranges
func (d *Detector) detectProvidersFromIPs(ips []string, result *models.CloudAnalysisResult) {
	// Process each IP in parallel
	var wg sync.WaitGroup
	var mutex sync.Mutex

	for _, ip := range ips {
		wg.Add(1)
		go func(ipAddr string) {
			defer wg.Done()

			// Skip private IPs
			if isPrivateIP(ipAddr) {
				return
			}

			// Check if IP is in AWS ranges
			if isAWSIP(ipAddr) {
				mutex.Lock()
				if result.Providers["AWS"] == nil {
					result.Providers["AWS"] = &models.CloudProviderInfo{
						Provider:     "AWS",
						IPs:          []string{ipAddr},
						Confidence:   "Medium",
						Verification: "IP range",
					}
				} else {
					result.Providers["AWS"].IPs = append(result.Providers["AWS"].IPs, ipAddr)
				}
				mutex.Unlock()
				return
			}

			// Check if IP is in Azure ranges
			if isAzureIP(ipAddr) {
				mutex.Lock()
				if result.Providers["Azure"] == nil {
					result.Providers["Azure"] = &models.CloudProviderInfo{
						Provider:     "Azure",
						IPs:          []string{ipAddr},
						Confidence:   "Medium",
						Verification: "IP range",
					}
				} else {
					result.Providers["Azure"].IPs = append(result.Providers["Azure"].IPs, ipAddr)
				}
				mutex.Unlock()
				return
			}

			// Check if IP is in GCP ranges
			if isGCPIP(ipAddr) {
				mutex.Lock()
				if result.Providers["GCP"] == nil {
					result.Providers["GCP"] = &models.CloudProviderInfo{
						Provider:     "GCP",
						IPs:          []string{ipAddr},
						Confidence:   "Medium",
						Verification: "IP range",
					}
				} else {
					result.Providers["GCP"].IPs = append(result.Providers["GCP"].IPs, ipAddr)
				}
				mutex.Unlock()
				return
			}

			// Check for Digital Ocean
			if isDigitalOceanIP(ipAddr) {
				mutex.Lock()
				if result.Providers["DigitalOcean"] == nil {
					result.Providers["DigitalOcean"] = &models.CloudProviderInfo{
						Provider:     "DigitalOcean",
						IPs:          []string{ipAddr},
						Confidence:   "Medium",
						Verification: "IP range",
					}
				} else {
					result.Providers["DigitalOcean"].IPs = append(result.Providers["DigitalOcean"].IPs, ipAddr)
				}
				mutex.Unlock()
				return
			}

			// Additional providers can be added here

		}(ip)
	}

	wg.Wait()
}

// detectProvidersFromDNS detects cloud providers based on DNS patterns
func (d *Detector) detectProvidersFromDNS(subdomains []string, results *models.Results, result *models.CloudAnalysisResult) {
	// Check all domain and subdomains for cloud-specific patterns
	for _, subdomain := range subdomains {
		// Check for AWS patterns
		if strings.Contains(subdomain, "amazonaws.com") ||
			strings.Contains(subdomain, "cloudfront.net") ||
			strings.Contains(subdomain, "elasticbeanstalk.com") {
			service := detectAWSService(subdomain)

			if result.Providers["AWS"] == nil {
				result.Providers["AWS"] = &models.CloudProviderInfo{
					Provider:     "AWS",
					Services:     []string{service},
					Subdomains:   []string{subdomain},
					Confidence:   "High",
					Verification: "DNS pattern",
				}
			} else {
				if !containsString(result.Providers["AWS"].Services, service) {
					result.Providers["AWS"].Services = append(result.Providers["AWS"].Services, service)
				}
				if !containsString(result.Providers["AWS"].Subdomains, subdomain) {
					result.Providers["AWS"].Subdomains = append(result.Providers["AWS"].Subdomains, subdomain)
				}
				// Upgrade confidence level if previously detected only by IP
				if result.Providers["AWS"].Confidence == "Medium" && result.Providers["AWS"].Verification == "IP range" {
					result.Providers["AWS"].Confidence = "High"
					result.Providers["AWS"].Verification = "IP range and DNS pattern"
				}
			}
		}

		// Check for Azure patterns
		if strings.Contains(subdomain, "azurewebsites.net") ||
			strings.Contains(subdomain, "cloudapp.net") ||
			strings.Contains(subdomain, "blob.core.windows.net") ||
			strings.Contains(subdomain, "azure-api.net") {
			service := detectAzureService(subdomain)

			if result.Providers["Azure"] == nil {
				result.Providers["Azure"] = &models.CloudProviderInfo{
					Provider:     "Azure",
					Services:     []string{service},
					Subdomains:   []string{subdomain},
					Confidence:   "High",
					Verification: "DNS pattern",
				}
			} else {
				if !containsString(result.Providers["Azure"].Services, service) {
					result.Providers["Azure"].Services = append(result.Providers["Azure"].Services, service)
				}
				if !containsString(result.Providers["Azure"].Subdomains, subdomain) {
					result.Providers["Azure"].Subdomains = append(result.Providers["Azure"].Subdomains, subdomain)
				}
				// Upgrade confidence level if previously detected only by IP
				if result.Providers["Azure"].Confidence == "Medium" && result.Providers["Azure"].Verification == "IP range" {
					result.Providers["Azure"].Confidence = "High"
					result.Providers["Azure"].Verification = "IP range and DNS pattern"
				}
			}
		}

		// Check for GCP patterns
		if strings.Contains(subdomain, "appspot.com") ||
			strings.Contains(subdomain, "googleapis.com") ||
			strings.Contains(subdomain, "cloudfunctions.net") ||
			strings.Contains(subdomain, "run.app") {
			service := detectGCPService(subdomain)

			if result.Providers["GCP"] == nil {
				result.Providers["GCP"] = &models.CloudProviderInfo{
					Provider:     "GCP",
					Services:     []string{service},
					Subdomains:   []string{subdomain},
					Confidence:   "High",
					Verification: "DNS pattern",
				}
			} else {
				if !containsString(result.Providers["GCP"].Services, service) {
					result.Providers["GCP"].Services = append(result.Providers["GCP"].Services, service)
				}
				if !containsString(result.Providers["GCP"].Subdomains, subdomain) {
					result.Providers["GCP"].Subdomains = append(result.Providers["GCP"].Subdomains, subdomain)
				}
				// Upgrade confidence level if previously detected only by IP
				if result.Providers["GCP"].Confidence == "Medium" && result.Providers["GCP"].Verification == "IP range" {
					result.Providers["GCP"].Confidence = "High"
					result.Providers["GCP"].Verification = "IP range and DNS pattern"
				}
			}
		}

		// Add more providers as needed
	}

	// Also check CNAME records for each subdomain
	d.detectFromCNAMEs(results, result)

	// Also check TXT/SPF records for cloud provider signatures
	d.detectFromTXTRecords(results, result)
}

// detectFromCNAMEs looks for cloud provider signatures in CNAME records
func (d *Detector) detectFromCNAMEs(results *models.Results, result *models.CloudAnalysisResult) {
	// Check CNAME records
	if cnameRecords, ok := results.Records["CNAME"].([]interface{}); ok {
		for _, record := range cnameRecords {
			if cname, ok := record.(*models.CNAMERecord); ok {
				target := cname.Target

				// Check for AWS
				if strings.Contains(target, "amazonaws.com") ||
					strings.Contains(target, "cloudfront.net") ||
					strings.Contains(target, "elasticbeanstalk.com") {
					service := detectAWSService(target)

					if result.Providers["AWS"] == nil {
						result.Providers["AWS"] = &models.CloudProviderInfo{
							Provider:     "AWS",
							Services:     []string{service},
							Confidence:   "High",
							Verification: "CNAME record",
						}
					} else {
						if !containsString(result.Providers["AWS"].Services, service) {
							result.Providers["AWS"].Services = append(result.Providers["AWS"].Services, service)
						}
						result.Providers["AWS"].Confidence = "High"
					}
				}

				// Check for Azure
				if strings.Contains(target, "azurewebsites.net") ||
					strings.Contains(target, "cloudapp.net") ||
					strings.Contains(target, "blob.core.windows.net") {
					service := detectAzureService(target)

					if result.Providers["Azure"] == nil {
						result.Providers["Azure"] = &models.CloudProviderInfo{
							Provider:     "Azure",
							Services:     []string{service},
							Confidence:   "High",
							Verification: "CNAME record",
						}
					} else {
						if !containsString(result.Providers["Azure"].Services, service) {
							result.Providers["Azure"].Services = append(result.Providers["Azure"].Services, service)
						}
						result.Providers["Azure"].Confidence = "High"
					}
				}

				// Check for GCP
				if strings.Contains(target, "appspot.com") ||
					strings.Contains(target, "googleapis.com") ||
					strings.Contains(target, "cloudfunctions.net") {
					service := detectGCPService(target)

					if result.Providers["GCP"] == nil {
						result.Providers["GCP"] = &models.CloudProviderInfo{
							Provider:     "GCP",
							Services:     []string{service},
							Confidence:   "High",
							Verification: "CNAME record",
						}
					} else {
						if !containsString(result.Providers["GCP"].Services, service) {
							result.Providers["GCP"].Services = append(result.Providers["GCP"].Services, service)
						}
						result.Providers["GCP"].Confidence = "High"
					}
				}

				// Add more providers as needed
			}
		}
	}
}

// detectFromTXTRecords looks for cloud provider signatures in TXT/SPF records
func (d *Detector) detectFromTXTRecords(results *models.Results, result *models.CloudAnalysisResult) {
	// Check TXT records for SPF includes that reference cloud providers
	if txtRecords, ok := results.Records["TXT"].([]interface{}); ok {
		for _, record := range txtRecords {
			if txt, ok := record.(*models.TXTRecord); ok {
				// Look for SPF records
				if strings.HasPrefix(txt.Text, "v=spf1") {
					// Check for AWS SES
					if strings.Contains(txt.Text, "include:amazonses.com") {
						if result.Providers["AWS"] == nil {
							result.Providers["AWS"] = &models.CloudProviderInfo{
								Provider:     "AWS",
								Services:     []string{"SES (Simple Email Service)"},
								Confidence:   "High",
								Verification: "SPF record",
							}
						} else {
							if !containsString(result.Providers["AWS"].Services, "SES (Simple Email Service)") {
								result.Providers["AWS"].Services = append(result.Providers["AWS"].Services, "SES (Simple Email Service)")
							}
						}
					}

					// Check for Office 365/Azure
					if strings.Contains(txt.Text, "include:spf.protection.outlook.com") {
						if result.Providers["Microsoft"] == nil {
							result.Providers["Microsoft"] = &models.CloudProviderInfo{
								Provider:     "Microsoft",
								Services:     []string{"Office 365 Email"},
								Confidence:   "High",
								Verification: "SPF record",
							}
						} else {
							if !containsString(result.Providers["Microsoft"].Services, "Office 365 Email") {
								result.Providers["Microsoft"].Services = append(result.Providers["Microsoft"].Services, "Office 365 Email")
							}
						}
					}

					// Check for Google Workspace/GCP
					if strings.Contains(txt.Text, "include:_spf.google.com") {
						if result.Providers["Google"] == nil {
							result.Providers["Google"] = &models.CloudProviderInfo{
								Provider:     "Google",
								Services:     []string{"Google Workspace Email"},
								Confidence:   "High",
								Verification: "SPF record",
							}
						} else {
							if !containsString(result.Providers["Google"].Services, "Google Workspace Email") {
								result.Providers["Google"].Services = append(result.Providers["Google"].Services, "Google Workspace Email")
							}
						}
					}

					// Add more providers as needed
				}

				// Check for domain verification TXT records
				if strings.Contains(txt.Text, "MS=ms") {
					// Microsoft domain verification
					if result.Providers["Microsoft"] == nil {
						result.Providers["Microsoft"] = &models.CloudProviderInfo{
							Provider:     "Microsoft",
							Services:     []string{"Domain Verification"},
							Confidence:   "Medium",
							Verification: "TXT record",
						}
					}
				}

				if strings.Contains(txt.Text, "google-site-verification") {
					// Google domain verification
					if result.Providers["Google"] == nil {
						result.Providers["Google"] = &models.CloudProviderInfo{
							Provider:     "Google",
							Services:     []string{"Domain Verification"},
							Confidence:   "Medium",
							Verification: "TXT record",
						}
					}
				}

				if strings.Contains(txt.Text, "aws-verification") {
					// AWS domain verification
					if result.Providers["AWS"] == nil {
						result.Providers["AWS"] = &models.CloudProviderInfo{
							Provider:     "AWS",
							Services:     []string{"Domain Verification"},
							Confidence:   "Medium",
							Verification: "TXT record",
						}
					}
				}
			}
		}
	}
}

// detectOrphanedResources looks for potential orphaned cloud resources
func (d *Detector) detectOrphanedResources(subdomains []string, results *models.Results, result *models.CloudAnalysisResult) {
	// Look for dangling CNAMEs (pointing to inactive cloud resources)
	if cnameRecords, ok := results.Records["CNAME"].([]interface{}); ok {
		for _, record := range cnameRecords {
			if cname, ok := record.(*models.CNAMERecord); ok {
				target := cname.Target

				// Check for common cloud patterns
				if strings.Contains(target, "s3-website") ||
					strings.Contains(target, "cloudfront.net") ||
					strings.Contains(target, "azurewebsites.net") ||
					strings.Contains(target, "blob.core.windows.net") ||
					strings.Contains(target, "appspot.com") ||
					strings.Contains(target, "googleapis.com") {

					// Try to resolve the target to see if it exists
					ips, err := net.LookupHost(target)
					if err != nil || len(ips) == 0 {
						// This might be an orphaned resource
						provider := detectProviderFromTarget(target)
						orphanedResource := fmt.Sprintf("Dangling CNAME: %s -> %s", cname, target)

						if result.Providers[provider] != nil {
							result.Providers[provider].Orphaned = append(result.Providers[provider].Orphaned, orphanedResource)
						}
					}
				}
			}
		}
	}

	// Check for orphaned subdomains (with cloud patterns but no resolution)
	for _, subdomain := range subdomains {
		if isCloudSubdomain(subdomain) {
			// Try to resolve
			_, err := net.LookupHost(subdomain)
			if err != nil {
				// Might be orphaned
				provider := detectProviderFromSubdomain(subdomain)
				orphanedResource := fmt.Sprintf("Orphaned subdomain: %s", subdomain)

				if result.Providers[provider] != nil {
					result.Providers[provider].Orphaned = append(result.Providers[provider].Orphaned, orphanedResource)
				}
			}
		}
	}
}

// generateRecommendations creates recommendations based on findings
func (d *Detector) generateRecommendations(result *models.CloudAnalysisResult) {
	// General cloud security recommendations
	if len(result.Providers) > 0 {
		result.Recommendations = append(result.Recommendations,
			"Consider implementing a cloud asset inventory system to track all cloud resources")
	}

	// Provider-specific recommendations
	for provider, info := range result.Providers {
		// Orphaned resources recommendations
		if len(info.Orphaned) > 0 {
			result.Recommendations = append(result.Recommendations,
				fmt.Sprintf("Clean up orphaned %s resources to reduce attack surface and costs", provider))
		}

		// AWS-specific recommendations
		if provider == "AWS" {
			if containsString(info.Services, "S3") {
				result.Recommendations = append(result.Recommendations,
					"Ensure AWS S3 buckets have proper access controls and are not publicly accessible")
			}
			if containsString(info.Services, "CloudFront") {
				result.Recommendations = append(result.Recommendations,
					"Configure AWS CloudFront distributions with secure settings and HTTPS")
			}
		}

		// Azure-specific recommendations
		if provider == "Azure" {
			if containsString(info.Services, "App Service") {
				result.Recommendations = append(result.Recommendations,
					"Ensure Azure App Services are configured with HTTPS only and latest TLS")
			}
			if containsString(info.Services, "Blob Storage") {
				result.Recommendations = append(result.Recommendations,
					"Verify Azure Blob Storage containers have appropriate access policies")
			}
		}

		// GCP-specific recommendations
		if provider == "GCP" {
			if containsString(info.Services, "Cloud Storage") {
				result.Recommendations = append(result.Recommendations,
					"Ensure GCP Cloud Storage buckets have appropriate IAM permissions")
			}
			if containsString(info.Services, "App Engine") {
				result.Recommendations = append(result.Recommendations,
					"Configure GCP App Engine services with appropriate security settings")
			}
		}
	}

	// Multi-cloud recommendations
	if len(result.Providers) > 1 {
		result.Recommendations = append(result.Recommendations,
			"Implement consistent security controls across all cloud providers")
	}
}

// calculateTotals calculates summary statistics
func (d *Detector) calculateTotals(result *models.CloudAnalysisResult) {
	result.TotalProviders = len(result.Providers)

	// Count total services and orphaned resources
	totalServices := 0
	totalOrphaned := 0

	for _, info := range result.Providers {
		totalServices += len(info.Services)
		totalOrphaned += len(info.Orphaned)
	}

	result.TotalServices = totalServices
	result.TotalOrphaned = totalOrphaned
}

// calculateRiskLevel determines overall risk level
func (d *Detector) calculateRiskLevel(result *models.CloudAnalysisResult) {
	// Start with Low risk
	riskLevel := "Low"

	// Increase risk level based on findings
	if result.TotalOrphaned > 0 {
		riskLevel = "Medium"
	}

	if result.TotalOrphaned > 3 {
		riskLevel = "High"
	}

	// Multi-cloud environments often have higher risk
	if result.TotalProviders > 1 && result.TotalServices > 5 {
		if riskLevel == "Low" {
			riskLevel = "Medium"
		} else if riskLevel == "Medium" {
			riskLevel = "High"
		}
	}

	result.RiskLevel = riskLevel
}

// Helper functions for cloud provider detection

// isPrivateIP checks if an IP is private
func isPrivateIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	// Check RFC1918 private ranges
	privateRanges := []struct {
		start net.IP
		end   net.IP
	}{
		{net.ParseIP("10.0.0.0"), net.ParseIP("10.255.255.255")},
		{net.ParseIP("172.16.0.0"), net.ParseIP("172.31.255.255")},
		{net.ParseIP("192.168.0.0"), net.ParseIP("192.168.255.255")},
	}

	for _, r := range privateRanges {
		if bytes4ToUint32(parsedIP.To4()) >= bytes4ToUint32(r.start.To4()) &&
			bytes4ToUint32(parsedIP.To4()) <= bytes4ToUint32(r.end.To4()) {
			return true
		}
	}

	return false
}

// bytes4ToUint32 converts a 4-byte IP to uint32 for comparison
func bytes4ToUint32(bytes []byte) uint32 {
	if bytes == nil || len(bytes) != 4 {
		return 0
	}
	return uint32(bytes[0])<<24 | uint32(bytes[1])<<16 | uint32(bytes[2])<<8 | uint32(bytes[3])
}

// isAWSIP checks if an IP is in AWS IP ranges (simplification - in production, use AWS IP range JSON)
func isAWSIP(ip string) bool {
	// This is a simplified implementation for demonstration
	// In a real implementation, you would download and parse AWS's IP range JSON
	// from https://ip-ranges.amazonaws.com/ip-ranges.json

	// For now, we'll check a few known AWS ranges
	knownRanges := []struct {
		cidr string
	}{
		{"52.0.0.0/12"},
		{"54.0.0.0/8"},
		{"35.0.0.0/8"},
		{"18.0.0.0/8"},
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	for _, r := range knownRanges {
		_, ipNet, err := net.ParseCIDR(r.cidr)
		if err != nil {
			continue
		}

		if ipNet.Contains(parsedIP) {
			return true
		}
	}

	return false
}

// isAzureIP checks if an IP is in Azure IP ranges
func isAzureIP(ip string) bool {
	// Simplified Azure detection
	knownRanges := []struct {
		cidr string
	}{
		{"13.64.0.0/12"},
		{"13.104.0.0/14"},
		{"20.0.0.0/8"},
		{"40.64.0.0/12"},
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	for _, r := range knownRanges {
		_, ipNet, err := net.ParseCIDR(r.cidr)
		if err != nil {
			continue
		}

		if ipNet.Contains(parsedIP) {
			return true
		}
	}

	return false
}

// isGCPIP checks if an IP is in GCP IP ranges
func isGCPIP(ip string) bool {
	// Simplified GCP detection
	knownRanges := []struct {
		cidr string
	}{
		{"34.0.0.0/8"},
		{"35.186.0.0/16"},
		{"35.190.0.0/16"},
		{"35.195.0.0/16"},
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	for _, r := range knownRanges {
		_, ipNet, err := net.ParseCIDR(r.cidr)
		if err != nil {
			continue
		}

		if ipNet.Contains(parsedIP) {
			return true
		}
	}

	return false
}

// isDigitalOceanIP checks if an IP is in DigitalOcean IP ranges
func isDigitalOceanIP(ip string) bool {
	// Simplified Digital Ocean detection
	knownRanges := []struct {
		cidr string
	}{
		{"159.65.0.0/16"},
		{"165.227.0.0/16"},
		{"104.131.0.0/16"},
		{"178.62.0.0/16"},
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	for _, r := range knownRanges {
		_, ipNet, err := net.ParseCIDR(r.cidr)
		if err != nil {
			continue
		}

		if ipNet.Contains(parsedIP) {
			return true
		}
	}

	return false
}

// detectAWSService identifies specific AWS service from a subdomain
func detectAWSService(subdomain string) string {
	subdomain = strings.ToLower(subdomain)

	if strings.Contains(subdomain, "s3") || strings.Contains(subdomain, "s3-website") {
		return "S3 (Simple Storage Service)"
	} else if strings.Contains(subdomain, "cloudfront") {
		return "CloudFront"
	} else if strings.Contains(subdomain, "elb") || strings.Contains(subdomain, "elasticloadbalancing") {
		return "ELB (Elastic Load Balancer)"
	} else if strings.Contains(subdomain, "lambda") {
		return "Lambda"
	} else if strings.Contains(subdomain, "elasticbeanstalk") {
		return "Elastic Beanstalk"
	} else if strings.Contains(subdomain, "ec2") {
		return "EC2 (Elastic Compute Cloud)"
	} else if strings.Contains(subdomain, "amazonses") || strings.Contains(subdomain, "ses") {
		return "SES (Simple Email Service)"
	} else {
		return "Unknown AWS Service"
	}
}

// detectAzureService identifies specific Azure service from a subdomain
func detectAzureService(subdomain string) string {
	subdomain = strings.ToLower(subdomain)

	if strings.Contains(subdomain, "azurewebsites") {
		return "App Service"
	} else if strings.Contains(subdomain, "blob.core.windows") {
		return "Blob Storage"
	} else if strings.Contains(subdomain, "cloudapp") {
		return "Cloud Services"
	} else if strings.Contains(subdomain, "azure-api") {
		return "API Management"
	} else if strings.Contains(subdomain, "azurecontainer") {
		return "Container Instances"
	} else if strings.Contains(subdomain, "azurecr") {
		return "Container Registry"
	} else {
		return "Unknown Azure Service"
	}
}

// detectGCPService identifies specific GCP service from a subdomain
func detectGCPService(subdomain string) string {
	subdomain = strings.ToLower(subdomain)

	if strings.Contains(subdomain, "appspot") {
		return "App Engine"
	} else if strings.Contains(subdomain, "storage.googleapis") {
		return "Cloud Storage"
	} else if strings.Contains(subdomain, "cloudfunctions") {
		return "Cloud Functions"
	} else if strings.Contains(subdomain, "run.app") {
		return "Cloud Run"
	} else if strings.Contains(subdomain, "firebaseapp") {
		return "Firebase"
	} else {
		return "Unknown GCP Service"
	}
}

// detectProviderFromTarget determines which cloud provider a target belongs to
func detectProviderFromTarget(target string) string {
	target = strings.ToLower(target)

	if strings.Contains(target, "amazonaws") ||
		strings.Contains(target, "cloudfront") ||
		strings.Contains(target, "elasticbeanstalk") {
		return "AWS"
	} else if strings.Contains(target, "azure") ||
		strings.Contains(target, "windows.net") {
		return "Azure"
	} else if strings.Contains(target, "appspot") ||
		strings.Contains(target, "googleapis") ||
		strings.Contains(target, "gcp") {
		return "GCP"
	} else {
		return "Unknown"
	}
}

// detectProviderFromSubdomain determines which cloud provider a subdomain might belong to
func detectProviderFromSubdomain(subdomain string) string {
	subdomain = strings.ToLower(subdomain)

	if strings.Contains(subdomain, "aws") ||
		strings.Contains(subdomain, "s3") ||
		strings.Contains(subdomain, "cloudfront") ||
		strings.Contains(subdomain, "ec2") {
		return "AWS"
	} else if strings.Contains(subdomain, "azure") ||
		strings.Contains(subdomain, "msft") {
		return "Azure"
	} else if strings.Contains(subdomain, "gcp") ||
		strings.Contains(subdomain, "gcloud") ||
		strings.Contains(subdomain, "appspot") {
		return "GCP"
	} else {
		return "Unknown"
	}
}

// isCloudSubdomain checks if a subdomain follows cloud naming patterns
func isCloudSubdomain(subdomain string) bool {
	subdomain = strings.ToLower(subdomain)

	cloudPatterns := []string{
		"aws", "s3", "cloudfront", "ec2", "elb", "lambda",
		"azure", "blob", "appservice",
		"gcp", "gcloud", "appspot", "firebase",
		"compute", "storage", "cloud", "cdn",
	}

	for _, pattern := range cloudPatterns {
		if strings.Contains(subdomain, pattern) {
			return true
		}
	}

	return false
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
