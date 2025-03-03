package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/tldr-it-stepankutaj/dnsutils/internal/models"
	"github.com/tldr-it-stepankutaj/dnsutils/internal/output"
	"github.com/tldr-it-stepankutaj/dnsutils/internal/security"
	"os"
)

func main() {
	// Parse command-line arguments
	domain := flag.String("domain", "", "Domain to analyze")
	dnsServer := flag.String("dns", "8.8.8.8:53", "DNS server to use")
	jsonOutput := flag.String("json", "", "Output file for JSON results")
	flag.Parse()

	if *domain == "" {
		fmt.Println("Error: Domain is required")
		flag.Usage()
		os.Exit(1)
	}

	// Create console output
	console := output.NewConsole()
	console.PrintBanner()
	console.PrintProgress(fmt.Sprintf("Analyzing security configuration for domain: %s", *domain))

	// Create security analyzer
	analyzer := security.NewAnalyzer(*dnsServer)

	// Perform analysis
	result, err := analyzer.AnalyzeDomain(*domain)
	if err != nil {
		console.PrintError(fmt.Sprintf("Error analyzing domain: %s", err))
		os.Exit(1)
	}

	// Print results
	printSecurityResults(console, result, *domain)

	// Save results to JSON if requested
	if *jsonOutput != "" {
		file, err := os.Create(*jsonOutput)
		if err != nil {
			console.PrintError(fmt.Sprintf("Error creating JSON output file: %s", err))
			os.Exit(1)
		}
		defer file.Close()

		encoder := json.NewEncoder(file)
		encoder.SetIndent("", "  ")
		err = encoder.Encode(result)
		if err != nil {
			console.PrintError(fmt.Sprintf("Error encoding JSON: %s", err))
			os.Exit(1)
		}

		console.PrintSuccess(fmt.Sprintf("Results saved to: %s", *jsonOutput))
	}
}

// printSecurityResults prints security analysis results
func printSecurityResults(console *output.Console, result *models.SecurityResult, domain string) {
	// Print overall security score
	securityRating := "Poor"
	if result.SecurityScore >= 70 {
		securityRating = "Excellent"
	} else if result.SecurityScore >= 50 {
		securityRating = "Good"
	} else if result.SecurityScore >= 30 {
		securityRating = "Fair"
	}

	fmt.Printf("\n%sEmail Security Rating:%s %s (%d/100)\n",
		output.ColorBold, output.ColorReset, securityRating, result.SecurityScore)

	// Print SPF Record Information
	fmt.Printf("\n%sSPF Record Analysis:%s\n", output.ColorBlue, output.ColorReset)
	if result.SPFRecord != nil {
		validStatus := fmt.Sprintf("%sValid%s", output.ColorGreen, output.ColorReset)
		if !result.SPFRecord.Valid {
			validStatus = fmt.Sprintf("%sInvalid%s", output.ColorRed, output.ColorReset)
		}

		fmt.Printf("  Record: %s\n", result.SPFRecord.Record)
		fmt.Printf("  Status: %s\n", validStatus)
		fmt.Printf("  Policy: %s\n", formatPolicy(result.SPFRecord.Policy))

		if len(result.SPFRecord.Includes) > 0 {
			fmt.Printf("  Includes:\n")
			for _, include := range result.SPFRecord.Includes {
				fmt.Printf("    - %s\n", include)
			}
		}

		if len(result.SPFRecord.Issues) > 0 {
			fmt.Printf("  %sIssues:%s\n", output.ColorYellow, output.ColorReset)
			for _, issue := range result.SPFRecord.Issues {
				fmt.Printf("    - %s\n", issue)
			}
		}
	} else {
		fmt.Printf("  %sNo SPF record found%s\n", output.ColorRed, output.ColorReset)
	}

	// Print DMARC Record Information
	fmt.Printf("\n%sDMARC Record Analysis:%s\n", output.ColorBlue, output.ColorReset)
	if result.DMARCRecord != nil {
		validStatus := fmt.Sprintf("%sValid%s", output.ColorGreen, output.ColorReset)
		if !result.DMARCRecord.Valid {
			validStatus = fmt.Sprintf("%sInvalid%s", output.ColorRed, output.ColorReset)
		}

		fmt.Printf("  Record: %s\n", result.DMARCRecord.Record)
		fmt.Printf("  Status: %s\n", validStatus)
		fmt.Printf("  Policy: %s\n", formatPolicy(result.DMARCRecord.Policy))

		if result.DMARCRecord.SubdomainPolicy != "" {
			fmt.Printf("  Subdomain Policy: %s\n", formatPolicy(result.DMARCRecord.SubdomainPolicy))
		}

		fmt.Printf("  Percentage: %d%%\n", result.DMARCRecord.Percentage)

		if len(result.DMARCRecord.ReportURI) > 0 {
			fmt.Printf("  Aggregate Reports To:\n")
			for _, uri := range result.DMARCRecord.ReportURI {
				fmt.Printf("    - %s\n", uri)
			}
		}

		if len(result.DMARCRecord.ForensicURI) > 0 {
			fmt.Printf("  Forensic Reports To:\n")
			for _, uri := range result.DMARCRecord.ForensicURI {
				fmt.Printf("    - %s\n", uri)
			}
		}

		if len(result.DMARCRecord.Issues) > 0 {
			fmt.Printf("  %sIssues:%s\n", output.ColorYellow, output.ColorReset)
			for _, issue := range result.DMARCRecord.Issues {
				fmt.Printf("    - %s\n", issue)
			}
		}
	} else {
		fmt.Printf("  %sNo DMARC record found%s\n", output.ColorRed, output.ColorReset)
	}

	// Print DKIM Records Information
	fmt.Printf("\n%sDKIM Records Analysis:%s\n", output.ColorBlue, output.ColorReset)
	if result.DKIMRecords != nil && len(result.DKIMRecords) > 0 {
		for _, dkim := range result.DKIMRecords {
			validStatus := fmt.Sprintf("%sValid%s", output.ColorGreen, output.ColorReset)
			if !dkim.Valid {
				validStatus = fmt.Sprintf("%sInvalid%s", output.ColorRed, output.ColorReset)
			}

			fmt.Printf("  Selector: %s\n", dkim.Selector)
			fmt.Printf("  Status: %s\n", validStatus)

			if dkim.KeyType != "" {
				fmt.Printf("  Key Type: %s\n", dkim.KeyType)
			}

			if len(dkim.Issues) > 0 {
				fmt.Printf("  %sIssues:%s\n", output.ColorYellow, output.ColorReset)
				for _, issue := range dkim.Issues {
					fmt.Printf("    - %s\n", issue)
				}
			}

			fmt.Println()
		}
	} else {
		fmt.Printf("  %sNo DKIM records found%s\n", output.ColorRed, output.ColorReset)
	}

	// Print MX Analysis
	fmt.Printf("\n%sMX Records Security Analysis:%s\n", output.ColorBlue, output.ColorReset)
	if result.MXAnalysis != nil {
		if len(result.MXAnalysis.Servers) > 0 {
			fmt.Printf("  Mail Servers:\n")
			for _, server := range result.MXAnalysis.Servers {
				secureStatus := ""
				for _, secureServer := range result.MXAnalysis.SecureServers {
					if server == secureServer {
						secureStatus = fmt.Sprintf(" %s(TLS Support)%s", output.ColorGreen, output.ColorReset)
						break
					}
				}
				fmt.Printf("    - %s%s\n", server, secureStatus)
			}
		}

		backupStatus := fmt.Sprintf("%sYes%s", output.ColorGreen, output.ColorReset)
		if !result.MXAnalysis.HasBackup {
			backupStatus = fmt.Sprintf("%sNo%s", output.ColorYellow, output.ColorReset)
		}
		fmt.Printf("  Backup MX: %s\n", backupStatus)

		tlsStatus := fmt.Sprintf("%sAll Servers%s", output.ColorGreen, output.ColorReset)
		if !result.MXAnalysis.AllSecure {
			tlsStatus = fmt.Sprintf("%sPartial/Unknown%s", output.ColorYellow, output.ColorReset)
		}
		fmt.Printf("  TLS Support: %s\n", tlsStatus)

		if len(result.MXAnalysis.Issues) > 0 {
			fmt.Printf("  %sIssues:%s\n", output.ColorYellow, output.ColorReset)
			for _, issue := range result.MXAnalysis.Issues {
				fmt.Printf("    - %s\n", issue)
			}
		}
	} else {
		fmt.Printf("  %sNo MX records found%s\n", output.ColorRed, output.ColorReset)
	}

	// Print CAA Analysis
	fmt.Printf("\n%sCAA Records Analysis:%s\n", output.ColorBlue, output.ColorReset)
	if result.CAAAnalysis != nil {
		if len(result.CAAAnalysis.Records) > 0 {
			fmt.Printf("  CAA Records:\n")
			for _, record := range result.CAAAnalysis.Records {
				fmt.Printf("    - %s\n", record)
			}
		}

		if len(result.CAAAnalysis.IssueCAs) > 0 {
			fmt.Printf("  Authorized CAs:\n")
			for _, ca := range result.CAAAnalysis.IssueCAs {
				fmt.Printf("    - %s\n", ca)
			}
		}

		if result.CAAAnalysis.HasIssueWildcard && len(result.CAAAnalysis.IssueWildcardCAs) > 0 {
			fmt.Printf("  Authorized Wildcard CAs:\n")
			for _, ca := range result.CAAAnalysis.IssueWildcardCAs {
				fmt.Printf("    - %s\n", ca)
			}
		}

		iodefStatus := fmt.Sprintf("%sYes%s", output.ColorGreen, output.ColorReset)
		if !result.CAAAnalysis.HasIODEF {
			iodefStatus = fmt.Sprintf("%sNo%s", output.ColorYellow, output.ColorReset)
		}
		fmt.Printf("  Certificate Issue Violation Reporting: %s\n", iodefStatus)

		if len(result.CAAAnalysis.Issues) > 0 {
			fmt.Printf("  %sIssues:%s\n", output.ColorYellow, output.ColorReset)
			for _, issue := range result.CAAAnalysis.Issues {
				fmt.Printf("    - %s\n", issue)
			}
		}
	} else {
		fmt.Printf("  %sNo CAA records found%s\n", output.ColorYellow, output.ColorReset)
	}

	// Print Recommendations
	if len(result.Recommendations) > 0 {
		fmt.Printf("\n%sSecurity Recommendations:%s\n", output.ColorBold, output.ColorReset)
		for i, rec := range result.Recommendations {
			fmt.Printf("%s%d.%s %s\n", output.ColorGreen, i+1, output.ColorReset, rec)
		}
	}
}

// formatPolicy formats the policy for display
func formatPolicy(policy string) string {
	switch policy {
	case "fail", "reject":
		return fmt.Sprintf("%s%s%s", output.ColorGreen, policy, output.ColorReset)
	case "softfail", "quarantine":
		return fmt.Sprintf("%s%s%s", output.ColorYellow, policy, output.ColorReset)
	case "none", "neutral", "pass":
		return fmt.Sprintf("%s%s%s", output.ColorRed, policy, output.ColorReset)
	default:
		return policy
	}
}
