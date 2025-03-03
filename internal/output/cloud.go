package output

import (
	"fmt"
	"github.com/tldr-it-stepankutaj/dnsutils/internal/models"
	"os"
	"sort"
	"strings"

	"github.com/olekukonko/tablewriter"
)

// PrintCloudResults prints cloud infrastructure analysis results
func (c *Console) PrintCloudResults(result *models.CloudAnalysisResult, domain string) {
	// Print cloud analysis section header
	fmt.Printf("\n%s%sCloud Infrastructure Analysis for %s:%s\n",
		ColorBold, ColorBlue, domain, ColorReset)

	// Print summary table
	summaryTable := tablewriter.NewWriter(os.Stdout)
	summaryTable.SetHeader([]string{"Providers", "Services", "Orphaned Resources", "Risk Level"})

	riskLevelColored := result.RiskLevel
	switch result.RiskLevel {
	case "Low":
		riskLevelColored = fmt.Sprintf("%s%s%s", ColorGreen, result.RiskLevel, ColorReset)
	case "Medium":
		riskLevelColored = fmt.Sprintf("%s%s%s", ColorYellow, result.RiskLevel, ColorReset)
	case "High":
		riskLevelColored = fmt.Sprintf("%s%s%s", ColorRed, result.RiskLevel, ColorReset)
	}

	summaryTable.Append([]string{
		fmt.Sprintf("%d", result.TotalProviders),
		fmt.Sprintf("%d", result.TotalServices),
		fmt.Sprintf("%d", result.TotalOrphaned),
		riskLevelColored,
	})

	summaryTable.SetBorder(true)
	summaryTable.Render()

	// Print providers table
	if len(result.Providers) > 0 {
		fmt.Printf("\n%s%sDetected Cloud Providers:%s\n", ColorBold, ColorBlue, ColorReset)

		providerTable := tablewriter.NewWriter(os.Stdout)
		providerTable.SetHeader([]string{"Provider", "Services", "Confidence", "Verification"})
		providerTable.SetAutoWrapText(false)
		providerTable.SetColWidth(40)

		// Sort providers by name for consistent output
		var providers []string
		for provider := range result.Providers {
			providers = append(providers, provider)
		}
		sort.Strings(providers)

		for _, provider := range providers {
			info := result.Providers[provider]

			// Format services as a comma-separated list, or "None detected" if empty
			services := "None detected"
			if len(info.Services) > 0 {
				services = strings.Join(info.Services, ", ")
			}

			providerTable.Append([]string{
				provider,
				services,
				formatCloudConfidence(info.Confidence),
				info.Verification,
			})
		}

		providerTable.SetBorder(true)
		providerTable.Render()
	}

	// Print orphaned resources table if any found
	if result.TotalOrphaned > 0 {
		fmt.Printf("\n%s%sPotential Orphaned Resources:%s\n", ColorBold, ColorRed, ColorReset)

		orphanedTable := tablewriter.NewWriter(os.Stdout)
		orphanedTable.SetHeader([]string{"Provider", "Resource"})
		orphanedTable.SetAutoWrapText(false)
		orphanedTable.SetColWidth(80)

		for provider, info := range result.Providers {
			if len(info.Orphaned) > 0 {
				for _, resource := range info.Orphaned {
					orphanedTable.Append([]string{
						provider,
						resource,
					})
				}
			}
		}

		orphanedTable.SetBorder(true)
		orphanedTable.Render()
	}

	// Print recommendations table
	if len(result.Recommendations) > 0 {
		fmt.Printf("\n%s%sCloud Security Recommendations:%s\n", ColorBold, ColorBlue, ColorReset)

		recTable := tablewriter.NewWriter(os.Stdout)
		recTable.SetHeader([]string{"#", "Recommendation"})
		recTable.SetAutoWrapText(false)
		recTable.SetColWidth(80)

		for i, rec := range result.Recommendations {
			recTable.Append([]string{
				fmt.Sprintf("%d", i+1),
				rec,
			})
		}

		recTable.SetBorder(true)
		recTable.Render()
	}
}

// formatCloudConfidence formats confidence levels with colors
func formatCloudConfidence(confidence string) string {
	switch confidence {
	case "High":
		return fmt.Sprintf("%s%s%s", ColorGreen, confidence, ColorReset)
	case "Medium":
		return fmt.Sprintf("%s%s%s", ColorYellow, confidence, ColorReset)
	case "Low":
		return fmt.Sprintf("%s%s%s", ColorRed, confidence, ColorReset)
	default:
		return confidence
	}
}
