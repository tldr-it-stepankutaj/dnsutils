package models

// CloudProviderInfo stores information about detected cloud providers
type CloudProviderInfo struct {
	Provider     string   `json:"provider"`               // Cloud provider name (AWS, Azure, GCP, etc.)
	Services     []string `json:"services,omitempty"`     // Detected services (S3, EC2, Azure App Service, etc.)
	Subdomains   []string `json:"subdomains,omitempty"`   // Subdomains associated with this provider
	IPs          []string `json:"ips,omitempty"`          // IP addresses associated with this provider
	Orphaned     []string `json:"orphaned,omitempty"`     // Potential orphaned resources
	Confidence   string   `json:"confidence"`             // Confidence level (High, Medium, Low)
	Verification string   `json:"verification,omitempty"` // How the provider was verified
}

// CloudAnalysisResult stores the result of cloud infrastructure analysis
type CloudAnalysisResult struct {
	Providers       map[string]*CloudProviderInfo `json:"providers"`                 // Detected cloud providers
	TotalProviders  int                           `json:"total_providers"`           // Total number of distinct providers
	TotalServices   int                           `json:"total_services"`            // Total number of distinct services
	TotalOrphaned   int                           `json:"total_orphaned"`            // Total number of orphaned resources
	Recommendations []string                      `json:"recommendations,omitempty"` // Recommendations based on findings
	RiskLevel       string                        `json:"risk_level"`                // Overall risk level
}
