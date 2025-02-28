package asn

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Lookup handles ASN information lookups
type Lookup struct {
	Client *http.Client
}

// NewLookup creates a new ASN lookup
func NewLookup() *Lookup {
	return &Lookup{
		Client: &http.Client{
			Timeout: 60 * time.Second,
		},
	}
}

// GetASNInfo gets ASN information for an IP address
func (l *Lookup) GetASNInfo(ip string) string {
	// Check if it's a private IP
	if l.isPrivateIP(ip) {
		return "Private IP (no ASN)"
	}

	// First try ipapi.co
	info := l.getASNFromIPAPI(ip)
	if !strings.Contains(info, "error") && !strings.Contains(info, "unavailable") {
		return info
	}

	// If that fails, try ip-api.com as fallback
	return l.getASNFromIPAPIcom(ip)
}

// getASNFromIPAPI gets ASN info from ipapi.co
func (l *Lookup) getASNFromIPAPI(ip string) string {
	resp, err := l.Client.Get(fmt.Sprintf("https://ipapi.co/%s/json/", ip))
	if err != nil {
		return "Connection error"
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Sprintf("HTTP error: %d", resp.StatusCode)
	}

	var data map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&data)
	if err != nil {
		return "Response parsing error"
	}

	if _, ok := data["error"].(string); ok {
		// Don't return error message, try fallback instead
		return "API error"
	}

	if asn, ok := data["asn"].(string); ok {
		if org, ok := data["org"].(string); ok {
			return fmt.Sprintf("ASN:%s %s", asn, org)
		}
	}

	return "ASN info unavailable"
}

// getASNFromIPAPIcom gets ASN info from ip-api.com (fallback)
func (l *Lookup) getASNFromIPAPIcom(ip string) string {
	resp, err := l.Client.Get(fmt.Sprintf("http://ip-api.com/json/%s?fields=as,org,isp", ip))
	if err != nil {
		return "No ASN info available"
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "No ASN info available"
	}

	var data map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&data)
	if err != nil {
		return "No ASN info available"
	}

	// Extract ASN info
	if as, ok := data["as"].(string); ok {
		// Try to extract just the ASN number
		asnParts := strings.Split(as, " ")
		asnNum := ""
		if len(asnParts) > 0 {
			asnNum = strings.TrimPrefix(asnParts[0], "AS")
		}

		// Get organization name
		org := ""
		if orgData, ok := data["org"].(string); ok {
			org = orgData
		} else if ispData, ok := data["isp"].(string); ok {
			org = ispData
		}

		if asnNum != "" && org != "" {
			return fmt.Sprintf("ASN:%s %s", asnNum, org)
		} else if as != "" {
			return as
		}
	}

	return "No ASN info available"
}

// isPrivateIP checks if an IP address is private
func (l *Lookup) isPrivateIP(ip string) bool {
	privateRanges := []string{
		"10.",
		"172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
		"172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
		"172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
		"192.168.",
	}

	for _, prefix := range privateRanges {
		if strings.HasPrefix(ip, prefix) {
			return true
		}
	}

	return false
}
