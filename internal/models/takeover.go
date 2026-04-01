package models

// TakeoverResult represents the result of a subdomain takeover check
type TakeoverResult struct {
	Subdomain   string `json:"subdomain"`
	CNAME       string `json:"cname"`
	Service     string `json:"service"`
	Vulnerable  bool   `json:"vulnerable"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Risk        string `json:"risk"` // High, Medium, Low
}
