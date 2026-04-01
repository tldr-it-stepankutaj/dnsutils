package models

// HeaderAnalysis represents the results of HTTP header security analysis
type HeaderAnalysis struct {
	URL             string            `json:"url"`
	StatusCode      int               `json:"status_code"`
	Server          string            `json:"server,omitempty"`
	PoweredBy       string            `json:"powered_by,omitempty"`
	SecurityHeaders map[string]string `json:"security_headers"`
	MissingHeaders  []string          `json:"missing_headers"`
	Technologies    []string          `json:"technologies,omitempty"`
	Findings        []string          `json:"findings,omitempty"`
}
