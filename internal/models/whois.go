package models

type WhoisInfo struct {
	Registrar    string   `json:"registrar"`
	CreatedDate  string   `json:"created_date"`
	ExpiryDate   string   `json:"expiry_date"`
	UpdatedDate  string   `json:"updated_date"`
	NameServers  []string `json:"name_servers,omitempty"`
	Organization string   `json:"organization,omitempty"`
	Country      string   `json:"country,omitempty"`
	DNSSEC       string   `json:"dnssec,omitempty"`
	RawText      string   `json:"raw_text,omitempty"`
}
