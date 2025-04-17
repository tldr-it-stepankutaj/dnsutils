package models

import "time"

type SSLNameNew struct {
	CommonName   string
	Organization string
}

type SSLInfoNew struct {
	Subject *SSLNameNew
	Issuer  *SSLNameNew
	Expiry  time.Time
}

type SubdomainDetailsNew struct {
	IP           string
	ASN          string
	OpenServices []string
	SSLInfo      *SSLInfoNew
}
