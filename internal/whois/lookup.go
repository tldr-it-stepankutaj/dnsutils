package whois

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/tldr-it-stepankutaj/dnsutils/internal/models"
)

const (
	ianaWhoisServer = "whois.iana.org"
	whoisPort       = "43"
	dialTimeout     = 10 * time.Second
	readTimeout     = 15 * time.Second
)

// Lookup provides WHOIS query functionality.
type Lookup struct{}

// NewLookup creates a new Lookup instance.
func NewLookup() *Lookup {
	return &Lookup{}
}

// GetWhoisInfo performs a WHOIS lookup for the given domain and returns
// parsed registration information. It first queries whois.iana.org to
// discover the authoritative WHOIS server for the TLD, then queries
// that server for the full domain record.
func (l *Lookup) GetWhoisInfo(domain string) (*models.WhoisInfo, error) {
	domain = strings.TrimSpace(strings.ToLower(domain))
	if domain == "" {
		return nil, fmt.Errorf("empty domain")
	}

	// Step 1: determine the authoritative WHOIS server via IANA referral.
	server, err := l.findWhoisServer(domain)
	if err != nil {
		return nil, fmt.Errorf("finding whois server: %w", err)
	}

	// Step 2: query the authoritative WHOIS server.
	raw, err := l.query(server, domain)
	if err != nil {
		return nil, fmt.Errorf("querying %s: %w", server, err)
	}

	// Step 3: some registries (e.g. .com via verisign) include a "Registrar
	// WHOIS Server" referral pointing to the registrar's own WHOIS. Follow it
	// for richer data.
	if referral := extractReferral(raw); referral != "" {
		referred, err := l.query(referral, domain)
		if err == nil && len(referred) > len(raw) {
			raw = referred
		}
	}

	info := parseWhoisResponse(raw)
	info.RawText = raw
	return info, nil
}

// findWhoisServer queries whois.iana.org to discover the TLD's authoritative
// WHOIS server.
func (l *Lookup) findWhoisServer(domain string) (string, error) {
	tld := domain
	if idx := strings.LastIndex(domain, "."); idx != -1 {
		tld = domain[idx+1:]
	}

	raw, err := l.query(ianaWhoisServer, tld)
	if err != nil {
		return "", err
	}

	// IANA responses contain a "refer:" or "whois:" line with the server.
	scanner := bufio.NewScanner(strings.NewReader(raw))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		lower := strings.ToLower(line)
		for _, prefix := range []string{"refer:", "whois:"} {
			if strings.HasPrefix(lower, prefix) {
				server := strings.TrimSpace(line[len(prefix):])
				if server != "" {
					return server, nil
				}
			}
		}
	}

	return "", fmt.Errorf("no whois server found for TLD %q", tld)
}

// query sends a WHOIS query to the given server and returns the raw response.
func (l *Lookup) query(server, queryStr string) (string, error) {
	addr := net.JoinHostPort(server, whoisPort)

	conn, err := net.DialTimeout("tcp", addr, dialTimeout)
	if err != nil {
		return "", fmt.Errorf("connecting to %s: %w", addr, err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(readTimeout)); err != nil {
		return "", fmt.Errorf("setting deadline: %w", err)
	}

	_, err = fmt.Fprintf(conn, "%s\r\n", queryStr)
	if err != nil {
		return "", fmt.Errorf("writing query: %w", err)
	}

	data, err := io.ReadAll(conn)
	if err != nil {
		return "", fmt.Errorf("reading response: %w", err)
	}

	return string(data), nil
}

// extractReferral looks for a registrar-level WHOIS server referral in the
// raw response text.
func extractReferral(raw string) string {
	scanner := bufio.NewScanner(strings.NewReader(raw))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "registrar whois server:") {
			server := strings.TrimSpace(line[len("registrar whois server:"):])
			// Some entries include the protocol prefix; strip it.
			server = strings.TrimPrefix(server, "http://")
			server = strings.TrimPrefix(server, "https://")
			server = strings.TrimSuffix(server, "/")
			if server != "" {
				return server
			}
		}
	}
	return ""
}

// parseWhoisResponse extracts structured fields from raw WHOIS text.
// Different registrars use slightly different field names; we handle the
// most common variations.
func parseWhoisResponse(raw string) *models.WhoisInfo {
	info := &models.WhoisInfo{}
	seen := make(map[string]bool)

	scanner := bufio.NewScanner(strings.NewReader(raw))
	for scanner.Scan() {
		line := scanner.Text()
		colonIdx := strings.Index(line, ":")
		if colonIdx == -1 {
			continue
		}

		key := strings.TrimSpace(line[:colonIdx])
		value := strings.TrimSpace(line[colonIdx+1:])
		if value == "" {
			continue
		}

		keyLower := strings.ToLower(key)

		switch {
		case matchesAny(keyLower, "registrar"):
			if !seen["registrar"] {
				info.Registrar = value
				seen["registrar"] = true
			}

		case matchesAny(keyLower, "creation date", "created", "created date",
			"registration date", "registered on", "domain registration date"):
			if !seen["created"] {
				info.CreatedDate = value
				seen["created"] = true
			}

		case matchesAny(keyLower, "registry expiry date", "expiry date",
			"expiration date", "registrar registration expiration date",
			"paid-till", "expires on", "domain expiration date"):
			if !seen["expiry"] {
				info.ExpiryDate = value
				seen["expiry"] = true
			}

		case matchesAny(keyLower, "updated date", "last updated",
			"last modified", "last update of whois database"):
			if !seen["updated"] {
				info.UpdatedDate = value
				seen["updated"] = true
			}

		case matchesAny(keyLower, "name server", "nserver"):
			ns := strings.ToLower(strings.Fields(value)[0])
			info.NameServers = append(info.NameServers, ns)

		case matchesAny(keyLower, "registrant organization", "registrant organisation",
			"org", "organization"):
			if !seen["org"] {
				info.Organization = value
				seen["org"] = true
			}

		case matchesAny(keyLower, "registrant country", "registrant country/economy"):
			if !seen["country"] {
				info.Country = value
				seen["country"] = true
			}

		case matchesAny(keyLower, "dnssec"):
			if !seen["dnssec"] {
				info.DNSSEC = value
				seen["dnssec"] = true
			}
		}
	}

	return info
}

// matchesAny returns true if s equals any of the given candidates.
func matchesAny(s string, candidates ...string) bool {
	for _, c := range candidates {
		if s == c {
			return true
		}
	}
	return false
}
