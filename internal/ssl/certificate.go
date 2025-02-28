package ssl

import (
	"crypto/tls"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/tldr-it-stepankutaj/dnsutils/internal/models"
)

// Certificate handles SSL certificate operations
type Certificate struct{}

// NewCertificate creates a new Certificate handler
func NewCertificate() *Certificate {
	return &Certificate{}
}

// GetSSLInfo gets SSL certificate information for a domain
func (c *Certificate) GetSSLInfo(domain string, port int) *models.SSLInfo {
	// First try using OpenSSL
	info, err := c.getSSLInfoUsingOpenSSL(domain, port)
	if err == nil {
		return info
	}

	// Fallback to Go's TLS implementation
	return c.getSSLInfoUsingGoTLS(domain, port)
}

// getSSLInfoUsingOpenSSL uses the OpenSSL command line tool to get certificate info
func (c *Certificate) getSSLInfoUsingOpenSSL(domain string, port int) (*models.SSLInfo, error) {
	cmd := exec.Command("sh", "-c",
		fmt.Sprintf("echo | openssl s_client -showcerts -servername %s -connect %s:%d 2>/dev/null | openssl x509 -inform pem -noout -text",
			domain, domain, port))

	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, err
	}

	outputStr := string(output)

	// Extract information
	commonName := ""
	issuer := ""
	expiry := ""

	// Find CN in Subject
	subjectRegex := regexp.MustCompile(`Subject:.*?CN\s*=\s*([^,\n]+)`)
	if matches := subjectRegex.FindStringSubmatch(outputStr); len(matches) > 1 {
		commonName = matches[1]
	}

	// Find CN in Issuer
	issuerRegex := regexp.MustCompile(`Issuer:.*?CN\s*=\s*([^,\n]+)`)
	if matches := issuerRegex.FindStringSubmatch(outputStr); len(matches) > 1 {
		issuer = matches[1]
	}

	// Find expiry
	expiryRegex := regexp.MustCompile(`Not After\s*:\s*(.+)\n`)
	if matches := expiryRegex.FindStringSubmatch(outputStr); len(matches) > 1 {
		expiry = strings.TrimSpace(matches[1])
	}

	// If commonName is still empty, try to find it in SAN
	if commonName == "" {
		sanRegex := regexp.MustCompile(`X509v3 Subject Alternative Name:[^\n]*\n\s*DNS:([^\s,]+)`)
		if matches := sanRegex.FindStringSubmatch(outputStr); len(matches) > 1 {
			commonName = matches[1]
		}
	}

	// If still no CN, use domain name
	if commonName == "" {
		commonName = domain
	}

	return &models.SSLInfo{
		CommonName: commonName,
		Issuer:     issuer,
		Expiry:     expiry,
	}, nil
}

// getSSLInfoUsingGoTLS uses Go's TLS implementation to get certificate info
func (c *Certificate) getSSLInfoUsingGoTLS(domain string, port int) *models.SSLInfo {
	config := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         domain,
	}

	address := fmt.Sprintf("%s:%d", domain, port)
	dialer := &net.Dialer{
		Timeout: 3 * time.Second,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", address, config)
	if err != nil {
		return &models.SSLInfo{
			CommonName: domain,
			Issuer:     "Could not obtain",
			Expiry:     "Could not obtain",
		}
	}
	defer conn.Close()

	// Get the peer certificates
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return &models.SSLInfo{
			CommonName: domain,
			Issuer:     "No certificates",
			Expiry:     "No certificates",
		}
	}

	cert := certs[0]

	commonName := ""
	if len(cert.Subject.CommonName) > 0 {
		commonName = cert.Subject.CommonName
	} else {
		commonName = domain
	}

	issuer := ""
	if len(cert.Issuer.CommonName) > 0 {
		issuer = cert.Issuer.CommonName
	} else {
		issuer = "Unknown issuer"
	}

	expiry := cert.NotAfter.Format(time.RFC1123)

	return &models.SSLInfo{
		CommonName: commonName,
		Issuer:     issuer,
		Expiry:     expiry,
	}
}
