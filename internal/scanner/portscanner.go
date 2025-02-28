package scanner

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/html"
)

// Scanner handles port scanning and service detection
type Scanner struct {
	Timeout       time.Duration
	MaxConcurrent int
}

// NewScanner creates a new scanner
func NewScanner() *Scanner {
	return &Scanner{
		Timeout:       1 * time.Second,
		MaxConcurrent: 100,
	}
}

// PortScan scans the specified ports on a given IP
func (s *Scanner) PortScan(ip string, ports []int) []int {
	var openPorts []int
	var mutex sync.Mutex
	var wg sync.WaitGroup

	// Create semaphore for limiting concurrent scans
	sem := make(chan struct{}, s.MaxConcurrent)

	for _, port := range ports {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()

			// Acquire semaphore slot
			sem <- struct{}{}
			defer func() { <-sem }()

			address := fmt.Sprintf("%s:%d", ip, port)
			conn, err := net.DialTimeout("tcp", address, s.Timeout)
			if err == nil {
				mutex.Lock()
				openPorts = append(openPorts, port)
				mutex.Unlock()
				conn.Close()
			}
		}(port)
	}

	wg.Wait()
	return openPorts
}

// GetServiceName maps a port to a service name
func (s *Scanner) GetServiceName(port int) string {
	serviceMap := map[int]string{
		21:   "ftp",
		22:   "ssh",
		23:   "telnet",
		25:   "smtp",
		53:   "dns",
		80:   "http",
		110:  "pop3",
		143:  "imap",
		443:  "https",
		3306: "mysql",
		5432: "postgresql",
		8080: "http-alt",
		8443: "https-alt",
	}

	if name, ok := serviceMap[port]; ok {
		return name
	}

	return fmt.Sprintf("port-%d", port)
}

// GetServiceDetails gets details about a service on a specific port
func (s *Scanner) GetServiceDetails(ip string, port int) string {
	serviceName := s.GetServiceName(port)

	switch port {
	case 80:
		info, err := s.GetHTTPInfo(ip, 80, false)
		if err == nil {
			return fmt.Sprintf("http: %s", info)
		}
	case 443:
		info, err := s.GetHTTPInfo(ip, 443, true)
		if err == nil {
			return fmt.Sprintf("https: %s", info)
		}
	case 22:
		banner, err := s.GetSSHBanner(ip)
		if err == nil {
			return fmt.Sprintf("ssh: %s", banner)
		}
	case 21:
		banner, err := s.GetFTPBanner(ip)
		if err == nil {
			return fmt.Sprintf("ftp: %s", banner)
		}
	}

	return serviceName
}

// GetSSHBanner gets the SSH banner from a server
func (s *Scanner) GetSSHBanner(ip string) (string, error) {
	address := fmt.Sprintf("%s:22", ip)
	conn, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	buffer := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(buffer)
	if err != nil {
		return "", err
	}

	return string(buffer[:n]), nil
}

// GetFTPBanner gets the FTP banner from a server
func (s *Scanner) GetFTPBanner(ip string) (string, error) {
	address := fmt.Sprintf("%s:21", ip)
	conn, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	buffer := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(buffer)
	if err != nil {
		return "", err
	}

	return string(buffer[:n]), nil
}

// GetHTTPInfo gets HTTP server information
func (s *Scanner) GetHTTPInfo(ip string, port int, isHTTPS bool) (string, error) {
	protocol := "http"
	if isHTTPS {
		protocol = "https"
	}

	url := fmt.Sprintf("%s://%s:%d", protocol, ip, port)

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Get(url)
	if err != nil {
		return "Connection failed", err
	}
	defer resp.Body.Close()

	server := resp.Header.Get("Server")

	// Try to get page title
	title := ""
	contentType := resp.Header.Get("Content-Type")
	if strings.Contains(contentType, "text/html") {
		body, err := ioutil.ReadAll(resp.Body)
		if err == nil {
			title = s.extractTitle(string(body))
		}
	}

	result := server
	if title != "" {
		result += fmt.Sprintf(" title: %s", title)
	}

	return result, nil
}

// extractTitle extracts the title from HTML
func (s *Scanner) extractTitle(htmlContent string) string {
	tokenizer := html.NewTokenizer(strings.NewReader(htmlContent))
	inTitle := false

	for {
		tokenType := tokenizer.Next()

		switch tokenType {
		case html.ErrorToken:
			return "" // End of document or error
		case html.StartTagToken, html.SelfClosingTagToken:
			token := tokenizer.Token()
			if token.Data == "title" {
				inTitle = true
			}
		case html.TextToken:
			if inTitle {
				return tokenizer.Token().Data
			}
		case html.EndTagToken:
			token := tokenizer.Token()
			if token.Data == "title" {
				inTitle = false
			}
		}
	}
}
