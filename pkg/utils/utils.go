package utils

import (
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
)

// ValidateDomain checks if a domain name is valid
func ValidateDomain(domain string) bool {
	// Regex for basic domain validation
	// This should match most valid domain names
	pattern := `^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`
	regex := regexp.MustCompile(pattern)

	return regex.MatchString(domain)
}

// FileExists checks if a file exists and is not a directory
func FileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

// DirExists checks if a directory exists
func DirExists(dirname string) bool {
	info, err := os.Stat(dirname)
	if os.IsNotExist(err) {
		return false
	}
	return info.IsDir()
}

// IsRoot checks if the current process is running as root
func IsRoot() bool {
	return os.Geteuid() == 0
}

// IsPortOpen checks if a port is open on a host
func IsPortOpen(host string, port int) bool {
	address := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", address, 1000000000) // 1 second timeout

	if err != nil {
		return false
	}

	defer conn.Close()
	return true
}

// NormalizeDomain removes protocol prefixes and paths from a domain
// Example: https://example.com/path -> example.com
func NormalizeDomain(input string) string {
	// Remove protocol if present
	input = strings.TrimPrefix(input, "http://")
	input = strings.TrimPrefix(input, "https://")

	// Remove path and query
	if idx := strings.Index(input, "/"); idx != -1 {
		input = input[:idx]
	}

	// Remove port if present
	if idx := strings.Index(input, ":"); idx != -1 {
		input = input[:idx]
	}

	// Remove www. prefix if present
	input = strings.TrimPrefix(input, "www.")

	return input
}

// UniqueStrings returns a slice of unique strings from the input slice
func UniqueStrings(input []string) []string {
	seen := make(map[string]struct{})
	var result []string

	for _, item := range input {
		if _, exists := seen[item]; !exists {
			seen[item] = struct{}{}
			result = append(result, item)
		}
	}

	return result
}

// ExtractHostname extracts the hostname part from a URL
// Example: https://example.com:8080/path -> example.com
func ExtractHostname(urlStr string) string {
	urlStr = strings.TrimSpace(urlStr)
	urlStr = strings.ToLower(urlStr)

	// Remove protocol
	if idx := strings.Index(urlStr, "://"); idx != -1 {
		urlStr = urlStr[idx+3:]
	}

	// Remove path and query
	if idx := strings.Index(urlStr, "/"); idx != -1 {
		urlStr = urlStr[:idx]
	}

	// Remove port
	if idx := strings.Index(urlStr, ":"); idx != -1 {
		urlStr = urlStr[:idx]
	}

	return urlStr
}

// IsPrivateIP checks if an IP is in a private range
func IsPrivateIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	// Check against private IP ranges
	privateRanges := []struct {
		start net.IP
		end   net.IP
	}{
		{net.ParseIP("10.0.0.0"), net.ParseIP("10.255.255.255")},
		{net.ParseIP("172.16.0.0"), net.ParseIP("172.31.255.255")},
		{net.ParseIP("192.168.0.0"), net.ParseIP("192.168.255.255")},
	}

	for _, r := range privateRanges {
		if bytes4ToUint32(parsedIP.To4()) >= bytes4ToUint32(r.start.To4()) &&
			bytes4ToUint32(parsedIP.To4()) <= bytes4ToUint32(r.end.To4()) {
			return true
		}
	}

	return false
}

// bytes4ToUint32 converts a 4-byte IP to uint32 for comparison
func bytes4ToUint32(bytes []byte) uint32 {
	if bytes == nil || len(bytes) != 4 {
		return 0
	}
	return uint32(bytes[0])<<24 | uint32(bytes[1])<<16 | uint32(bytes[2])<<8 | uint32(bytes[3])
}
