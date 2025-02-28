# DNS Reconnaissance Tool

A powerful DNS reconnaissance and subdomain discovery tool written in Go. This tool helps security researchers and penetration testers gather comprehensive information about domains, including DNS records, subdomains, SSL certificates, and service fingerprinting.

[![GitHub release](https://img.shields.io/github/v/release/tldr-it-stepankutaj/dnsutils)](https://github.com/tldr-it-stepankutaj/dnsutils/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/tldr-it-stepankutaj/dnsutils)](https://goreportcard.com/report/github.com/tldr-it-stepankutaj/dnsutils)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Features

- 🔍 **DNS record enumeration** - A, AAAA, MX, TXT, CNAME, NS and SOA records
- 🔎 **Subdomain discovery** via:
  - Certificate Transparency logs
  - Brute-force scanning with custom wordlists
- 🔐 **SSL certificate information**
- 🔧 **Port scanning and service fingerprinting**
- 🌐 **ASN lookup** for discovered IP addresses
- 📊 **Clean, colorized output** with formatted tables
- 💾 **JSON export** for further analysis or integration

## Installation

### Pre-built Binaries

Download the latest release from the [Releases page](https://github.com/tldr-it-stepankutaj/dnsutils/releases).

### Building from Source

#### Prerequisites

- Go 1.21 or later

#### Building

1. Clone the repository:
   ```bash
   git clone https://github.com/tldr-it-stepankutaj/dnsutils.git
   cd dnsutils
   ```

2. Build the binary:
   ```bash
   make build
   ```

   This will create a binary in the `bin` directory.

3. Or build for all platforms:
   ```bash
   make build-all
   ```

   This creates binaries for:
   - Linux (amd64, arm64)
   - macOS (amd64, arm64)
   - Windows (amd64)

## Usage

```bash
./bin/dnsutils [options] domain
```

### Options

```
  -c int
        Concurrency level for scans (default 40)
  -dns string
        DNS server to use for queries (default "8.8.8.8:53")
  -no-bruteforce
        Skip brute-force subdomain discovery
  -no-certs
        Skip subdomain discovery via certificates
  -o string
        Output file for results (JSON)
  -p value
        Ports to scan (can be used multiple times, default: 80,443,22,21,25,8080,8443)
  -t int
        Timeout in seconds for network operations (default 1)
  -v    Verbose output
  -w string
        File with subdomain list for brute-force
```

### Examples

Basic scan:
```bash
./bin/dnsutils example.com
```

Advanced scan with custom settings:
```bash
./bin/dnsutils -o results.json -w wordlist.txt -p 80 -p 443 -p 8080 -c 100 -t 2 example.com
```

## Example Output

Running a scan against `cia.gov` produces detailed output like this:

<pre style="background-color: #000; color: #fff; padding: 10px; border-radius: 5px; overflow: auto;">
<span style="color: #3498db;">
╔═══════════════════════════════════════════════════════╗
║               DNS Reconnaissance Tool                 ║
╚═══════════════════════════════════════════════════════╝
</span>
<span style="color: #3498db;">[*]</span> Starting DNS reconnaissance...
<span style="color: #3498db;">[*]</span> Getting IP addresses for the domain...
<span style="color: #2ecc71;">[+]</span> Found 3 IP addresses for cia.gov
<span style="color: #3498db;">[*]</span> Looking for SOA records...
<span style="color: #3498db;">[*]</span> Looking for CNAME records...
<span style="color: #3498db;">[*]</span> Looking for NS records...
<span style="color: #3498db;">[*]</span> Looking for A records...
<span style="color: #3498db;">[*]</span> Looking for TXT records...
<span style="color: #3498db;">[*]</span> Looking for AAAA records...
<span style="color: #3498db;">[*]</span> Looking for MX records...
<span style="color: #2ecc71;">[+]</span> Found 1 A records
<span style="color: #2ecc71;">[+]</span> Found 1 SOA records
<span style="color: #2ecc71;">[+]</span> Found 6 NS records
<span style="color: #2ecc71;">[+]</span> Found 2 MX records
<span style="color: #2ecc71;">[+]</span> Found 1 TXT records
<span style="color: #2ecc71;">[+]</span> Found 2 AAAA records
<span style="color: #3498db;">[*]</span> Looking for subdomains via certificates...
<span style="color: #2ecc71;">[+]</span> Found 15 subdomains via certificates
<span style="color: #2ecc71;">[+]</span> Verified 6 active subdomains from certificates
<span style="color: #3498db;">[*]</span> Starting brute-force subdomain discovery...
<span style="color: #2ecc71;">[+]</span> Found 1 subdomains via brute-force
<span style="color: #3498db;">[*]</span> Gathering detailed information about subdomains...
<span style="color: #2ecc71;">[+]</span> Gathered detailed information for 6 subdomains
<span style="color: #2ecc71;">[+]</span> Scanning domain: cia.gov
<span style="color: #2ecc71;">[+]</span> Domain IP addresses: 23.207.8.62, 2600:141b:e800:1088::184d, 2600:141b:e800:108b::184d

DNS MX Records:
+------------+----------------+
| PREFERENCE | EXCHANGE       |
+------------+----------------+
| 10         | mail4.cia.gov. |
+------------+----------------+
| 10         | mail3.cia.gov. |
+------------+----------------+

DNS TXT Records:
+----------------+
| TEXT           |
+----------------+
| v=spf1 mx -all |
+----------------+

DNS AAAA Records:
+---------------------------+
| IP ADDRESS                |
+---------------------------+
| 2600:141b:e800:1088::184d |
+---------------------------+
| 2600:141b:e800:108b::184d |
+---------------------------+

DNS A Records:
+-------------+
| IP ADDRESS  |
+-------------+
| 23.207.8.62 |
+-------------+

DNS SOA Records:
+-----------------+-----------------+------------+---------+-------+---------+---------+
| PRIMARY NS      | ADMIN EMAIL     | SERIAL     | REFRESH | RETRY | EXPIRE  | MINIMUM |
+-----------------+-----------------+------------+---------+-------+---------+---------+
| a1-22.akam.net. | monrpt.cia.gov. | 2015111800 | 7200    | 3600  | 2419200 | 14400   |
+-----------------+-----------------+------------+---------+-------+---------+---------+

DNS NS Records:
+------------------+
| NAMESERVER       |
+------------------+
| a12-65.akam.net. |
+------------------+
| a22-66.akam.net. |
+------------------+
| a3-64.akam.net.  |
+------------------+
| a16-67.akam.net. |
+------------------+
| a13-65.akam.net. |
+------------------+
| a1-22.akam.net.  |
+------------------+

<span style="color: #3498db; font-weight: bold;">Discovered Subdomains (7):</span>
+---------------+----------------+--------------------------------------+---------------------------------------+
| SUBDOMAIN     | IP ADDRESS     | ASN                                  | OPEN SERVICES                         |
+---------------+----------------+--------------------------------------+---------------------------------------+
| crypt.cia.gov | 198.81.129.72  | ASN:7046 Central Intelligence Agency |                                       |
+---------------+----------------+--------------------------------------+---------------------------------------+
| mail3.cia.gov | 12.151.182.158 | ASN:7018 AT&T Services, Inc.         | smtp                                  |
+---------------+----------------+--------------------------------------+---------------------------------------+
| mail4.cia.gov | 12.151.182.219 | ASN:7018 AT&T Services, Inc.         | smtp                                  |
+---------------+----------------+--------------------------------------+---------------------------------------+
| mivsp.cia.gov | 198.81.130.231 | ASN:7046 Central Intelligence Agency |                                       |
+---------------+----------------+--------------------------------------+---------------------------------------+
| res.cia.gov   | 198.81.129.116 | ASN:7046 Central Intelligence Agency |                                       |
+---------------+----------------+--------------------------------------+---------------------------------------+
| www.cia.gov   | 184.30.165.43  | ASN:16625 Akamai Technologies, Inc.  | https: AkamaiGHost title: Invalid URL |
|               |                |                                      |                                       |
|               |                |                                      | http: AkamaiGHost title: Invalid URL  |
+---------------+----------------+--------------------------------------+---------------------------------------+
| www.cia.gov   | 184.30.165.43  | ASN:16625 Akamai Technologies, Inc.  | https: AkamaiGHost title: Invalid URL |
|               |                |                                      |                                       |
|               |                |                                      | http: AkamaiGHost title: Invalid URL  |
+---------------+----------------+--------------------------------------+---------------------------------------+

<span style="color: #3498db; font-weight: bold;">SSL Certificates (6):</span>
+---------------+---------------+-----------------------+--------------------------+
| SUBDOMAIN     | COMMON NAME   | ISSUER                | EXPIRY                   |
+---------------+---------------+-----------------------+--------------------------+
| www.cia.gov   | www.cia.gov   | DigiCert EV RSA CA G2 | Apr 22 23:59:59 2025 GMT |
| res.cia.gov   | res.cia.gov   | Could not obtain      | Could not obtain         |
| mivsp.cia.gov | mivsp.cia.gov | Could not obtain      | Could not obtain         |
| mail3.cia.gov | mail3.cia.gov | Could not obtain      | Could not obtain         |
| mail4.cia.gov | mail4.cia.gov | Could not obtain      | Could not obtain         |
| crypt.cia.gov | crypt.cia.gov | Could not obtain      | Could not obtain         |
+---------------+---------------+-----------------------+--------------------------+
</pre>

## Project Structure

```
.
├── cmd
│   └── main.go            # Application entry point
├── go.mod                 # Go module file
├── go.sum                 # Go module checksum
├── internal
│   ├── asn
│   │   └── lookup.go      # ASN lookup functionality
│   ├── dns
│   │   └── resolver.go    # DNS record retrieval
│   ├── models
│   │   └── models.go      # Data structures
│   ├── output
│   │   ├── console.go     # Console output formatting
│   │   └── json.go        # JSON output
│   ├── scanner
│   │   └── portscanner.go # Port scanning and service detection
│   ├── ssl
│   │   └── certificate.go # SSL certificate handling
│   └── subdomain
│       ├── bruteforce.go  # Brute force subdomain discovery
│       └── certs.go       # Subdomain discovery via certs
└── pkg
    └── utils
        └── utils.go       # Utility functions
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- [miekg/dns](https://github.com/miekg/dns) - DNS library for Go
- [olekukonko/tablewriter](https://github.com/olekukonko/tablewriter) - ASCII table in Go

---

## Author

This tool was developed by Stepan Kutaj (TLDR-IT). For more information or questions, contact me at [stepan.kutaj@tldr-it.com](mailto:stepan.kutaj@tldr-it.com) or visit my website at [www.tldr-it.com](https://www.tldr-it.com).

[![GitHub](https://img.shields.io/github/followers/tldr-it-stepankutaj?label=Follow%20%40tldr-it-stepankutaj&style=social)](https://github.com/tldr-it-stepankutaj)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue?style=social&logo=linkedin)](https://www.linkedin.com/in/stepankutaj)
[![Buy Me a Coffee](https://img.shields.io/badge/Buy%20Me%20a%20Coffee-Support-orange?style=social&logo=buy-me-a-coffee)](https://buymeacoffee.com/stepankutae)

*For educational and legitimate security research purposes only. Always obtain proper authorization before performing reconnaissance on any systems.*
