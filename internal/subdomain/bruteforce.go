package subdomain

import (
	"bufio"
	"fmt"
	"os"
	"sync"
)

// BruteFinder handles brute-force subdomain discovery
type BruteFinder struct {
	MaxConcurrent int
}

// NewBruteFinder creates a new brute-force subdomain finder
func NewBruteFinder() *BruteFinder {
	return &BruteFinder{
		MaxConcurrent: 40,
	}
}

// SubdomainResult represents a found subdomain
type SubdomainResult struct {
	Name string
	IP   string
}

// BruteForceSubdomains finds subdomains using brute force
func (bf *BruteFinder) BruteForceSubdomains(domain string, wordlistFile string) []SubdomainResult {
	var results []SubdomainResult

	// Get prefixes to test
	prefixes := bf.getSubdomainPrefixes(wordlistFile)

	// Create a channel for results
	resultChan := make(chan *SubdomainResult)

	// Create a wait group to track goroutines
	var wg sync.WaitGroup

	// Create semaphore for concurrency control
	sem := make(chan struct{}, bf.MaxConcurrent)

	// Create a CertFinder to use its CheckSubdomain method
	certFinder := NewCertFinder()

	// Launch goroutines for each prefix
	for _, prefix := range prefixes {
		wg.Add(1)
		go func(prefix string) {
			defer wg.Done()

			// Acquire semaphore
			sem <- struct{}{}
			defer func() { <-sem }()

			subdomain := fmt.Sprintf("%s.%s", prefix, domain)
			name, ip, err := certFinder.CheckSubdomain(subdomain)
			if err == nil {
				resultChan <- &SubdomainResult{
					Name: name,
					IP:   ip,
				}
			} else {
				resultChan <- nil
			}
		}(prefix)
	}

	// Collect results in a separate goroutine
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Process results
	for result := range resultChan {
		if result != nil {
			results = append(results, *result)
		}
	}

	return results
}

// getSubdomainPrefixes gets prefixes to use for subdomain brute forcing
func (bf *BruteFinder) getSubdomainPrefixes(wordlistFile string) []string {
	// Default common prefixes (~500 entries for comprehensive subdomain brute-force)
	commonPrefixes := []string{
		// Standard
		"www", "mail", "ftp", "smtp", "pop", "pop3", "imap", "ns1", "ns2", "ns3", "ns4",
		"dns", "dns1", "dns2", "mx", "mx1", "mx2",
		// Web
		"web", "www1", "www2", "www3", "portal", "app", "api", "api2", "api3",
		"static", "assets", "cdn", "media", "img", "images", "files", "download", "upload",
		"content", "cache", "edge", "origin", "ww1", "ww2", "web1", "web2",
		// Dev / Staging
		"dev", "development", "staging", "stage", "test", "testing", "qa", "uat",
		"sandbox", "demo", "beta", "alpha", "preview", "canary", "nightly",
		"dev1", "dev2", "dev3", "stage1", "stage2", "test1", "test2", "qa1", "qa2",
		"preprod", "pre-prod", "pre", "integration", "int",
		// Infrastructure
		"vpn", "vpn1", "vpn2", "remote", "gateway", "gw", "gw1", "gw2",
		"proxy", "proxy1", "proxy2", "lb", "lb1", "lb2", "load", "balancer",
		"firewall", "fw", "fw1", "router", "router1", "switch", "switch1",
		"nas", "nas1", "backup", "backup1", "backup2", "bak",
		"monitor", "monitoring", "nagios", "zabbix", "grafana", "kibana",
		"elastic", "prometheus", "alertmanager", "pagerduty",
		"jenkins", "ci", "cd", "build", "deploy", "ansible", "puppet", "chef", "terraform",
		"salt", "rundeck", "octopus", "argo", "argocd", "drone", "circleci", "travis",
		"server", "server1", "server2", "host", "host1", "host2",
		// Internal / Admin
		"intranet", "internal", "corp", "corporate", "extranet", "private", "secure",
		"admin", "administrator", "manage", "management", "panel", "dashboard",
		"console", "control", "cp", "cpanel", "whm", "webmail",
		"adm", "sysadmin", "ops", "devops", "infra", "staff",
		// Database
		"db", "db1", "db2", "db3", "database", "mysql", "mysql1",
		"postgres", "postgresql", "pgsql", "mongo", "mongodb",
		"redis", "redis1", "elasticsearch", "es", "es1",
		"memcache", "memcached", "cassandra", "couchdb", "mariadb",
		"influxdb", "neo4j", "dynamodb", "rds", "sql", "sql1", "mssql", "oracle",
		// Messaging / Communication
		"chat", "slack", "teams", "meet", "conference", "webex", "zoom", "jitsi",
		"matrix", "mattermost", "rocketchat", "irc", "xmpp", "jabber",
		"voip", "sip", "pbx", "asterisk", "phone", "tel", "call",
		// Mail (extended)
		"mail", "mail1", "mail2", "mail3", "mail4", "email",
		"exchange", "owa", "autodiscover", "autoconfig", "postfix",
		"mailgw", "mailgateway", "relay", "relay1", "mta",
		"spam", "spamfilter", "barracuda", "proofpoint",
		// Auth / Identity
		"auth", "auth1", "oauth", "oauth2", "sso", "login", "signin", "signup",
		"register", "identity", "id", "cas", "ldap", "ad", "saml",
		"okta", "keycloak", "auth0", "duo", "mfa", "2fa", "radius",
		"accounts", "account", "myaccount", "profile",
		// Cloud / Containers
		"cloud", "cloud1", "cloud2", "k8s", "kubernetes", "kube",
		"docker", "registry", "harbor", "rancher", "openshift", "swarm",
		"node", "node1", "node2", "node3", "worker", "worker1", "worker2",
		"master", "master1", "cluster", "cluster1",
		"aws", "azure", "gcp", "gcloud", "heroku", "digitalocean", "linode",
		"ec2", "ecs", "eks", "aks", "gke", "lambda", "serverless",
		// Services / API
		"rest", "graphql", "grpc", "ws", "websocket", "socket",
		"realtime", "push", "notification", "notify", "webhook", "hooks",
		"events", "stream", "streaming", "feed", "rss", "atom",
		"search", "solr", "sphinx",
		// Storage
		"s3", "storage", "blob", "share", "nfs", "ftp", "sftp", "scp",
		"rsync", "minio", "ceph", "gluster", "swift", "oss",
		"data", "data1", "data2", "archive", "archives",
		// Security
		"waf", "ids", "ips", "siem", "soc", "vault", "vault1",
		"cert", "certs", "pki", "ca", "ocsp", "crl",
		"security", "sec", "scan", "scanner", "pentest",
		"splunk", "sentinel", "crowdstrike", "carbon",
		// Blogs / Content / Community
		"blog", "blogs", "forum", "forums", "community", "wiki",
		"docs", "doc", "documentation", "help", "support", "faq",
		"kb", "knowledgebase", "learn", "training", "academy", "edu",
		"news", "press", "pr", "updates", "changelog",
		// Business / Commerce
		"shop", "store", "ecommerce", "cart", "checkout", "pay",
		"payment", "payments", "billing", "invoice", "invoices",
		"crm", "erp", "hr", "finance", "accounting",
		"sales", "marketing", "leads", "pipeline",
		"order", "orders", "catalog", "product", "products",
		// Ticket / Project Management
		"ticket", "tickets", "jira", "confluence", "trello",
		"asana", "notion", "basecamp", "monday", "clickup",
		"project", "projects", "task", "tasks", "pm",
		"helpdesk", "servicedesk", "freshdesk", "zendesk", "intercom",
		// Code / VCS
		"gitlab", "github", "bitbucket", "git", "git1", "svn", "repo",
		"repos", "repository", "code", "codereview", "review",
		"gerrit", "phabricator", "sourcecode",
		// Status / Monitoring
		"status", "health", "healthcheck", "ping", "uptime",
		"statuspage", "incidents", "metrics", "stats", "analytics",
		"apm", "trace", "tracing", "jaeger", "zipkin", "datadog", "newrelic",
		// Misc / General
		"info", "about", "career", "careers", "jobs", "job",
		"m", "mobile", "wap",
		"old", "new", "legacy", "v1", "v2", "v3",
		"go", "link", "links", "redirect", "short", "url",
		"lab", "labs", "research", "r", "d",
		"it", "tech", "engineering", "platform",
		"reports", "report", "log", "logs", "logging", "syslog",
		"ssh", "rdp", "vnc", "terminal", "shell", "bastion", "jump",
		"config", "configuration", "setup", "install",
		"license", "licensing", "activate", "activation",
		"partner", "partners", "affiliate", "affiliates", "reseller",
		"vendor", "suppliers", "procurement",
		"map", "maps", "geo", "gis", "location",
		"video", "videos", "audio", "podcast", "live", "tv", "radio",
		"calendar", "schedule", "booking", "reserve", "reservation",
		"survey", "surveys", "poll", "feedback", "review", "reviews",
		"image", "photo", "photos", "gallery", "assets1",
		"api-gateway", "api-gw", "apigw",
		"staging-api", "dev-api", "test-api",
		"sentry", "bugsnag", "rollbar", "errortracking",
		"queue", "rabbit", "rabbitmq", "kafka", "activemq", "sqs", "celery",
		"proxy-east", "proxy-west", "us", "eu", "ap", "us-east", "us-west",
		"eu-west", "eu-central", "ap-south", "ap-east",
		"cname", "origin-www", "origin-api",
		"autodiscover", "lyncdiscover", "sip", "enterpriseregistration",
		"enterpriseenrollment", "msoid", "selector1", "selector2",
		"dkim", "dmarc", "spf",
		"ns", "time", "ntp", "ntp1", "ntp2", "clock",
		"smtp1", "smtp2", "imap1", "imap2", "pop1", "pop2",
		"bbs", "1", "2", "3", "4", "5", "10", "20", "100",
	}

	// If wordlist file is provided, use it
	if wordlistFile != "" {
		file, err := os.Open(wordlistFile)
		if err == nil {
			defer file.Close()

			var prefixes []string
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				prefixes = append(prefixes, scanner.Text())
			}

			if len(prefixes) > 0 {
				return prefixes
			}
		}
	}

	return commonPrefixes
}
