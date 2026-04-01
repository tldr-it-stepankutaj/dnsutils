package httpinfo

import (
	"net/http"
	"regexp"
	"strings"
)

// TechSignature defines a technology detection signature
type TechSignature struct {
	Name     string
	Category string            // "CMS", "Framework", "CDN", "Server", "Analytics", "JavaScript Library", "Security", "E-commerce"
	Headers  map[string]string // header name -> regex pattern to match
	HTML     []string          // regex patterns to search in HTML body
	Meta     map[string]string // meta tag name -> regex pattern
	Cookies  []string          // cookie name patterns
}

// builtinSignatures contains the built-in technology detection database
var builtinSignatures = []TechSignature{
	// ── CMS ──
	{
		Name:     "WordPress",
		Category: "CMS",
		Headers:  map[string]string{"x-powered-by": "(?i)wordpress", "link": "(?i)wp-json"},
		HTML:     []string{`(?i)wp-content/`, `(?i)wp-includes/`, `(?i)/wp-admin/`, `(?i)<meta[^>]+name=["']generator["'][^>]+content=["']WordPress`},
		Meta:     map[string]string{"generator": "(?i)wordpress"},
		Cookies:  []string{"wordpress_", "wp-settings-"},
	},
	{
		Name:     "Drupal",
		Category: "CMS",
		Headers:  map[string]string{"x-drupal-cache": "", "x-generator": "(?i)drupal"},
		HTML:     []string{`(?i)drupal\.js`, `(?i)Drupal\.settings`, `(?i)drupal\.org`, `(?i)/sites/default/files/`},
		Meta:     map[string]string{"generator": "(?i)drupal"},
		Cookies:  []string{"SSESS", "Drupal.visitor"},
	},
	{
		Name:     "Joomla",
		Category: "CMS",
		Headers:  map[string]string{},
		HTML:     []string{`(?i)/media/jui/`, `(?i)/components/com_`, `(?i)<meta[^>]+content=["']Joomla`},
		Meta:     map[string]string{"generator": "(?i)joomla"},
		Cookies:  []string{"joomla_"},
	},
	{
		Name:     "Ghost",
		Category: "CMS",
		Headers:  map[string]string{"x-powered-by": "(?i)ghost"},
		HTML:     []string{`(?i)ghost-url`, `(?i)content/themes/`, `(?i)<meta[^>]+content=["']Ghost`},
		Meta:     map[string]string{"generator": "(?i)ghost"},
		Cookies:  []string{"ghost-admin-api-session"},
	},

	// ── Frameworks ──
	{
		Name:     "React",
		Category: "Framework",
		HTML:     []string{`(?i)react\.production\.min\.js`, `(?i)data-reactroot`, `(?i)__NEXT_DATA__`, `(?i)react-dom`},
	},
	{
		Name:     "Angular",
		Category: "Framework",
		HTML:     []string{`(?i)ng-version=`, `(?i)ng-app=`, `(?i)angular\.min\.js`, `(?i)<app-root[^>]*>`},
	},
	{
		Name:     "Vue.js",
		Category: "Framework",
		HTML:     []string{`(?i)vue\.min\.js`, `(?i)vue\.runtime`, `(?i)data-v-[a-f0-9]`, `(?i)__vue__`},
	},
	{
		Name:     "Next.js",
		Category: "Framework",
		Headers:  map[string]string{"x-powered-by": "(?i)next\\.js"},
		HTML:     []string{`(?i)__NEXT_DATA__`, `(?i)/_next/static/`, `(?i)next/dist/`},
	},
	{
		Name:     "Django",
		Category: "Framework",
		Headers:  map[string]string{"x-frame-options": "(?i)SAMEORIGIN"},
		HTML:     []string{`(?i)csrfmiddlewaretoken`, `(?i)__admin_media_prefix__`},
		Cookies:  []string{"csrftoken", "django_language"},
	},
	{
		Name:     "Laravel",
		Category: "Framework",
		Headers:  map[string]string{"x-powered-by": "(?i)laravel"},
		Cookies:  []string{"laravel_session", "XSRF-TOKEN"},
	},
	{
		Name:     "Ruby on Rails",
		Category: "Framework",
		Headers:  map[string]string{"x-powered-by": "(?i)phusion passenger", "x-runtime": ""},
		HTML:     []string{`(?i)csrf-token`, `(?i)data-turbolinks-track`},
		Cookies:  []string{"_rails_", "_session_id"},
	},
	{
		Name:     "Spring",
		Category: "Framework",
		Headers:  map[string]string{"x-application-context": ""},
		Cookies:  []string{"JSESSIONID"},
	},

	// ── CDN ──
	{
		Name:     "Cloudflare",
		Category: "CDN",
		Headers:  map[string]string{"cf-ray": "", "cf-cache-status": "", "server": "(?i)cloudflare"},
		Cookies:  []string{"__cfduid", "__cf_bm"},
	},
	{
		Name:     "Akamai",
		Category: "CDN",
		Headers:  map[string]string{"x-akamai-transformed": "", "x-akamai-request-id": "", "server": "(?i)akamai"},
	},
	{
		Name:     "Fastly",
		Category: "CDN",
		Headers:  map[string]string{"x-fastly-request-id": "", "via": "(?i)varnish", "x-served-by": "(?i)cache-"},
	},
	{
		Name:     "AWS CloudFront",
		Category: "CDN",
		Headers:  map[string]string{"x-amz-cf-id": "", "x-amz-cf-pop": "", "via": "(?i)cloudfront", "server": "(?i)cloudfront"},
	},

	// ── Server ──
	{
		Name:     "nginx",
		Category: "Server",
		Headers:  map[string]string{"server": "(?i)^nginx"},
	},
	{
		Name:     "Apache",
		Category: "Server",
		Headers:  map[string]string{"server": "(?i)^apache"},
	},
	{
		Name:     "Microsoft IIS",
		Category: "Server",
		Headers:  map[string]string{"server": "(?i)microsoft-iis", "x-powered-by": "(?i)asp\\.net"},
	},
	{
		Name:     "LiteSpeed",
		Category: "Server",
		Headers:  map[string]string{"server": "(?i)litespeed"},
	},
	{
		Name:     "Caddy",
		Category: "Server",
		Headers:  map[string]string{"server": "(?i)^caddy"},
	},

	// ── Analytics ──
	{
		Name:     "Google Analytics",
		Category: "Analytics",
		HTML:     []string{`(?i)google-analytics\.com/analytics\.js`, `(?i)googletagmanager\.com/gtag/`, `(?i)ga\('create'`, `(?i)_gaq\.push`},
	},
	{
		Name:     "Google Tag Manager",
		Category: "Analytics",
		HTML:     []string{`(?i)googletagmanager\.com/gtm\.js`, `(?i)GTM-[A-Z0-9]+`},
	},
	{
		Name:     "Facebook Pixel",
		Category: "Analytics",
		HTML:     []string{`(?i)connect\.facebook\.net/.*/fbevents\.js`, `(?i)fbq\('init'`},
	},
	{
		Name:     "Hotjar",
		Category: "Analytics",
		HTML:     []string{`(?i)static\.hotjar\.com`, `(?i)hotjar\.com/c/hotjar-`},
	},

	// ── Security ──
	{
		Name:     "ModSecurity",
		Category: "Security",
		Headers:  map[string]string{"server": "(?i)mod_security", "x-modsecurity": ""},
	},
	{
		Name:     "Sucuri",
		Category: "Security",
		Headers:  map[string]string{"x-sucuri-id": "", "server": "(?i)sucuri", "x-sucuri-cache": ""},
	},
	{
		Name:     "Imperva",
		Category: "Security",
		Headers:  map[string]string{"x-iinfo": "", "x-cdn": "(?i)imperva|incapsula"},
		Cookies:  []string{"incap_ses_", "visid_incap_"},
	},

	// ── E-commerce ──
	{
		Name:     "Shopify",
		Category: "E-commerce",
		Headers:  map[string]string{"x-shopid": "", "x-shopify-stage": "", "x-sorting-hat-shopid": ""},
		HTML:     []string{`(?i)cdn\.shopify\.com`, `(?i)Shopify\.theme`},
		Cookies:  []string{"_shopify_s", "_shopify_y"},
	},
	{
		Name:     "WooCommerce",
		Category: "E-commerce",
		HTML:     []string{`(?i)woocommerce`, `(?i)wc-add-to-cart`, `(?i)wp-content/plugins/woocommerce`},
		Meta:     map[string]string{"generator": "(?i)woocommerce"},
	},
	{
		Name:     "Magento",
		Category: "E-commerce",
		Headers:  map[string]string{"x-magento-vary": ""},
		HTML:     []string{`(?i)mage/cookies`, `(?i)Magento_Ui`, `(?i)/static/version`, `(?i)magento\.com`},
		Cookies:  []string{"PHPSESSID", "mage-cache-storage"},
	},
}

// DetectTechnologies analyzes an HTTP response and body for known technology signatures.
// It returns a deduplicated list of detected technologies with their categories.
func DetectTechnologies(resp *http.Response, body string) []string {
	seen := make(map[string]bool)
	var results []string

	for _, sig := range builtinSignatures {
		if seen[sig.Name] {
			continue
		}

		if matchSignature(resp, body, &sig) {
			seen[sig.Name] = true
			results = append(results, sig.Category+": "+sig.Name)
		}
	}

	return results
}

// matchSignature checks whether a single technology signature matches the response
func matchSignature(resp *http.Response, body string, sig *TechSignature) bool {
	// Check headers
	if matchHeaders(resp, sig.Headers) {
		return true
	}

	// Check HTML body patterns
	if matchHTML(body, sig.HTML) {
		return true
	}

	// Check meta tag patterns
	if matchMeta(body, sig.Meta) {
		return true
	}

	// Check cookies
	if matchCookies(resp, sig.Cookies) {
		return true
	}

	return false
}

// matchHeaders checks response headers against signature header patterns
func matchHeaders(resp *http.Response, headers map[string]string) bool {
	if resp == nil || len(headers) == 0 {
		return false
	}

	for name, pattern := range headers {
		value := resp.Header.Get(name)
		if value == "" {
			continue
		}

		// Empty pattern means presence is enough
		if pattern == "" {
			return true
		}

		re, err := regexp.Compile(pattern)
		if err != nil {
			continue
		}
		if re.MatchString(value) {
			return true
		}
	}

	return false
}

// matchHTML checks body content against HTML regex patterns
func matchHTML(body string, patterns []string) bool {
	if body == "" || len(patterns) == 0 {
		return false
	}

	for _, pattern := range patterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			continue
		}
		if re.MatchString(body) {
			return true
		}
	}

	return false
}

// matchMeta checks HTML meta tags against signature patterns
func matchMeta(body string, meta map[string]string) bool {
	if body == "" || len(meta) == 0 {
		return false
	}

	for name, pattern := range meta {
		// Match <meta name="..." content="..."> or <meta content="..." name="...">
		metaRe := regexp.MustCompile(`(?i)<meta[^>]+name=["']` + regexp.QuoteMeta(name) + `["'][^>]+content=["']([^"']+)["']`)
		matches := metaRe.FindStringSubmatch(body)
		if len(matches) < 2 {
			// Try reverse attribute order
			metaRe = regexp.MustCompile(`(?i)<meta[^>]+content=["']([^"']+)["'][^>]+name=["']` + regexp.QuoteMeta(name) + `["']`)
			matches = metaRe.FindStringSubmatch(body)
		}
		if len(matches) >= 2 {
			if pattern == "" {
				return true
			}
			re, err := regexp.Compile(pattern)
			if err != nil {
				continue
			}
			if re.MatchString(matches[1]) {
				return true
			}
		}
	}

	return false
}

// matchCookies checks response cookies against signature cookie name patterns
func matchCookies(resp *http.Response, cookiePatterns []string) bool {
	if resp == nil || len(cookiePatterns) == 0 {
		return false
	}

	cookies := resp.Cookies()
	if len(cookies) == 0 {
		return false
	}

	for _, pattern := range cookiePatterns {
		for _, cookie := range cookies {
			if strings.Contains(strings.ToLower(cookie.Name), strings.ToLower(pattern)) {
				return true
			}
		}
	}

	return false
}
