# Penetration Testing Checklist

## Pre-Engagement

### Scope Verification
- [ ] Review complete scope document (scope.md or target-info.md)
- [ ] Verify all in-scope assets (domains, subdomains, IP ranges, APIs, mobile apps)
- [ ] Confirm out-of-scope assets to avoid
- [ ] Understand prohibited testing actions (DoS, social engineering, physical attacks)
- [ ] Review allowed testing methods
- [ ] Check rate limiting requirements
- [ ] Identify test account credentials
- [ ] Review severity/rewards matrix
- [ ] Understand reporting requirements
- [ ] Note response time expectations
- [ ] Save emergency contact information

### Tool Setup
- [ ] Kali Linux VM configured and updated
- [ ] All reconnaissance tools installed (subfinder, httpx, nuclei, katana, etc.)
- [ ] All exploitation tools installed (sqlmap, dalfox, ffuf, commix, etc.)
- [ ] Burp Suite configured with extensions
- [ ] GitHub Copilot CLI authenticated for MCP
- [ ] Wordlists downloaded (SecLists, OneListForAll)
- [ ] Environment variables set (RATE_LIMIT, MAX_THREADS, TIMEOUT)
- [ ] VPN/proxy configured if required
- [ ] Note-taking system ready (findings.md, recon.md)
- [ ] Screenshot/recording tools ready (gowitness, flameshot, OBS)

### Test Accounts
- [ ] Test user account created and verified
- [ ] Test admin account (if provided)
- [ ] Payment test account (if applicable)
- [ ] API credentials obtained (if applicable)
- [ ] Mobile app test accounts (if applicable)
- [ ] Document all test credentials securely

---

## Phase 1: Reconnaissance

### Passive OSINT
- [ ] Certificate transparency search (crt.sh, certspotter)
- [ ] DNS intelligence (dns.bufferover.run, dnsrecon)
- [ ] Web archive analysis (waybackurls, gau)
- [ ] Search engine dorking (Google, Bing, DuckDuckGo)
- [ ] GitHub secret hunting (search for API keys, passwords, tokens)
- [ ] Shodan/Censys search (org name, domain, SSL certificate)
- [ ] Social media reconnaissance (LinkedIn employees, tech stack mentions)
- [ ] Job postings analysis (technology requirements reveal stack)
- [ ] Company acquisitions/subsidiaries research
- [ ] Whois/domain registration information

### Subdomain Enumeration
- [ ] subfinder (all sources, recursive)
- [ ] assetfinder
- [ ] amass (passive mode)
- [ ] chaos (ProjectDiscovery Chaos dataset)
- [ ] Certificate transparency logs
- [ ] DNS brute forcing (if allowed)
- [ ] Merge and deduplicate all results
- [ ] DNS validation with dnsx
- [ ] Resolve to IP addresses
- [ ] Identify cloud-hosted assets (AWS, GCP, Azure)

### HTTP Probing & Technology Detection
- [ ] Probe for live web services (httpx)
- [ ] Extract status codes
- [ ] Capture page titles
- [ ] Detect technologies (httpx tech-detect)
- [ ] Identify web servers (nginx, Apache, IIS)
- [ ] Screenshot all alive hosts (gowitness, aquatone)
- [ ] Deeper technology fingerprinting (whatweb, wappalyzer)
- [ ] Identify CMS platforms (WordPress, Joomla, Drupal)
- [ ] Detect frameworks (React, Angular, Vue, Django, Laravel)
- [ ] Identify programming languages
- [ ] Note interesting ports/services (8080, 8443, 3000, 9090)

### Port Scanning
- [ ] Fast port discovery (naabu top ports)
- [ ] Comprehensive port scan (nmap -p-)
- [ ] Service version detection (nmap -sV)
- [ ] Default script scan (nmap -sC)
- [ ] Identify unusual services
- [ ] Check for common management ports (22, 3389, 5900, 3306, 5432, 6379, 9200)
- [ ] Test for open databases
- [ ] Check for exposed admin panels
- [ ] Identify API endpoints by port
- [ ] Document all open ports per host

### Web Crawling & Spidering
- [ ] Comprehensive crawling (katana, gospider, hakrawler)
- [ ] Extract all URLs and endpoints
- [ ] Identify URL patterns and structure
- [ ] Discover query parameters
- [ ] Find form endpoints
- [ ] Locate API endpoints
- [ ] Identify authentication pages
- [ ] Find admin/management interfaces
- [ ] Discover upload functionality
- [ ] Map out application structure

### Directory & File Discovery
- [ ] Directory fuzzing (ffuf, feroxbuster)
- [ ] Common file discovery (.git, .env, .sql, .bak, config files)
- [ ] Backup file fuzzing (.old, .bak, ~, .swp)
- [ ] Admin panel discovery (/admin, /administrator, /wp-admin)
- [ ] API documentation (/api-docs, /swagger.json, /openapi.json)
- [ ] Check for exposed Git repositories
- [ ] Test for accessible .env files
- [ ] Look for SQL dumps
- [ ] Find log files (access.log, error.log)
- [ ] Identify debug/test pages

### JavaScript Analysis
- [ ] Discover all JavaScript files (katana -jc, subjs)
- [ ] Download JavaScript files
- [ ] Extract endpoints with LinkFinder
- [ ] Look for hardcoded API keys
- [ ] Find sensitive strings (passwords, tokens, secrets)
- [ ] Identify API endpoints
- [ ] Analyze authentication logic
- [ ] Find hidden parameters
- [ ] Check for source maps (.map files)
- [ ] Deobfuscate minified JavaScript

### Parameter Discovery
- [ ] Extract parameters from archives (waybackurls + unfurl)
- [ ] Active parameter discovery (arjun, paramspider, x8)
- [ ] Parameter fuzzing (ffuf with param wordlist)
- [ ] Check for hidden parameters
- [ ] Test for debug parameters
- [ ] Identify custom parameters
- [ ] Document all discovered parameters
- [ ] Note sensitive parameter names (debug, test, admin, key)

### API Discovery
- [ ] Identify REST API endpoints
- [ ] GraphQL detection (/graphql, /graphiql)
- [ ] SOAP/WSDL discovery
- [ ] WebSocket endpoints
- [ ] Check for API versioning (/v1, /v2, /api/v1)
- [ ] Look for API documentation
- [ ] Test Swagger/OpenAPI specs
- [ ] API route fuzzing (kiterunner)
- [ ] Identify authenticated vs unauthenticated endpoints
- [ ] Document API structure

### Cloud Asset Discovery
- [ ] S3 bucket enumeration
- [ ] Azure Blob Storage discovery
- [ ] Google Cloud Storage buckets
- [ ] Check for public buckets
- [ ] Test bucket permissions
- [ ] Subdomain takeover check (AWS, Azure, Heroku, GitHub Pages)
- [ ] Cloud metadata service access (if applicable)
- [ ] Identify cloud provider (AWS/GCP/Azure)
- [ ] Check for exposed cloud resources
- [ ] Document all cloud assets

---

## Phase 2: Automated Vulnerability Assessment

### Nuclei Scanning
- [ ] Critical/High severity exposures
- [ ] CVE scanning (all years)
- [ ] Misconfiguration detection
- [ ] Technology-specific templates (WordPress, Jenkins, Jira, etc.)
- [ ] Default credentials check
- [ ] Exposed panels detection
- [ ] Information disclosure templates
- [ ] DNS templates
- [ ] SSL/TLS templates
- [ ] Custom templates (if available)
- [ ] Review and validate all findings

### Web Application Scanners
- [ ] Nikto scan
- [ ] Wapiti comprehensive scan
- [ ] Arachni scan (if applicable)
- [ ] CMS-specific scans (wpscan, joomscan, droopescan)
- [ ] Review scanner outputs
- [ ] Validate findings (eliminate false positives)

### SSL/TLS Testing
- [ ] testssl.sh comprehensive test
- [ ] Check supported protocols (SSLv2, SSLv3, TLS 1.0, 1.1, 1.2, 1.3)
- [ ] Weak cipher suites
- [ ] Certificate validation
- [ ] Certificate transparency
- [ ] HSTS header check
- [ ] Mixed content issues
- [ ] Heartbleed vulnerability
- [ ] POODLE vulnerability
- [ ] BEAST vulnerability

### Security Headers Analysis
- [ ] X-Frame-Options (clickjacking protection)
- [ ] X-XSS-Protection
- [ ] X-Content-Type-Options (MIME sniffing)
- [ ] Strict-Transport-Security (HSTS)
- [ ] Content-Security-Policy (CSP)
- [ ] Referrer-Policy
- [ ] Permissions-Policy
- [ ] Cross-Origin-Resource-Policy
- [ ] Cross-Origin-Embedder-Policy
- [ ] Cross-Origin-Opener-Policy

### CORS Testing
- [ ] Test with arbitrary Origin header
- [ ] Check for wildcard origin with credentials
- [ ] Test null origin
- [ ] Subdomain reflection
- [ ] Pre-flight request bypass
- [ ] Credential handling
- [ ] Document CORS misconfigurations

---

## Phase 3: Authentication Testing

### User Enumeration
- [ ] Username enumeration via registration
- [ ] Username enumeration via login (different error messages)
- [ ] Username enumeration via password reset
- [ ] Timing-based enumeration
- [ ] Email enumeration
- [ ] Response code differences
- [ ] Response size differences

### Password Policy Testing
- [ ] Weak password acceptance (123456, password, etc.)
- [ ] Minimum password length
- [ ] Password complexity requirements
- [ ] Password reuse policy
- [ ] Password history check
- [ ] Common password blacklist
- [ ] Password strength meter bypass

### Brute Force Protection
- [ ] Rate limiting on login attempts
- [ ] Account lockout mechanism
- [ ] CAPTCHA implementation
- [ ] IP-based blocking
- [ ] Account unlock mechanism
- [ ] Brute force via different IPs (if ethical)
- [ ] Distributed brute force protection

### SQL Injection in Login
- [ ] `' OR '1'='1`
- [ ] `' OR '1'='1'--`
- [ ] `admin' --`
- [ ] `admin' #`
- [ ] `') OR ('1'='1`
- [ ] Time-based blind SQLi (`' AND SLEEP(5)--`)
- [ ] Error-based SQLi
- [ ] SQLMap on login form

### NoSQL Injection in Login
- [ ] `username[$ne]=admin&password[$ne]=pass`
- [ ] `{"username": {"$ne": null}, "password": {"$ne": null}}`
- [ ] `{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}`
- [ ] MongoDB operator injection
- [ ] Redis command injection

### Authentication Bypass
- [ ] Direct access to protected pages
- [ ] Cookie manipulation
- [ ] Parameter tampering
- [ ] Forced browsing
- [ ] Default credentials
- [ ] Hardcoded credentials
- [ ] Backdoor accounts
- [ ] Magic link vulnerabilities
- [ ] Login CSRF

### JWT Testing
- [ ] Algorithm confusion (RS256 → HS256)
- [ ] None algorithm attack (`"alg":"none"`)
- [ ] Weak secret brute force
- [ ] Claims manipulation (user_id, role, is_admin)
- [ ] Kid parameter injection
- [ ] JKU header manipulation
- [ ] X5U header exploitation
- [ ] Token expiration check
- [ ] Signature verification bypass
- [ ] JWT in URL (exposure risk)

### OAuth/SSO Testing
- [ ] redirect_uri manipulation
- [ ] State parameter CSRF
- [ ] Authorization code replay
- [ ] Scope elevation
- [ ] Open redirect chain
- [ ] Token leakage via Referer
- [ ] Account linking issues
- [ ] Pre-account takeover
- [ ] Race conditions in OAuth flow

### 2FA/MFA Bypass
- [ ] Response manipulation (change false to true)
- [ ] Status code manipulation (404 → 200)
- [ ] Rate limiting on 2FA codes
- [ ] Backup code enumeration
- [ ] Session fixation during 2FA
- [ ] Direct request to post-2FA pages
- [ ] Remember device bypass
- [ ] 2FA code reuse
- [ ] Time-based 2FA prediction
- [ ] Brute force 2FA codes

### Session Management
- [ ] Session fixation
- [ ] Session prediction
- [ ] Session token entropy analysis
- [ ] Concurrent sessions allowed
- [ ] Session timeout testing
- [ ] Session invalidation on logout
- [ ] Session invalidation on password change
- [ ] Cookie security flags (Secure, HttpOnly, SameSite)
- [ ] Session token in URL
- [ ] Session token in Referer

### Password Reset
- [ ] Token prediction/guessing
- [ ] Token expiration check
- [ ] Token reuse after consumption
- [ ] Token not invalidated after password change
- [ ] Host header injection
- [ ] Parameter pollution (multiple emails)
- [ ] Race condition attacks
- [ ] Email parameter tampering
- [ ] Password reset link in HTTP (not HTTPS)
- [ ] Weak token generation

---

## Phase 4: Authorization Testing

### IDOR - Numeric IDs
- [ ] Sequential ID testing (`/user/123` → `/user/124`)
- [ ] Negative IDs (`/user/-1`)
- [ ] Zero ID (`/user/0`)
- [ ] Large numbers (`/user/999999`)
- [ ] Floating point (`/user/1.5`)
- [ ] Test with all HTTP methods (GET, POST, PUT, DELETE, PATCH)
- [ ] Test with missing authentication
- [ ] Test with different user roles

### IDOR - UUIDs/GUIDs
- [ ] Similar resource access
- [ ] UUID enumeration from other endpoints
- [ ] UUID in URL vs body
- [ ] UUID prediction (if weak generation)

### IDOR - Hashed IDs
- [ ] Hash algorithm identification
- [ ] Hash collision
- [ ] Hash reversal (if weak)
- [ ] Similar hash patterns

### IDOR - Encoded IDs
- [ ] Base64 decode, manipulate, re-encode
- [ ] Hex decode, manipulate, re-encode
- [ ] URL decode, manipulate, re-encode

### IDOR - Array/Multiple IDs
- [ ] `user_ids[]=123&user_ids[]=124`
- [ ] `ids=123,124,125`
- [ ] JSON array manipulation

### Horizontal Privilege Escalation
- [ ] User A accessing User B profile
- [ ] User A viewing User B orders
- [ ] User A reading User B messages
- [ ] User A modifying User B data
- [ ] User A deleting User B resources
- [ ] Test across different user types

### Vertical Privilege Escalation
- [ ] User accessing admin endpoints
- [ ] Parameter injection (`role=admin`)
- [ ] Mass assignment (`is_admin=true`)
- [ ] Direct access to admin functions
- [ ] Forced browsing to admin pages
- [ ] Path traversal in authorization (`/api/../../admin/users`)
- [ ] HTTP method tampering (GET allowed, try POST/PUT/DELETE)
- [ ] Missing function-level access control

### Multi-Step Process Authorization
- [ ] Skip steps in workflow
- [ ] Access steps out of order
- [ ] Repeat steps multiple times
- [ ] Parameter tampering between steps
- [ ] Session manipulation between steps

---

## Phase 5: Input Validation Testing

### SQL Injection
- [ ] Error-based detection (`'`, `"`, `;`)
- [ ] Boolean-based blind (`' AND '1'='1`)
- [ ] Time-based blind (`' AND SLEEP(5)--`)
- [ ] Union-based (`' UNION SELECT NULL--`)
- [ ] Stacked queries (`'; DROP TABLE users--`)
- [ ] Second-order SQLi
- [ ] SQLMap comprehensive scan
- [ ] Test all input fields
- [ ] Test all parameters (GET, POST, Cookie, Headers)
- [ ] Test JSON/XML inputs
- [ ] Database-specific payloads (MySQL, PostgreSQL, MSSQL, Oracle)

### XSS - Reflected
- [ ] `<script>alert(1)</script>`
- [ ] `<img src=x onerror=alert(1)>`
- [ ] `<svg onload=alert(1)>`
- [ ] Event handler payloads
- [ ] Context-specific payloads (HTML, JS, attribute, URL)
- [ ] Filter bypass techniques
- [ ] Encoding variations
- [ ] Polyglot payloads
- [ ] Test in all input fields
- [ ] Test in URL parameters
- [ ] Test in HTTP headers (User-Agent, Referer, X-Forwarded-For)

### XSS - Stored
- [ ] Profile information (name, bio, about)
- [ ] Comments/reviews
- [ ] Forum posts
- [ ] Chat messages
- [ ] File names
- [ ] Support tickets
- [ ] Any user-generated content
- [ ] Admin panel stored XSS
- [ ] Check for CSP bypass

### XSS - DOM-Based
- [ ] Analyze JavaScript for sources (location.hash, location.search)
- [ ] Identify sinks (innerHTML, document.write, eval)
- [ ] Test DOM-based payloads
- [ ] Fragment identifier XSS
- [ ] postMessage XSS

### Command Injection
- [ ] `; whoami`
- [ ] `| whoami`
- [ ] `& whoami`
- [ ] `&& whoami`
- [ ] `|| whoami`
- [ ] <code>`whoami`</code>
- [ ] `$(whoami)`
- [ ] Time-based detection (`; sleep 5`)
- [ ] Space bypass (${IFS}, $IFS$9, {cat,/etc/passwd})
- [ ] Quote manipulation
- [ ] Commix tool scan

### XXE - Basic
- [ ] File read (`<!ENTITY xxe SYSTEM "file:///etc/passwd">`)
- [ ] Internal port scanning
- [ ] Blind XXE with OOB
- [ ] XXE via file uploads (SVG, DOCX, XLSX, PDF)
- [ ] SSRF via XXE
- [ ] Billion laughs attack (DoS - only if authorized)
- [ ] Parameter entities

### SSTI - Detection
- [ ] `{{7*7}}`
- [ ] `${7*7}`
- [ ] `<%= 7*7 %>`
- [ ] `${{7*7}}`
- [ ] `#{7*7}`
- [ ] Identify template engine
- [ ] Engine-specific exploitation (Jinja2, Twig, FreeMarker, ERB)
- [ ] RCE via SSTI

### LDAP Injection
- [ ] `*`
- [ ] `*)(&`
- [ ] `*)(uid=*))(|(uid=*`
- [ ] Authentication bypass
- [ ] Data extraction

### XPath Injection
- [ ] `' or '1'='1`
- [ ] `' or ''='`
- [ ] `x' or 1=1 or 'x'='y`
- [ ] Data extraction

### Header Injection
- [ ] CRLF injection (`%0d%0aSet-Cookie:admin=true`)
- [ ] Host header poisoning
- [ ] HTTP response splitting
- [ ] Header parameter tampering

### File Upload - Extension Bypass
- [ ] Double extension (shell.php.jpg)
- [ ] Null byte (shell.php%00.jpg)
- [ ] Case variation (shell.PHP, shell.PhP)
- [ ] Special characters (shell.php%20, shell.php.....)
- [ ] Alternative extensions (.phtml, .php3, .php5, .phar)
- [ ] Windows-specific (shell.php::$DATA)

### File Upload - Content-Type Bypass
- [ ] Change Content-Type to image/jpeg
- [ ] MIME type manipulation
- [ ] Test if validation is client-side only

### File Upload - Magic Byte Bypass
- [ ] Add image magic bytes (GIF89a;)
- [ ] Polyglot files (valid image + valid code)
- [ ] Metadata injection

### File Upload - Path Traversal
- [ ] Filename: `../../../shell.php`
- [ ] Encoded: `..%2F..%2F..%2Fshell.php`
- [ ] Null byte: `../../../shell.php%00.jpg`

### File Upload - Content Testing
- [ ] XXE via SVG upload
- [ ] XSS via SVG upload
- [ ] HTML upload (if rendered)
- [ ] ZIP slip vulnerability

### LFI/RFI
- [ ] Basic LFI (`/etc/passwd`, `/etc/hosts`)
- [ ] Windows LFI (`C:\Windows\win.ini`)
- [ ] PHP wrappers (php://filter, php://input, data://, expect://)
- [ ] Log poisoning
- [ ] /proc/self/environ exploitation
- [ ] Session file inclusion
- [ ] Filter bypass (null byte, encoding, path truncation)
- [ ] RFI testing (if allowed)

### Path Traversal
- [ ] `../../../etc/passwd`
- [ ] `..\..\..\windows\win.ini`
- [ ] Encoding variations
- [ ] Absolute paths
- [ ] OS-specific variations

---

## Phase 6: Business Logic Testing

### Race Conditions
- [ ] Parallel withdrawal from account
- [ ] Simultaneous coupon redemption
- [ ] Parallel vote submission
- [ ] Race in password reset
- [ ] Race in email verification
- [ ] TOCTOU vulnerabilities
- [ ] Use Burp Turbo Intruder

### Price/Quantity Manipulation
- [ ] Negative prices
- [ ] Negative quantities
- [ ] Zero price
- [ ] Decimal abuse (0.001)
- [ ] Integer overflow
- [ ] Currency manipulation
- [ ] Fractional quantities

### Workflow Bypass
- [ ] Skip payment step
- [ ] Skip verification step
- [ ] Access steps out of order
- [ ] Jump to completion
- [ ] State manipulation
- [ ] Forced browsing

### Coupon/Promo Code Testing
- [ ] Code enumeration
- [ ] Code reuse
- [ ] Expired code usage
- [ ] Stack multiple coupons
- [ ] Case sensitivity
- [ ] Special character handling

### Referral System
- [ ] Self-referral
- [ ] Circular referrals
- [ ] Fake referrals
- [ ] Referral count manipulation

### Subscription/Payment
- [ ] Trial extension
- [ ] Subscription status manipulation
- [ ] Payment bypass
- [ ] Downgrade without restrictions
- [ ] Free trial abuse

---

## Phase 7: Server-Side Testing

### SSRF - Basic
- [ ] `http://localhost`
- [ ] `http://127.0.0.1`
- [ ] `http://0.0.0.0`
- [ ] `http://[::1]`
- [ ] Internal IP ranges (10.x, 172.16.x, 192.168.x)
- [ ] Port scanning via SSRF

### SSRF - Cloud Metadata
- [ ] AWS: `http://169.254.169.254/latest/meta-data/`
- [ ] GCP: `http://metadata.google.internal/computeMetadata/v1/`
- [ ] Azure: `http://169.254.169.254/metadata/instance`
- [ ] Retrieve IAM credentials
- [ ] Retrieve instance details

### SSRF - Bypass Techniques
- [ ] Decimal IP encoding
- [ ] Hex IP encoding
- [ ] Octal IP encoding
- [ ] IPv6 format
- [ ] URL schemes (file://, dict://, gopher://)
- [ ] @ character tricks
- [ ] Domain-based bypass (127.0.0.1.nip.io)
- [ ] DNS rebinding

### SSRF - Blind Detection
- [ ] Out-of-band interaction (Burp Collaborator, attacker server)
- [ ] Time-based detection
- [ ] Error message differences

### Insecure Deserialization
- [ ] Identify serialized data (Java: rO0, PHP: O:, Python: \x80)
- [ ] Java: ysoserial gadget chains
- [ ] PHP: phpggc exploitation
- [ ] Python: pickle RCE
- [ ] .NET: ysoserial.net
- [ ] Test all input fields for serialized data

---

## Phase 8: Client-Side Testing

### CSRF
- [ ] Identify state-changing requests
- [ ] Check for CSRF tokens
- [ ] Test token validation (missing, predictable, reusable)
- [ ] Method tampering (POST → GET)
- [ ] Token in URL
- [ ] Token not tied to session
- [ ] Referrer validation bypass
- [ ] SameSite cookie bypass
- [ ] Create CSRF PoC

### Clickjacking
- [ ] Check X-Frame-Options header
- [ ] Test iframe embedding
- [ ] Frame busting bypass
- [ ] Create clickjacking PoC
- [ ] Test sensitive actions (delete account, change settings)

### CORS Misconfiguration
- [ ] Test with arbitrary Origin
- [ ] Wildcard origin with credentials
- [ ] Null origin reflection
- [ ] Subdomain reflection
- [ ] Pre-flight request bypass
- [ ] Create exploitation PoC

### Open Redirect
- [ ] Test redirect parameters (url, redirect, next, return)
- [ ] Bypass filters (@, #, ?, //, \\, %00)
- [ ] Header-based redirect (X-Forwarded-Host)
- [ ] Chain with OAuth token theft

### PostMessage Vulnerabilities
- [ ] Identify postMessage usage
- [ ] Test origin validation
- [ ] Message injection
- [ ] XSS via postMessage
- [ ] Sensitive data leakage

---

## Phase 9: API Security Testing

### REST API
- [ ] Endpoint enumeration
- [ ] Authentication testing
- [ ] Authorization testing (BOLA/IDOR)
- [ ] Parameter pollution
- [ ] Mass assignment
- [ ] Excessive data exposure
- [ ] Rate limiting
- [ ] HTTP method testing (GET, POST, PUT, DELETE, PATCH)
- [ ] API versioning issues
- [ ] Content-Type manipulation

### GraphQL
- [ ] Introspection query
- [ ] Schema enumeration
- [ ] Batching attacks
- [ ] Nested query DoS
- [ ] Field suggestions
- [ ] IDOR in resolvers
- [ ] Query depth limiting
- [ ] Mutation testing
- [ ] Subscription testing

### SOAP/XML-RPC
- [ ] WSDL enumeration
- [ ] XXE in SOAP
- [ ] Parameter tampering
- [ ] Method enumeration

### WebSocket
- [ ] Authentication testing
- [ ] Authorization testing
- [ ] Message injection
- [ ] CSWSH (Cross-Site WebSocket Hijacking)
- [ ] Rate limiting
- [ ] Data validation

---

## Phase 10: Mobile Security (If Applicable)

### Android
- [ ] APK decompilation (apktool, jadx)
- [ ] Hardcoded secrets search
- [ ] Certificate pinning bypass
- [ ] Deep link exploitation
- [ ] Insecure data storage (SharedPreferences, SQLite)
- [ ] Root detection bypass
- [ ] Dynamic analysis (Frida)
- [ ] Network traffic analysis (mitmproxy)
- [ ] AndroidManifest.xml review

### iOS
- [ ] IPA extraction and analysis
- [ ] Class-dump analysis
- [ ] Jailbreak detection bypass
- [ ] Certificate pinning bypass
- [ ] Insecure data storage (NSUserDefaults, Keychain)
- [ ] Deep link exploitation
- [ ] Dynamic analysis (Frida)
- [ ] Network traffic analysis

---

## Phase 11: Reporting

### Vulnerability Documentation
- [ ] Clear title with severity
- [ ] Executive summary
- [ ] Severity rating with CVSS score
- [ ] Vulnerability details (CWE, affected component)
- [ ] Step-by-step reproduction
- [ ] Proof of concept (requests, responses, screenshots)
- [ ] Impact analysis (confidentiality, integrity, availability)
- [ ] Business impact explanation
- [ ] Remediation recommendations
- [ ] Secure code examples
- [ ] References (CWE, OWASP)
- [ ] Timeline

### Quality Assurance
- [ ] Finding is reproducible
- [ ] All PII removed from evidence
- [ ] Screenshots are clear
- [ ] Steps are detailed and accurate
- [ ] Impact is realistic
- [ ] Severity is appropriate
- [ ] Remediation is actionable
- [ ] No duplicate findings
- [ ] Professional language used
- [ ] Grammar and spelling checked

### Submission
- [ ] Report submitted through proper channel
- [ ] Confirmation received
- [ ] Follow up as needed
- [ ] Track triage status
- [ ] Track resolution status
- [ ] Update timeline in findings.md

---

## Post-Exploitation (Only If Authorized)

### Privilege Escalation
- [ ] Further access testing
- [ ] Lateral movement possibilities
- [ ] Data access validation

### Persistence (Only If Authorized)
- [ ] Document methods only
- [ ] Do not implement without explicit permission

### Data Exfiltration (Only If Authorized)
- [ ] Proof of concept only
- [ ] Do not extract real user data
- [ ] Sanitize all evidence

---

## Cleanup & Finalization

### Cleanup
- [ ] Remove test files uploaded
- [ ] Delete test accounts created (if not provided)
- [ ] Remove any shells/backdoors (if applicable)
- [ ] Clear logs if requested
- [ ] Document cleanup actions

### Final Report
- [ ] Executive summary
- [ ] Testing methodology used
- [ ] Scope and limitations
- [ ] All findings documented
- [ ] Statistics (vulns by severity, type)
- [ ] Recommendations
- [ ] Appendices (full technical details)

### Archive
- [ ] Save all findings to findings.md
- [ ] Save reconnaissance data to recon.md
- [ ] Archive screenshots and evidence
- [ ] Save tool outputs
- [ ] Backup notes
- [ ] Git commit all changes
- [ ] Tag version if program complete

---

## Progress Tracking

### Overall Progress
- [ ] Reconnaissance: ____%
- [ ] Automated Scanning: ____%
- [ ] Authentication Testing: ____%
- [ ] Authorization Testing: ____%
- [ ] Input Validation: ____%
- [ ] Business Logic: ____%
- [ ] Server-Side: ____%
- [ ] Client-Side: ____%
- [ ] API Security: ____%
- [ ] Mobile Security: ____%
- [ ] Reporting: ____%

### Findings Summary
- Critical: ___
- High: ___
- Medium: ___
- Low: ___
- Informational: ___
- Total: ___

### Time Tracking
- Start Date: ____________
- End Date: ____________
- Total Hours: ____________
- Findings per Hour: ____________

---

**This checklist ensures comprehensive coverage of all testing phases. Adapt based on scope, technology stack, and target application type.**
