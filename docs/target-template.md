# Target Information Template

> **Instructions:** Copy this template when starting a new bug bounty program or TryHackMe room. Fill in all sections with complete details.

---

## Program Overview

### Basic Information
- **Program Name:** [Company Name / TryHackMe Room Name]
- **Platform:** [HackerOne / Bugcrowd / Synack / TryHackMe / Other]
- **Profile URL:** [Direct link to program page]
- **Launch Date:** [When program started]
- **Testing Start Date:** [When you started testing]
- **Program Type:** [Public / Private / Invite Only / CTF]
- **Program Status:** [Active / Paused / Closed]

### Program Maturity
- **Response Time:** [Typical time to first response]
- **Payment Time:** [Typical time to payment]
- **Acceptance Rate:** [Percentage of valid reports accepted]
- **Total Bounties Paid:** [If publicly available]
- **Reputation:** [Low / Medium / High / Excellent]

### Contact Information
- **Primary Contact:** [Email or platform messaging]
- **Security Email:** security@company.com
- **Emergency Contact:** [If provided]
- **PGP Key:** [If encryption required]
- **Response Hours:** [Business hours, timezone]

---

## Scope

### In-Scope Assets

#### Web Applications
| Asset | Description | Environment | Authentication |
|-------|-------------|-------------|----------------|
| https://example.com | Main application | Production | Required |
| https://app.example.com | Web application | Production | Required |
| https://api.example.com | REST API | Production | API key required |
| https://admin.example.com | Admin panel | Production | Admin access |

#### API Endpoints
- `https://api.example.com/v1/*` - API version 1
- `https://api.example.com/v2/*` - API version 2
- `https://api.example.com/graphql` - GraphQL endpoint

#### Mobile Applications
- **Android:** [Package name / Play Store link]
  - Version: X.X.X
  - Min SDK: XX
- **iOS:** [Bundle ID / App Store link]
  - Version: X.X.X
  - Min iOS: XX.X

#### IP Ranges & Networks
- `203.0.113.0/24` - Production infrastructure
- `198.51.100.0/24` - Development infrastructure

#### Subdomains
- `*.example.com` - All subdomains (wildcard scope)
- Explicitly in scope:
  - www.example.com
  - app.example.com
  - api.example.com
  - staging.example.com
  - dev.example.com

#### Other Assets
- Desktop applications
- Browser extensions
- IoT devices
- Cloud storage buckets

### Out-of-Scope Assets

#### Explicitly Excluded
- old.example.com - Decommissioned application
- partner.example.com - Third-party managed
- test.example.com - Test environment (not maintained)
- legacy.example.com - Legacy system (being retired)

#### Third-Party Services
- cdn.cloudflare.com
- s3.amazonaws.com (unless company-specific bucket)
- Google Analytics
- Social media accounts

#### Specific Exclusions
- Physical offices / facilities
- Employee personal accounts
- Company social media accounts (unless specified)

---

## Testing Rules

### Allowed Testing Methods
- ✅ Automated scanning (with rate limiting)
- ✅ Manual penetration testing
- ✅ Source code review (if accessible)
- ✅ Authenticated testing (with test accounts)
- ✅ Subdomain enumeration
- ✅ Port scanning
- ✅ File fuzzing
- ✅ Password testing (test accounts only)
- ✅ Business logic testing
- ✅ API testing

### Prohibited Actions
- ❌ **Denial of Service (DoS/DDoS)** - Any action causing service disruption
- ❌ **Physical attacks** - No physical access attempts
- ❌ **Social engineering** - No phishing, pretexting, or manipulation of staff
- ❌ **Spam** - No email spam or excessive communications
- ❌ **Destructive testing** - No DELETE operations on production data
- ❌ **Accessing other users' data** - Beyond minimal PoC required
- ❌ **Automated account creation** - Unless explicitly allowed
- ❌ **Brute force attacks** - Excessive login attempts (limit: 3-5 attempts)
- ❌ **Testing third-party integrations** - Unless they're in scope
- ❌ **Publicly disclosing vulnerabilities** - Before program approval

### Rate Limiting Requirements
- **Default Rate Limit:** 10 requests per second
- **Burst Allowed:** Up to 50 requests in 5-second window
- **Daily Limit:** No specific limit, but be reasonable
- **Scanner Throttling:** Use `--rate-limit` flags with tools
- **Respect 429 responses:** Back off if rate limited

### Test Accounts Provided
| Account Type | Username/Email | Password | 2FA | Notes |
|--------------|----------------|----------|-----|-------|
| Standard User | test1@example.com | TestPass123! | No | Basic access |
| Premium User | test2@example.com | TestPass456! | Yes | Premium features |
| Admin User | admin@example.com | AdminPass789! | Yes | Full admin access |
| API Key | test-api-key | sk_test_abc123... | N/A | API testing |

**Notes on Test Accounts:**
- Only use provided test accounts
- Do not create new accounts without permission
- Do not test with real user accounts
- Report if test accounts are insufficient for testing

---

## Vulnerability Scope

### In-Scope Vulnerability Types

#### Critical Priority
- Remote Code Execution (RCE)
- SQL Injection
- Authentication bypass
- Privilege escalation (vertical)
- Critical IDOR exposing sensitive data
- Server-Side Request Forgery (SSRF) to cloud metadata
- Insecure deserialization leading to RCE
- XXE with file read or SSRF

#### High Priority
- Stored/Persistent XSS
- Significant IDOR (PII exposure)
- JWT vulnerabilities
- OAuth misconfigurations
- 2FA bypass
- SSRF (non-cloud metadata)
- Insecure direct object references
- File upload vulnerabilities (RCE potential)
- Business logic flaws with financial impact

#### Medium Priority
- Reflected XSS
- CSRF on important functions
- Open redirect
- CORS misconfiguration
- Host header injection
- CRLF injection
- Information disclosure (moderate impact)
- Missing rate limiting on critical endpoints

#### Low Priority
- Clickjacking
- CSRF on low-impact functions
- Information disclosure (minor impact)
- Missing security headers
- SSL/TLS configuration issues
- Verbose error messages

### Out-of-Scope / Won't Accept

#### Explicitly Not Accepted
- ❌ Self-XSS (unless you can demonstrate exploitation)
- ❌ Clickjacking on pages without sensitive actions
- ❌ Missing security headers (unless leading to exploitation)
- ❌ SSL/TLS best practices (unless critical vulnerability)
- ❌ Descriptive error messages (unless leaking sensitive data)
- ❌ Host header injection without impact
- ❌ Open redirect (unless chained with token theft)
- ❌ CSRF on logout
- ❌ SPF/DMARC/DKIM issues
- ❌ Publicly accessible login pages
- ❌ User enumeration (unless leading to account takeover)
- ❌ Password policy issues (unless critically weak)
- ❌ Denial of Service vulnerabilities
- ❌ Physical security issues
- ❌ Social engineering attacks
- ❌ Vulnerabilities in third-party services
- ❌ Issues requiring outdated browsers
- ❌ Issues requiring user interaction beyond normal use

#### Conditional Acceptance
- XSS requiring user interaction: Medium → Low
- IDOR with limited impact: High → Medium
- Open redirect chained with OAuth: Low → High
- Information disclosure leading to exploitation: Low → High

---

## Severity & Rewards

### Bounty Table
| Severity | CVSS Score | Bounty Range | Examples |
|----------|------------|--------------|----------|
| Critical | 9.0-10.0 | $5,000 - $20,000 | RCE, Auth bypass (admin) |
| High | 7.0-8.9 | $1,000 - $5,000 | SQLi, Stored XSS, IDOR (PII) |
| Medium | 4.0-6.9 | $250 - $1,000 | Reflected XSS, CSRF, CORS |
| Low | 0.1-3.9 | $50 - $250 | Clickjacking, Info disclosure |

### Bonus Rewards
- **First to report:** +20% bonus
- **Detailed write-up:** +10% bonus
- **Working PoC/exploit:** +15% bonus
- **Remediation assistance:** +10% bonus
- **Multiple unique vulnerabilities:** Potential bonus

### Payment Methods
- HackerOne platform (direct deposit)
- PayPal
- Bitcoin/Cryptocurrency
- Wire transfer (for high bounties)

### Payment Timeline
- **Triage:** 1-3 business days
- **Validation:** 3-7 business days
- **Fix deployment:** 7-30 days (depending on severity)
- **Bounty decision:** Within 14 days of fix
- **Payment processing:** 7-14 days after approval

---

## Reporting Requirements

### Required Information
- **Clear title** with severity and vulnerability type
- **Executive summary** (2-3 sentences)
- **Vulnerability classification** (CWE, OWASP category)
- **Affected component** (URL, parameter, endpoint)
- **Step-by-step reproduction** (numbered, detailed)
- **Proof of concept** (HTTP requests, screenshots, video)
- **Impact analysis** (confidentiality, integrity, availability)
- **Remediation recommendations**
- **CVSS score** with justification

### Quality Standards
- Reports must be reproducible
- Screenshots must be clear
- Requests/responses must be complete
- Sensitive data must be sanitized (no real user PII)
- Professional language required
- No duplicate submissions
- No automated scanner reports without validation

### Reporting Channel
- **Primary:** HackerOne platform submission
- **Email:** security@example.com (encrypted with PGP)
- **Emergency:** [Phone number] for critical vulnerabilities only

### Response SLA
- **Critical:** 24 hours
- **High:** 3 business days
- **Medium:** 5 business days
- **Low:** 7 business days

---

## Technology Stack

### Known Technologies
| Category | Technology | Version | Notes |
|----------|------------|---------|-------|
| Web Server | nginx | 1.21.x | Reverse proxy |
| Application | Node.js | 16.x | Backend API |
| Frontend | React | 17.x | SPA |
| Database | PostgreSQL | 13.x | Primary DB |
| Cache | Redis | 6.x | Session storage |
| CDN | Cloudflare | - | DDoS protection |
| Cloud | AWS | - | EC2, S3, RDS |

### Framework Stack
- **Backend:** Express.js, Sequelize ORM
- **Frontend:** React, Redux, Material-UI
- **API:** REST, GraphQL (Apollo)
- **Authentication:** JWT, OAuth 2.0
- **Authorization:** Role-based (RBAC)

### Third-Party Integrations
- Stripe (payment processing)
- SendGrid (email delivery)
- Twilio (SMS/2FA)
- AWS S3 (file storage)
- Google Analytics (tracking)

### Security Measures
- WAF: Cloudflare
- Rate limiting: Application-level
- SIEM: [System name]
- 2FA: TOTP-based
- Password hashing: bcrypt

---

## Attack Surface Analysis

### Priority Assets (Test First)
1. **Admin Panel** (admin.example.com)
   - High value target
   - Multiple auth vulnerabilities possible
   - Privilege escalation potential

2. **API Endpoints** (api.example.com)
   - REST API with IDOR potential
   - GraphQL endpoint (introspection, batching)
   - Authentication/authorization bypass

3. **Payment Flow** (example.com/checkout)
   - Business logic flaws
   - Price manipulation
   - Race conditions

4. **User Profile** (example.com/profile)
   - Stored XSS potential
   - IDOR vulnerabilities
   - Account takeover vectors

5. **File Upload** (example.com/upload)
   - RCE potential
   - Path traversal
   - XXE in file parsing

### Historical Vulnerability Patterns
Based on disclosed reports:
- Multiple IDOR findings in 2023 (API endpoints)
- Stored XSS in user profiles (fixed 2023-06)
- SSRF in image processing (fixed 2023-09)
- JWT weak secret (fixed 2024-01)

**Patterns suggest:**
- Authorization checks may be inconsistent
- User input validation needs review
- Focus on API security

---

## Testing Strategy

### Phase 1: Reconnaissance (Day 1-2)
- Subdomain enumeration
- Port scanning
- Technology fingerprinting
- Directory/file discovery
- JavaScript analysis
- API endpoint discovery

### Phase 2: Automated Scanning (Day 2-3)
- Nuclei comprehensive scan
- Web vulnerability scanners
- SSL/TLS testing
- Security header analysis

### Phase 3: Manual Testing (Day 3-7)
- Authentication testing
- Authorization testing (IDOR focus)
- Input validation (SQLi, XSS, etc.)
- Business logic flaws
- API security testing
- File upload testing

### Phase 4: Advanced Exploitation (Day 7-10)
- Chaining vulnerabilities
- Privilege escalation
- Complex business logic
- Race conditions
- Advanced SSRF scenarios

### Phase 5: Documentation & Reporting (Day 10+)
- Prepare comprehensive reports
- Calculate accurate CVSS scores
- Create PoC materials
- Submit findings
- Follow up on triage

### Estimated Timeline
- **Total Duration:** 10-14 days
- **Expected Findings:** 5-10 vulnerabilities
- **Estimated Bounty:** $3,000 - $10,000
- **Time Investment:** 60-80 hours

---

## Notes & Observations

### Program Insights
- Response times are excellent (usually within 24 hours)
- Security team is knowledgeable and collaborative
- Bounties paid promptly
- Open to PoC code and detailed analysis
- Accepts borderline findings if well-documented

### Testing Challenges
- Rate limiting is strict (respect 10 req/sec)
- WAF blocks common scanner patterns (use manual techniques)
- 2FA on all test accounts (keep TOTP tokens ready)
- Staging environment has different vulnerabilities than production

### Opportunities
- API security seems overlooked
- GraphQL endpoint not well-tested
- Mobile app has fewer testers
- Business logic less explored

### Red Flags
- None identified yet
- Professional and responsive team

---

## Progress Tracking

### Testing Progress
- [ ] Reconnaissance complete
- [ ] Automated scanning complete
- [ ] Authentication testing complete
- [ ] Authorization testing complete
- [ ] Input validation testing complete
- [ ] Business logic testing complete
- [ ] API security testing complete
- [ ] Mobile testing complete (if applicable)

### Findings Submitted
- [ ] F001: [Severity] Vulnerability Type
- [ ] F002: [Severity] Vulnerability Type
- [ ] F003: [Severity] Vulnerability Type

### Bounty Status
- Total submitted: 3 findings
- Triaged: 2 findings
- Resolved: 1 finding
- Bounty awarded: $1,500
- Bounty pending: $3,000 (estimated)

---

## Lessons Learned

### What Worked Well
- GraphQL testing yielded multiple findings
- IDOR testing on API was very productive
- Business logic testing in payment flow found critical issue

### What Didn't Work
- Automated XSS scanners flagged many false positives
- Directory fuzzing found nothing significant
- Mobile app testing was out of scope

### Improvements for Next Time
- Focus more on API security from day 1
- Test GraphQL earlier in the process
- Spend less time on automated scans
- More time on business logic

### Skills Developed
- GraphQL security testing
- Advanced IDOR exploitation
- Race condition testing
- Vulnerability chaining

---

## Responsible Disclosure Timeline

### 90-Day Disclosure Policy
- **Day 0 (Report Date):** Vulnerability reported
- **Day 7:** Triage and validation complete
- **Day 30:** Fix deployed to production
- **Day 45:** Bounty awarded
- **Day 90:** Public disclosure allowed (with approval)

### Public Disclosure
- [ ] Requested disclosure approval
- [ ] Received approval from program
- [ ] Sanitized report (removed sensitive details)
- [ ] Published write-up (blog/Twitter)
- [ ] Added to portfolio

---

**Keep this document updated throughout testing. It serves as the single source of truth for the target program.**
