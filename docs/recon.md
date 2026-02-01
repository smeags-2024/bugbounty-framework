# Reconnaissance Tracking

## Target Information
- **Program Name:** [TryHackMe Room / Bug Bounty Program Name]
- **Start Date:** YYYY-MM-DD
- **Platform:** TryHackMe / HackerOne / Bugcrowd / Other
- **Primary Domain:** target.com
- **Reconnaissance Start:** YYYY-MM-DD HH:MM UTC
- **Reconnaissance End:** YYYY-MM-DD HH:MM UTC

---

## Scope Summary

### In-Scope Assets
- *.target.com
- target.com
- api.target.com
- admin.target.com
- IP Range: 203.0.113.0/24

### Out-of-Scope Assets
- thirdparty.example.com
- old.target.com (decommissioned)

---

## Subdomain Discovery

### Summary Statistics
- **Total Subdomains Found:** 127
- **Alive Subdomains (HTTP/HTTPS):** 43
- **Unique IP Addresses:** 18
- **Cloud-Hosted:** 12 (AWS: 8, GCP: 3, Azure: 1)
- **On-Premise:** 6

### Discovery Sources
| Source | Count | Notes |
|--------|-------|-------|
| subfinder | 89 | Multiple sources (crt.sh, chaos, etc.) |
| assetfinder | 52 | Some duplicates |
| amass passive | 67 | High quality results |
| chaos dataset | 34 | ProjectDiscovery Chaos |
| crt.sh manual | 28 | Certificate transparency |
| DNS bruteforce | 15 | Custom wordlist |
| **Total Unique** | **127** | After deduplication |

### High-Value Subdomains
| Subdomain | IP Address | Status | Technologies | Priority | Notes |
|-----------|------------|--------|--------------|----------|-------|
| admin.target.com | 203.0.113.10 | 200 | PHP 7.4, nginx | HIGH | Admin panel found |
| api.target.com | 203.0.113.20 | 200 | Node.js, Express | HIGH | REST API |
| dev.target.com | 203.0.113.30 | 200 | Django, Python | HIGH | Development environment |
| staging.target.com | 203.0.113.40 | 200 | Rails, Ruby | MEDIUM | Staging server |
| backup.target.com | 203.0.113.50 | 403 | nginx | MEDIUM | Forbidden, investigate |
| jenkins.target.com | 203.0.113.60 | 200 | Jenkins 2.319 | HIGH | CI/CD server |
| grafana.target.com | 203.0.113.70 | 200 | Grafana 8.5.0 | MEDIUM | Monitoring dashboard |
| mail.target.com | 203.0.113.80 | 200 | Roundcube | LOW | Webmail |

### Cloud Assets
| Asset | Provider | Region | Public | Notes |
|-------|----------|--------|--------|-------|
| s3://target-backups | AWS S3 | us-east-1 | No | Access denied |
| s3://target-uploads | AWS S3 | us-west-2 | Yes | Public read access! |
| target-data.blob.core.windows.net | Azure | eastus | No | Private |
| storage.googleapis.com/target-prod | GCP | us-central1 | No | Private |

### Subdomain Takeover Candidates
| Subdomain | Provider | Status | Exploitable |
|-----------|----------|--------|-------------|
| blog.target.com | GitHub Pages | CNAME points to nonexistent repo | Yes |
| help.target.com | Heroku | No such app | Yes |
| shop.target.com | Shopify | Shop not found | No (claimed) |

---

## Port Scanning Results

### Open Ports Summary
| Service | Ports | Count | Priority |
|---------|-------|-------|----------|
| HTTP | 80 | 23 | MEDIUM |
| HTTPS | 443 | 41 | HIGH |
| SSH | 22 | 8 | LOW |
| FTP | 21 | 2 | HIGH |
| MySQL | 3306 | 1 | CRITICAL |
| PostgreSQL | 5432 | 1 | CRITICAL |
| Redis | 6379 | 1 | CRITICAL |
| MongoDB | 27017 | 1 | CRITICAL |
| Elasticsearch | 9200 | 1 | CRITICAL |
| Custom | 8080, 8443 | 12 | HIGH |

### Critical Exposed Services
| Host | Port | Service | Version | Risk |
|------|------|---------|---------|------|
| db.target.com | 3306 | MySQL | 5.7.33 | CRITICAL - Public DB |
| redis.target.com | 6379 | Redis | 6.2.5 | CRITICAL - No auth |
| elastic.target.com | 9200 | Elasticsearch | 7.10.0 | HIGH - Open access |
| jenkins.target.com | 8080 | Jenkins | 2.319 | HIGH - Old version |

### Interesting Findings
- **MySQL exposed on public internet** (db.target.com:3306) - Immediate security concern
- **Redis without authentication** (redis.target.com:6379) - Can be exploited
- **Old Jenkins version** with known CVEs
- **FTP with anonymous login** on old.target.com:21

---

## Technology Stack

### Web Servers
| Technology | Count | Versions | Notes |
|------------|-------|----------|-------|
| nginx | 28 | 1.18.0, 1.20.1, 1.21.3 | Most common |
| Apache | 12 | 2.4.41, 2.4.46 | Older installs |
| IIS | 3 | 10.0 | Windows servers |

### Programming Languages & Frameworks
| Language/Framework | Count | Versions | Endpoints |
|-------------------|-------|----------|-----------|
| PHP | 15 | 7.4.28, 8.0.15 | Main site, admin |
| Node.js | 8 | 14.18.3, 16.13.2 | API, microservices |
| Python (Django) | 5 | 3.9, Django 3.2 | Dev, internal tools |
| Ruby on Rails | 3 | Rails 6.1 | Staging, old apps |
| .NET Core | 2 | 5.0 | Legacy apps |

### Content Management Systems
| CMS | Count | Version | Location |
|-----|-------|---------|----------|
| WordPress | 1 | 5.8.3 | blog.target.com |
| Joomla | 0 | - | - |
| Drupal | 0 | - | - |

### JavaScript Frameworks (Frontend)
| Framework | Count | Endpoints |
|-----------|-------|-----------|
| React | 18 | Most SPAs |
| Vue.js | 5 | Admin panels |
| Angular | 2 | Legacy apps |
| jQuery | 12 | Older pages |

### Databases
| Database | Count | Exposed | Version |
|----------|-------|---------|---------|
| MySQL | 15 | 1 (CRITICAL) | 5.7.33, 8.0.27 |
| PostgreSQL | 8 | 1 (CRITICAL) | 12.9, 13.5 |
| MongoDB | 3 | 1 (CRITICAL) | 4.4.10 |
| Redis | 5 | 1 (HIGH) | 6.2.5 |

### Cloud Providers
| Provider | Services | Count |
|----------|----------|-------|
| AWS | EC2, S3, CloudFront, RDS | 12 |
| GCP | Cloud Storage, Compute Engine | 3 |
| Azure | Blob Storage, VMs | 1 |
| Cloudflare | CDN, DDoS Protection | 25 |

---

## Discovered Endpoints

### Total Endpoints: 1,847

### High-Value Endpoints
| Endpoint | Method | Status | Auth Required | Priority | Notes |
|----------|--------|--------|---------------|----------|-------|
| /admin | GET | 200 | Yes | HIGH | Admin panel |
| /admin/users | GET | 200 | Yes | HIGH | User management |
| /api/v1/users | GET | 200 | No | CRITICAL | IDOR potential |
| /api/v1/users/{id} | GET | 200 | No | CRITICAL | User details exposed |
| /api/v2/admin | GET | 403 | Yes | HIGH | Admin API |
| /debug | GET | 200 | No | HIGH | Debug page exposed |
| /phpinfo.php | GET | 200 | No | HIGH | PHP info leaked |
| /.env | GET | 200 | No | CRITICAL | Config file exposed! |
| /.git/config | GET | 200 | No | CRITICAL | Git repo exposed! |
| /backup.sql | GET | 403 | ? | HIGH | DB backup file |
| /upload | POST | 200 | Yes | HIGH | File upload |
| /graphql | POST | 200 | No | HIGH | GraphQL endpoint |
| /admin/logs | GET | 401 | Yes | MEDIUM | Log access |

### API Endpoints
| Endpoint | Method | Auth | Version | Notes |
|----------|--------|------|---------|-------|
| /api/v1/auth/login | POST | No | v1 | Authentication |
| /api/v1/auth/register | POST | No | v1 | Registration |
| /api/v1/users | GET | Yes | v1 | List users |
| /api/v1/users/{id} | GET | Yes | v1 | User details (IDOR test) |
| /api/v1/users/{id} | PUT | Yes | v1 | Update user (IDOR test) |
| /api/v1/users/{id} | DELETE | Yes | v1 | Delete user (IDOR test) |
| /api/v1/orders | GET | Yes | v1 | List orders (IDOR test) |
| /api/v1/payments | POST | Yes | v1 | Process payment |
| /api/v2/admin/users | GET | Yes | v2 | Admin user list |
| /api/v2/admin/settings | GET | Yes | v2 | Admin settings |

### Authentication Endpoints
- `/login` - POST - Main login
- `/logout` - GET - Logout
- `/register` - POST - User registration
- `/forgot-password` - POST - Password reset
- `/reset-password` - POST - Password reset confirmation
- `/api/v1/auth/login` - POST - API login
- `/api/v1/auth/refresh` - POST - Token refresh
- `/oauth/authorize` - GET - OAuth authorization
- `/oauth/token` - POST - OAuth token exchange

---

## JavaScript Analysis

### JavaScript Files Found: 342

### High-Priority JS Files
| File | Size | Endpoints Found | Secrets | Notes |
|------|------|-----------------|---------|-------|
| main.bundle.js | 2.4MB | 47 | 0 | Main application |
| admin.js | 890KB | 23 | 1 API key | Admin functionality |
| api-client.js | 145KB | 89 | 0 | API client library |
| auth.js | 67KB | 12 | 0 | Authentication logic |
| config.js | 12KB | 5 | 3 keys | **Config with API keys!** |

### Extracted Endpoints from JS: 287

### Secrets Found in JavaScript
| File | Secret Type | Value | Severity |
|------|-------------|-------|----------|
| config.js | API Key | sk_live_123abc... | CRITICAL |
| config.js | AWS Access Key | AKIA... | CRITICAL |
| admin.js | Internal API URL | https://internal-api.target.local | MEDIUM |
| analytics.js | Google Analytics | UA-12345678-1 | LOW |

### Interesting JavaScript Functions
- `isAdmin()` - Client-side admin check (bypassable)
- `validatePayment()` - Payment validation logic
- `encryptPassword()` - Weak encryption (Base64)
- `checkAccess()` - Authorization check (client-side)

---

## Parameter Discovery

### Total Parameters Found: 453

### High-Value Parameters
| Parameter | Endpoints | Type | Potential Vulnerability |
|-----------|-----------|------|-------------------------|
| id | 89 | Integer | IDOR |
| user_id | 34 | Integer | IDOR |
| file | 12 | String | LFI, Path Traversal |
| url | 8 | URL | SSRF, Open Redirect |
| redirect | 6 | URL | Open Redirect |
| page | 23 | String | LFI |
| cmd | 2 | String | Command Injection |
| query | 15 | String | SQLi, XSS |
| search | 28 | String | SQLi, XSS |
| email | 45 | Email | SQLi, XSS |
| callback | 5 | URL | SSRF, XSS |
| template | 3 | String | SSTI |
| role | 7 | String | Privilege Escalation |
| admin | 4 | Boolean | Privilege Escalation |
| debug | 2 | Boolean | Information Disclosure |

### Parameter Patterns
- Numeric IDs (id, user_id, order_id, payment_id) - Test for IDOR
- File paths (file, path, page) - Test for LFI/Path Traversal
- URLs (url, redirect, callback) - Test for SSRF/Open Redirect
- User input (search, query, comment) - Test for SQLi/XSS
- Role/privilege (role, admin, is_admin) - Test for privilege escalation

---

## Credentials & Secrets

### Found Credentials
| Location | Type | Value | Status |
|----------|------|-------|--------|
| .env file (exposed) | DB Password | mysecretpass123 | Valid |
| config.js | API Key | sk_live_abc123 | Valid |
| GitHub commit | AWS Key | AKIAIOSFODNN7EXAMPLE | Revoked |
| Hardcoded in JS | Test Account | test@test.com:password | Valid |

### Exposed Configuration Files
- `/.env` - Database credentials, API keys
- `/.git/config` - Git configuration
- `/config.php.bak` - Backup config file
- `/web.config` - IIS configuration

---

## Third-Party Integrations

### Identified Services
| Service | Purpose | Data Shared | Risk |
|---------|---------|-------------|------|
| Stripe | Payment Processing | Credit cards | HIGH |
| SendGrid | Email Delivery | Email addresses | MEDIUM |
| AWS S3 | File Storage | User uploads | HIGH |
| Google Analytics | Analytics | User behavior | LOW |
| Cloudflare | CDN/Security | All traffic | LOW |
| Twilio | SMS/2FA | Phone numbers | MEDIUM |
| Intercom | Customer Support | User data | MEDIUM |

### Third-Party Domains
- stripe.com
- sendgrid.net
- amazonaws.com
- google-analytics.com
- cloudflare.com
- twilio.com
- intercom.io

---

## Interesting Observations

### Security Findings During Recon
1. **Exposed .git repository** on main domain - Can download source code
2. **Public S3 bucket** (s3://target-uploads) - Contains uploaded files
3. **MySQL database exposed** to internet - Critical security issue
4. **API keys in JavaScript** - Immediate security concern
5. **Old Jenkins version** - Known CVEs available
6. **No rate limiting** on API endpoints - Enables brute force
7. **Verbose error messages** - Information disclosure
8. **Debug endpoints enabled** in production - `/debug`, `/phpinfo.php`
9. **Weak password policy** observed during registration
10. **Missing security headers** - No HSTS, CSP, X-Frame-Options

### Unusual Patterns
- Multiple development/staging environments accessible from internet
- Inconsistent authentication across API versions
- Mix of old and new technologies
- Some endpoints return different responses based on User-Agent
- Several subdomains return default server pages (might be forgotten)

### Attack Surface Priority
1. **Critical:** Exposed databases, API keys in JS, .env file accessible
2. **High:** Admin panels, API endpoints with IDOR potential, file upload
3. **Medium:** Old software versions, information disclosure, missing headers
4. **Low:** Subdomain takeover candidates, verbose errors

---

## Next Steps

### Immediate Actions
- [ ] Exploit exposed .env file - download and analyze
- [ ] Test IDOR on /api/v1/users/{id} endpoint
- [ ] Attempt authentication bypass with SQL injection
- [ ] Test file upload for RCE
- [ ] Exploit exposed database (if ethical and in scope)
- [ ] Download source code from .git repository
- [ ] Test API keys found in JavaScript

### Further Investigation
- [ ] GraphQL introspection and testing
- [ ] JWT token analysis and manipulation
- [ ] Admin panel authentication bypass attempts
- [ ] Business logic testing on payment flows
- [ ] SSRF testing on url/callback parameters
- [ ] XSS testing on all input fields
- [ ] CSRF testing on state-changing functions

### Tools to Run Next
- [ ] SQLMap on all input parameters
- [ ] Nuclei with all templates
- [ ] Burp Suite active scan
- [ ] Manual testing of high-value endpoints
- [ ] GitDumper to extract .git repository
- [ ] AWS CLI to test exposed S3 buckets

---

## Recon Timeline
- **Day 1:** Subdomain enumeration, HTTP probing (3 hours)
- **Day 2:** Port scanning, technology detection (2 hours)
- **Day 3:** Directory fuzzing, endpoint discovery (4 hours)
- **Day 4:** JavaScript analysis, parameter discovery (3 hours)
- **Day 5:** Documentation and prioritization (1 hour)
- **Total Time:** 13 hours

---

## Notes
- Keep this document updated as new assets are discovered
- Document all reconnaissance activities for reporting
- Prioritize findings based on potential impact
- Cross-reference with scope.md to ensure all testing is authorized
- Use this data to inform vulnerability testing phase
