# Bug Bounty Testing Framework

A comprehensive, professional bug bounty hunting framework designed for systematic penetration testing with AI assistance via GitHub Copilot CLI and MCP integration.

## 🎯 Overview

This framework provides:
- **Complete methodology** covering OWASP, PTES, and WAHH standards
- **100+ security tools** automated installation
- **AI-assisted workflows** via GitHub Copilot CLI + MCP
- **Professional documentation** templates for findings and reporting
- **Automation scripts** for reconnaissance and monitoring
- **Reusable structure** for multiple programs and CTF challenges

## 🏗️ Project Structure

```
BugBounty/
├── .github/
│   ├── prompts/              # AI assistant prompts
│   └── copilot-instructions.md
├── docs/                      # Core methodology documentation
│   ├── skills.md             # Complete testing methodology (OWASP, PTES, WAHH)
│   ├── checklist.md          # Comprehensive testing checklist
│   ├── findings.md           # Vulnerability documentation template
│   ├── recon.md              # Reconnaissance tracking
│   ├── workflow.md           # AI-assisted daily workflow
│   └── target-template.md    # New program template
├── scripts/
│   ├── setup.sh              # Tool installation for Kali Linux
│   ├── new-program.sh        # Create new target workspace
│   ├── automation/
│   │   ├── recon-pipeline.sh # Automated reconnaissance
│   │   ├── daily-recon.sh    # Daily monitoring
│   │   └── monitor.sh        # Continuous monitoring
│   ├── exploits/             # Custom exploitation scripts
│   └── parsers/              # Tool output parsers
├── configs/
│   ├── .bashrc-additions     # Environment variables and aliases
│   ├── burp-extensions.txt   # Recommended Burp Suite extensions
│   └── nuclei-config.yaml    # Nuclei configuration
├── templates/
│   └── [PROGRAM]/            # Template directory structure
└── README.md                 # This file
```

## 🚀 Quick Start

### 1. Initial Setup (Development Machine)

```bash
# Clone the repository
git clone https://github.com/[your-username]/bugbounty-framework.git ~/bugbounty-framework
cd ~/bugbounty-framework

# Review methodology
cat docs/skills.md
cat docs/checklist.md
```

### 2. Deploy on Kali Linux VM

```bash
# Authenticate GitHub CLI (if not already done)
gh auth login

# Clone repository on Kali
git clone https://github.com/[your-username]/bugbounty-framework.git ~/bugbounty-framework
cd ~/bugbounty-framework

# Install all tools (100+ security tools)
chmod +x scripts/setup.sh
./scripts/setup.sh

# Configure environment
cat configs/.bashrc-additions >> ~/.bashrc
source ~/.bashrc

# Verify installation
subfinder -version
httpx -version
nuclei -version
```

### 3. Create Your First Target

```bash
# Create new program workspace
./scripts/new-program.sh tryhackme-example

# Navigate to workspace
cd ~/pentesting/tryhackme-example

# Edit target information
vim target-info.md  # Add scope details

# Start reconnaissance
bash scripts/automation/quick-recon.sh target.com
```

### 4. Run Comprehensive Recon

```bash
# Full reconnaissance pipeline
~/bugbounty-framework/scripts/automation/recon-pipeline.sh target.com

# Review results
cd recon-[timestamp]/
cat summary.txt
```

## 📚 Documentation

### Methodology Files

- **[skills.md](docs/skills.md)** - Complete penetration testing methodology
  - OWASP Testing Guide v4.2 (all 12 categories)
  - PTES (Penetration Testing Execution Standard)
  - WAHH (Web Application Hacker's Handbook)
  - 10 testing phases with detailed techniques

- **[checklist.md](docs/checklist.md)** - Phase-by-phase testing checklist
  - Pre-engagement setup
  - Reconnaissance (passive & active)
  - Authentication & authorization testing
  - Input validation (SQLi, XSS, command injection, etc.)
  - Business logic flaws
  - API security
  - Mobile testing (Android & iOS)
  - Reporting requirements

- **[findings.md](docs/findings.md)** - Vulnerability documentation template
  - Professional report format
  - CVSS scoring
  - Reproduction steps
  - Proof of concept examples
  - Remediation recommendations

- **[workflow.md](docs/workflow.md)** - AI-assisted daily routine
  - Collaboration model (AI vs Human responsibilities)
  - Morning routine (AI overnight scans)
  - Afternoon manual testing
  - Evening documentation
  - Command examples

- **[target-template.md](docs/target-template.md)** - New program template
  - Scope definition
  - Asset inventory
  - Testing rules
  - Bounty information
  - Progress tracking

## 🛠️ Tools Included

### Reconnaissance (25+ tools)
- **Subdomain Enumeration:** subfinder, amass, assetfinder, chaos
- **HTTP Probing:** httpx, httprobe
- **Web Crawling:** katana, gospider, hakrawler, waybackurls, gau
- **JS Analysis:** LinkFinder, SecretFinder, subjs
- **Parameter Discovery:** arjun, paramspider, x8
- **Technology Detection:** whatweb, webanalyze, nuclei
- **Port Scanning:** nmap, masscan, naabu, rustscan
- **API Discovery:** kiterunner, graphql-cop

### Vulnerability Scanning (15+ tools)
- **Multi-purpose:** nuclei (5000+ templates)
- **Web Scanners:** nikto, wapiti, arachni
- **CMS Scanners:** wpscan, joomscan, droopescan
- **SSL/TLS:** testssl.sh, sslscan
- **Fuzzing:** ffuf, gobuster, feroxbuster, wfuzz

### Exploitation (20+ tools)
- **SQL Injection:** sqlmap, ghauri
- **XSS:** dalfox, XSStrike, xsser
- **Command Injection:** commix
- **SSRF:** SSRFmap, gopherus
- **Deserialization:** ysoserial, phpggc
- **JWT:** jwt_tool, jwt-cracker
- **Password Attacks:** hydra, john, hashcat
- **GraphQL:** graphql-cop, graphw00f

### Manual Testing
- **Burp Suite** with recommended extensions:
  - Autorize (authorization testing)
  - Active Scan++
  - JWT Editor
  - Param Miner
  - Turbo Intruder
  - Upload Scanner
  - Logger++

## 🤖 AI Integration

This framework is designed to work with **GitHub Copilot CLI** using **MCP (Model Context Protocol)** for direct command execution on Kali Linux.

### What AI Handles
- ✅ Running reconnaissance tools
- ✅ Parsing tool outputs
- ✅ Generating automation scripts
- ✅ Drafting vulnerability reports
- ✅ Calculating CVSS scores
- ✅ Creating exploitation PoCs
- ✅ Suggesting testing strategies

### What Humans Handle
- ✅ Scope interpretation
- ✅ Complex manual testing
- ✅ Business logic analysis
- ✅ Creative exploitation
- ✅ Final report review
- ✅ High-risk action approval

### Example AI Workflow

```bash
# Human: "Run recon on target.com"
# AI executes via MCP:
subfinder -d target.com -all -recursive -o subs.txt && \
  httpx -l subs.txt -o alive.txt && \
  nuclei -l alive.txt -t ~/nuclei-templates/ -severity critical,high -o findings.txt

# AI then summarizes findings:
"Found 47 subdomains, 23 alive services, 3 critical findings:
1. Exposed .env file on staging.target.com
2. SQL injection in search parameter  
3. Admin panel with default credentials"
```

## 📋 Testing Workflow

### Phase 1: Initial Setup
1. Create new program workspace
2. Review and document scope (target-info.md)
3. Set up test accounts
4. Configure rate limits

### Phase 2: Reconnaissance (Day 1-2)
```bash
# Automated recon pipeline
~/bugbounty-framework/scripts/automation/recon-pipeline.sh target.com

# Review outputs
- Subdomains discovered
- Technology stack identified
- Interesting endpoints found
- Nuclei critical findings
```

### Phase 3: Automated Scanning (Day 2-3)
```bash
# Comprehensive Nuclei scan
nuclei -l alive.txt -t ~/nuclei-templates/ -o nuclei-full.txt

# CMS-specific testing
wpscan --url https://blog.target.com --api-token YOUR_TOKEN

# SSL/TLS testing
testssl.sh https://target.com
```

### Phase 4: Manual Testing (Day 3-10)
- Authentication testing (SQLi, NoSQL, JWT, OAuth)
- Authorization testing (IDOR, privilege escalation)
- Input validation (SQLi, XSS, command injection)
- Business logic flaws
- API security (REST, GraphQL, SOAP)
- File upload testing

### Phase 5: Reporting (Ongoing)
- Document findings in findings.md
- Calculate accurate CVSS scores
- Create PoC materials
- Submit via platform
- Track triage/resolution status

## 🎓 Learning Path

### For Beginners
1. Start with **docs/skills.md** - Read the complete methodology
2. Practice on **TryHackMe** or **HackTheBox**
3. Use **docs/checklist.md** to ensure comprehensive testing
4. Document everything in **findings.md**

### For Intermediate
1. Focus on automation with **scripts/automation/**
2. Practice vulnerability chaining
3. Develop custom exploitation scripts
4. Contribute to the framework

### For Advanced
1. Create custom Nuclei templates
2. Develop advanced automation
3. Research 0-day vulnerabilities
4. Build custom tools in scripts/exploits/

## 🔐 Safety & Ethics

### Always Remember
- ✅ Test only in-scope assets
- ✅ Respect rate limits (default: 10 req/sec)
- ✅ Use test accounts only
- ✅ No DoS or destructive testing
- ✅ Report critical vulnerabilities immediately
- ✅ Follow responsible disclosure

### Stop Conditions
- ❌ Scope is ambiguous
- ❌ Action could cause harm
- ❌ Accessing real user data
- ❌ Unintended system behavior
- ❌ Legal/ethical concerns
- ❌ Evidence of active breach

## 🔄 Updates

### Update All Tools
```bash
# Run update script
~/tools/update-tools.sh

# Or manually update
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates
pip3 install --upgrade sqlmap arjun wapiti
```

### Update Framework
```bash
cd ~/bugbounty-framework
git pull origin main
```

## 📊 Performance Tips

### Efficient Reconnaissance
1. **Parallel Processing** - Run multiple tools simultaneously
2. **Overnight Scans** - Let nuclei/long scans run overnight
3. **Smart Filtering** - Use httpx to filter alive hosts before scanning
4. **Rate Limiting** - Always respect target servers

### Automation Best Practices
1. **Chain Tools** - Pipe outputs between tools
2. **Save Everything** - Document all commands and outputs
3. **Version Control** - Git commit methodology updates
4. **Backup Results** - Regular backups of findings/

## 🤝 Contributing

This is a personal framework, but improvements welcome:
1. Add new automation scripts
2. Improve documentation
3. Create custom Nuclei templates
4. Share interesting findings (redacted)

## 📄 License

This framework is for educational and authorized testing only. Always obtain proper authorization before testing any systems.

## 🙏 Credits

Built on the shoulders of giants:
- ProjectDiscovery (nuclei, subfinder, httpx, katana)
- OWASP (methodology, testing guide)
- TomNomNom (waybackurls, unfurl, gf, assetfinder)
- All open-source security tool developers

## 📞 Support

- **Documentation:** Check docs/ directory
- **Issues:** Review methodology in docs/skills.md
- **Community:** Bug bounty platform communities

---

**Remember:** With great power comes great responsibility. Test ethically, report responsibly, and help make the internet more secure. 🛡️

**Happy Hunting! 🎯**
