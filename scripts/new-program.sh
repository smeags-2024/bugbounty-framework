#!/bin/bash

# Create New Bug Bounty Program/Target Workspace
# Usage: ./new-program.sh <program-name>

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status() {
    echo -e "${GREEN}[*]${NC} $1"
}

print_error() {
    echo -e "${RED}[!]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[i]${NC} $1"
}

# Check arguments
if [ $# -eq 0 ]; then
    print_error "Usage: $0 <program-name>"
    echo "  Examples:"
    echo "    $0 hackerone-company"
    echo "    $0 tryhackme-skynet"
    echo "    $0 bugcrowd-example"
    exit 1
fi

PROGRAM_NAME="$1"
BASE_DIR=~/pentesting/$PROGRAM_NAME

# Check if directory already exists
if [ -d "$BASE_DIR" ]; then
    print_error "Directory already exists: $BASE_DIR"
    read -p "Do you want to continue anyway? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Create directory structure
print_status "Creating workspace for: $PROGRAM_NAME"
mkdir -p "$BASE_DIR"/{recon/{subdomain,port,web,dns,js-analysis,api,cloud},scans/{automated,manual},findings/{critical,high,medium,low,info,pocs},scripts/{automation,exploits,custom-tools},wordlists,reports/{drafts,submitted,templates},notes,monitoring}

# Create core tracking files
cd "$BASE_DIR" || exit 1

# Copy templates from framework
FRAMEWORK_DIR=~/bugbounty-framework
if [ -d "$FRAMEWORK_DIR" ]; then
    print_status "Copying documentation templates..."
    
    # Copy target template as target-info.md
    if [ -f "$FRAMEWORK_DIR/docs/target-template.md" ]; then
        cp "$FRAMEWORK_DIR/docs/target-template.md" target-info.md
        sed -i "s/\[Company Name \/ TryHackMe Room Name\]/$PROGRAM_NAME/g" target-info.md
    fi
    
    # Copy findings template
    if [ -f "$FRAMEWORK_DIR/docs/findings.md" ]; then
        cp "$FRAMEWORK_DIR/docs/findings.md" findings.md
    fi
    
    # Copy recon template
    if [ -f "$FRAMEWORK_DIR/docs/recon.md" ]; then
        cp "$FRAMEWORK_DIR/docs/recon.md" recon.md
        sed -i "s/\[TryHackMe Room \/ Bug Bounty Program Name\]/$PROGRAM_NAME/g" recon.md
    fi
else
    # Create basic templates if framework not found
    print_info "Framework not found, creating basic templates..."
    
    # Basic target-info.md
    cat > target-info.md << EOF
# $PROGRAM_NAME - Target Information

## Program Details
- **Name:** $PROGRAM_NAME
- **Start Date:** $(date +%Y-%m-%d)
- **Platform:** [HackerOne / Bugcrowd / TryHackMe / Other]
- **Status:** Active

## In-Scope Assets
- Add in-scope domains, IPs, and assets here

## Out-of-Scope Assets
- Add out-of-scope assets here

## Testing Rules
- **Rate Limit:** 10 req/sec
- **Prohibited:** DoS, Social Engineering
- **Test Accounts:** [Add credentials]

## Notes
- Add program-specific notes here
EOF

    # Basic findings.md
    cat > findings.md << EOF
# Findings - $PROGRAM_NAME

## Summary
- **Critical:** 0
- **High:** 0
- **Medium:** 0
- **Low:** 0
- **Info:** 0

## Findings List

### F001: [Title]
- **Severity:** 
- **Status:** Open
- **Found:** $(date +%Y-%m-%d)
- **Description:** 

---
EOF

    # Basic recon.md
    cat > recon.md << EOF
# Reconnaissance - $PROGRAM_NAME

## Start Date: $(date +%Y-%m-%d)

## Subdomain Discovery
- **Total Found:** 0
- **Alive:** 0

## Technology Stack
- Web Server: 
- Application: 
- Database: 

## High-Value Targets
- 

## Next Steps
- 
EOF
fi

# Create progress tracking file
cat > progress.md << EOF
# Testing Progress - $PROGRAM_NAME

## Current Phase
- [ ] Reconnaissance
- [ ] Automated Scanning
- [ ] Manual Testing
- [ ] Reporting

## Daily Log

### $(date +%Y-%m-%d)
- Started testing $PROGRAM_NAME
- Created workspace

---
EOF

# Create timeline file
cat > timeline.md << EOF
# Timeline - $PROGRAM_NAME

| Date | Activity | Findings | Notes |
|------|----------|----------|-------|
| $(date +%Y-%m-%d) | Setup workspace | - | Initial setup |

---
EOF

# Create README
cat > README.md << EOF
# $PROGRAM_NAME

Testing workspace for $PROGRAM_NAME bug bounty program.

## Directory Structure
\`\`\`
$PROGRAM_NAME/
├── recon/              # Reconnaissance data
│   ├── subdomain/      # Subdomain enumeration
│   ├── port/           # Port scanning results
│   ├── web/            # Web application data
│   ├── dns/            # DNS information
│   ├── js-analysis/    # JavaScript analysis
│   ├── api/            # API discovery
│   └── cloud/          # Cloud assets
├── scans/              # Vulnerability scans
│   ├── automated/      # Nuclei, Nikto, etc.
│   └── manual/         # Manual scan data
├── findings/           # Vulnerability findings
│   ├── critical/       # Critical severity
│   ├── high/           # High severity
│   ├── medium/         # Medium severity
│   ├── low/            # Low severity
│   ├── info/           # Informational
│   └── pocs/           # Proof of concepts
├── scripts/            # Custom scripts
│   ├── automation/     # Automation scripts
│   ├── exploits/       # Exploit scripts
│   └── custom-tools/   # Custom tooling
├── wordlists/          # Custom wordlists
├── reports/            # Report drafts
│   ├── drafts/         # Work in progress
│   ├── submitted/      # Submitted reports
│   └── templates/      # Report templates
├── notes/              # Testing notes
└── monitoring/         # Continuous monitoring

## Files
- **target-info.md** - Program scope and details
- **findings.md** - All vulnerability findings
- **recon.md** - Reconnaissance results
- **progress.md** - Testing progress tracking
- **timeline.md** - Activity timeline
\`\`\`

## Quick Start

### Initial Reconnaissance
\`\`\`bash
cd recon/subdomain
subfinder -d target.com -all -recursive -o subdomains.txt
httpx -l subdomains.txt -o alive.txt
cd ../..
\`\`\`

### Automated Scanning
\`\`\`bash
cd scans/automated
nuclei -l ../../recon/subdomain/alive.txt -t ~/nuclei-templates/ -o nuclei-results.txt
cd ../..
\`\`\`

### Documentation
- Update findings in \`findings.md\`
- Track recon in \`recon.md\`
- Log daily progress in \`progress.md\`

## Useful Commands
\`\`\`bash
# Quick recon
bash scripts/automation/recon-pipeline.sh

# Monitor new assets
bash scripts/automation/monitor.sh

# Update findings
vim findings.md
\`\`\`

---
**Started:** $(date +%Y-%m-%d)
**Status:** Active Testing
EOF

# Create basic automation scripts in target directory
mkdir -p scripts/automation

# Quick recon script
cat > scripts/automation/quick-recon.sh << 'SCRIPT'
#!/bin/bash
# Quick reconnaissance for current target

DOMAIN=${1:-target.com}
OUTPUT_DIR="../../recon"

echo "[*] Starting quick reconnaissance for $DOMAIN"

# Subdomain enumeration
echo "[*] Subdomain enumeration..."
subfinder -d "$DOMAIN" -silent -o "$OUTPUT_DIR/subdomain/subdomains-quick.txt"

# HTTP probing
echo "[*] HTTP probing..."
httpx -l "$OUTPUT_DIR/subdomain/subdomains-quick.txt" -silent -o "$OUTPUT_DIR/web/alive-quick.txt"

# Technology detection
echo "[*] Technology detection..."
httpx -l "$OUTPUT_DIR/web/alive-quick.txt" -tech-detect -silent

echo "[+] Quick recon complete! Check $OUTPUT_DIR for results."
SCRIPT

chmod +x scripts/automation/quick-recon.sh

# Create .gitignore
cat > .gitignore << EOF
# Sensitive data
*.key
*.pem
credentials.txt
api_keys.txt
secrets.txt

# Large files
*.pcap
*.log
*.sqlite

# Temporary files
*.tmp
*.temp
*~

# Tool outputs (keep structure, not data)
# Uncomment lines below if you want to commit outputs
# recon/*/
# scans/*/
# findings/pocs/

EOF

# Create notes structure
touch notes/daily-$(date +%Y-%m-%d).md
cat > notes/daily-$(date +%Y-%m-%d).md << EOF
# Daily Notes - $(date +%Y-%m-%d)

## Tasks
- [ ] Initial reconnaissance
- [ ] Review scope document
- [ ] Set up test accounts

## Observations
- 

## Ideas
- 

## Blockers
- 

---
EOF

print_status "Workspace created successfully!"
echo ""
print_info "Location: $BASE_DIR"
print_info "Program: $PROGRAM_NAME"
echo ""
echo "Directory structure:"
ls -1 "$BASE_DIR" | sed 's/^/  ├── /'
echo ""
echo "Quick start:"
echo "  cd $BASE_DIR"
echo "  cat README.md"
echo "  vim target-info.md  # Add scope details"
echo "  bash scripts/automation/quick-recon.sh target.com"
echo ""
print_status "Happy hunting! 🎯"
