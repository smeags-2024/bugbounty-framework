#!/bin/bash

# Automated Reconnaissance Pipeline
# Runs comprehensive reconnaissance against a target domain

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status() {
    echo -e "${GREEN}[$(date +%H:%M:%S)]${NC} $1"
}

print_error() {
    echo -e "${RED}[$(date +%H:%M:%S)]${NC} $1"
}

# Check arguments
if [ $# -eq 0 ]; then
    print_error "Usage: $0 <domain>"
    echo "  Example: $0 target.com"
    exit 1
fi

DOMAIN=$1
OUTPUT_DIR="recon-$(date +%Y%m%d-%H%M%S)"
RATE_LIMIT=${RATE_LIMIT:-10}

print_status "Starting reconnaissance pipeline for: $DOMAIN"
print_status "Output directory: $OUTPUT_DIR"
print_status "Rate limit: $RATE_LIMIT req/sec"

mkdir -p "$OUTPUT_DIR"/{subdomains,ports,web,nuclei,js,params,api}
cd "$OUTPUT_DIR" || exit 1

# Phase 1: Subdomain Enumeration
print_status "Phase 1/7: Subdomain Enumeration"

print_status "  Running subfinder..."
subfinder -d "$DOMAIN" -all -recursive -silent -o subdomains/subfinder.txt

print_status "  Running assetfinder..."
assetfinder --subs-only "$DOMAIN" | tee subdomains/assetfinder.txt

print_status "  Running amass (passive)..."
amass enum -passive -d "$DOMAIN" -o subdomains/amass.txt 2>/dev/null

print_status "  Merging and deduplicating..."
cat subdomains/*.txt | sort -u > subdomains/all-subdomains.txt
SUBDOMAIN_COUNT=$(wc -l < subdomains/all-subdomains.txt)
print_status "  Found $SUBDOMAIN_COUNT unique subdomains"

# Phase 2: DNS Resolution
print_status "Phase 2/7: DNS Resolution"
dnsx -l subdomains/all-subdomains.txt -silent -o subdomains/resolved.txt
RESOLVED_COUNT=$(wc -l < subdomains/resolved.txt)
print_status "  Resolved $RESOLVED_COUNT subdomains"

# Phase 3: HTTP Probing
print_status "Phase 3/7: HTTP Probing & Technology Detection"
httpx -l subdomains/resolved.txt \
    -status-code \
    -title \
    -tech-detect \
    -web-server \
    -content-length \
    -threads 50 \
    -rate-limit "$RATE_LIMIT" \
    -silent \
    -o web/alive.txt

ALIVE_COUNT=$(wc -l < web/alive.txt)
print_status "  Found $ALIVE_COUNT alive web services"

# Phase 4: Port Scanning (Top ports)
print_status "Phase 4/7: Port Scanning"
naabu -l subdomains/resolved.txt \
    -top-ports 1000 \
    -silent \
    -rate "$RATE_LIMIT" \
    -o ports/open-ports.txt

print_status "  Port scan complete"

# Phase 5: Nuclei Scanning
print_status "Phase 5/7: Nuclei Vulnerability Scanning"

print_status "  Scanning for critical/high exposures..."
nuclei -l web/alive.txt \
    -t ~/nuclei-templates/exposures/ \
    -severity critical,high \
    -silent \
    -rate-limit "$RATE_LIMIT" \
    -o nuclei/critical-exposures.txt

print_status "  Scanning for CVEs..."
nuclei -l web/alive.txt \
    -t ~/nuclei-templates/cves/ \
    -severity critical,high,medium \
    -silent \
    -rate-limit "$RATE_LIMIT" \
    -o nuclei/cves.txt

print_status "  Scanning for misconfigurations..."
nuclei -l web/alive.txt \
    -t ~/nuclei-templates/misconfiguration/ \
    -silent \
    -rate-limit "$RATE_LIMIT" \
    -o nuclei/misconfigs.txt

NUCLEI_FINDINGS=$(cat nuclei/*.txt 2>/dev/null | wc -l)
print_status "  Nuclei found $NUCLEI_FINDINGS potential issues"

# Phase 6: JavaScript Analysis
print_status "Phase 6/7: JavaScript Analysis"

print_status "  Discovering JavaScript files..."
katana -u web/alive.txt \
    -jc \
    -depth 3 \
    -silent \
    -rate-limit "$RATE_LIMIT" \
    -o js/js-files.txt 2>/dev/null || true

JS_COUNT=$(wc -l < js/js-files.txt 2>/dev/null || echo 0)
print_status "  Found $JS_COUNT JavaScript files"

if [ "$JS_COUNT" -gt 0 ]; then
    print_status "  Extracting endpoints from JavaScript..."
    cat js/js-files.txt | head -50 | while read -r url; do
        timeout 10 python3 ~/tools/LinkFinder/linkfinder.py -i "$url" -o cli 2>/dev/null || true
    done | tee js/extracted-endpoints.txt
fi

# Phase 7: Parameter Discovery
print_status "Phase 7/7: Parameter Discovery"

print_status "  Gathering historical parameters..."
waybackurls "$DOMAIN" 2>/dev/null | unfurl keys | sort -u > params/wayback-params.txt || true
gau "$DOMAIN" 2>/dev/null | unfurl keys | sort -u > params/gau-params.txt || true

cat params/*-params.txt 2>/dev/null | sort -u > params/all-params.txt || true
PARAM_COUNT=$(wc -l < params/all-params.txt 2>/dev/null || echo 0)
print_status "  Discovered $PARAM_COUNT unique parameters"

# Generate Summary Report
print_status "Generating summary report..."

cat > summary.txt << EOF
Reconnaissance Summary Report
Target: $DOMAIN
Date: $(date)
Duration: Automated Pipeline

=== STATISTICS ===
Total Subdomains Found: $SUBDOMAIN_COUNT
Resolved Subdomains: $RESOLVED_COUNT
Alive Web Services: $ALIVE_COUNT
JavaScript Files: $JS_COUNT
Parameters Discovered: $PARAM_COUNT
Nuclei Findings: $NUCLEI_FINDINGS

=== HIGH-VALUE TARGETS ===
Top 10 HTTP Services:
$(head -10 web/alive.txt)

=== NUCLEI CRITICAL FINDINGS ===
$(cat nuclei/critical-exposures.txt 2>/dev/null | head -20 || echo "No critical findings")

=== NEXT STEPS ===
1. Review nuclei findings in: nuclei/
2. Check alive.txt for interesting subdomains
3. Investigate exposed JavaScript files
4. Test discovered parameters for vulnerabilities
5. Run deeper scans on high-value targets

=== DIRECTORY STRUCTURE ===
$OUTPUT_DIR/
├── subdomains/       # Subdomain enumeration results
├── ports/            # Port scanning results
├── web/              # HTTP probing results
├── nuclei/           # Nuclei scan results
├── js/               # JavaScript analysis
├── params/           # Parameter discovery
└── summary.txt       # This file

EOF

print_status "Pipeline complete!"
echo ""
echo "=========================================="
echo "  Reconnaissance Complete!"
echo "=========================================="
echo ""
cat summary.txt
echo ""
print_status "Full results saved in: $OUTPUT_DIR/"
print_status "Review summary: cat $OUTPUT_DIR/summary.txt"
