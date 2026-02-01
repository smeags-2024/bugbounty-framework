#!/bin/bash

# Daily Reconnaissance - Monitor for new assets
# Run this daily via cron to monitor targets for changes

set -e

# Check if target file exists
TARGETS_FILE=${1:-"targets.txt"}

if [ ! -f "$TARGETS_FILE" ]; then
    echo "[!] Targets file not found: $TARGETS_FILE"
    echo "[i] Usage: $0 [targets-file]"
    echo "[i] Create targets.txt with one domain per line"
    exit 1
fi

DATE=$(date +%Y-%m-%d)
OUTPUT_DIR="daily-$DATE"
PREVIOUS_DIR=$(ls -td daily-* 2>/dev/null | head -2 | tail -1)

mkdir -p "$OUTPUT_DIR"

echo "[*] Daily Reconnaissance - $DATE"
echo "[*] Monitoring $(wc -l < "$TARGETS_FILE") targets"

# Process each target
while IFS= read -r domain || [ -n "$domain" ]; do
    [ -z "$domain" ] && continue
    [ "${domain:0:1}" = "#" ] && continue
    
    echo ""
    echo "[*] Processing: $domain"
    
    # Subdomain discovery
    echo "  [*] Subdomain enumeration..."
    subfinder -d "$domain" -all -silent -o "$OUTPUT_DIR/$domain-subs.txt"
    
    # DNS resolution
    echo "  [*] DNS resolution..."
    dnsx -l "$OUTPUT_DIR/$domain-subs.txt" -silent -o "$OUTPUT_DIR/$domain-resolved.txt"
    
    # HTTP probing
    echo "  [*] HTTP probing..."
    httpx -l "$OUTPUT_DIR/$domain-resolved.txt" -silent -o "$OUTPUT_DIR/$domain-alive.txt"
    
    # Check for new assets
    if [ -n "$PREVIOUS_DIR" ] && [ -f "$PREVIOUS_DIR/$domain-alive.txt" ]; then
        NEW_ASSETS=$(comm -13 <(sort "$PREVIOUS_DIR/$domain-alive.txt") <(sort "$OUTPUT_DIR/$domain-alive.txt"))
        NEW_COUNT=$(echo "$NEW_ASSETS" | grep -c . || echo 0)
        
        if [ "$NEW_COUNT" -gt 0 ]; then
            echo "  [+] Found $NEW_COUNT new assets!"
            echo "$NEW_ASSETS" | tee "$OUTPUT_DIR/$domain-new.txt"
            
            # Scan new assets immediately
            echo "  [*] Scanning new assets..."
            nuclei -l "$OUTPUT_DIR/$domain-new.txt" \
                -t ~/nuclei-templates/exposures/ \
                -severity critical,high \
                -silent \
                -o "$OUTPUT_DIR/$domain-new-findings.txt"
        else
            echo "  [i] No new assets found"
        fi
    fi
    
    # Summary
    SUBS_COUNT=$(wc -l < "$OUTPUT_DIR/$domain-subs.txt" 2>/dev/null || echo 0)
    ALIVE_COUNT=$(wc -l < "$OUTPUT_DIR/$domain-alive.txt" 2>/dev/null || echo 0)
    echo "  [+] Summary: $SUBS_COUNT subdomains, $ALIVE_COUNT alive"
    
done < "$TARGETS_FILE"

# Generate daily report
cat > "$OUTPUT_DIR/daily-report.txt" << EOF
Daily Monitoring Report
Date: $DATE

$(for domain in $(cat "$TARGETS_FILE" | grep -v "^#"); do
    SUBS=$(wc -l < "$OUTPUT_DIR/$domain-subs.txt" 2>/dev/null || echo 0)
    ALIVE=$(wc -l < "$OUTPUT_DIR/$domain-alive.txt" 2>/dev/null || echo 0)
    NEW=$(wc -l < "$OUTPUT_DIR/$domain-new.txt" 2>/dev/null || echo 0)
    echo "- $domain: $SUBS subdomains, $ALIVE alive ($NEW new)"
done)

New Findings:
$(cat "$OUTPUT_DIR"/*-new-findings.txt 2>/dev/null || echo "No new critical/high findings")

EOF

echo ""
echo "[+] Daily monitoring complete!"
echo "[i] Report: $OUTPUT_DIR/daily-report.txt"

# Clean up old daily scans (keep last 30 days)
find . -maxdepth 1 -type d -name "daily-*" -mtime +30 -exec rm -rf {} \; 2>/dev/null || true
