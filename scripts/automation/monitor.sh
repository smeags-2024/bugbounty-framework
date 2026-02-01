#!/bin/bash

# Asset Monitoring Script
# Continuously monitor targets for changes

TARGET_DOMAIN=${1:-""}
INTERVAL=${2:-3600}  # Check every hour by default

if [ -z "$TARGET_DOMAIN" ]; then
    echo "[!] Usage: $0 <domain> [interval-seconds]"
    echo "  Example: $0 target.com 3600"
    exit 1
fi

MONITOR_DIR="monitoring/$TARGET_DOMAIN"
mkdir -p "$MONITOR_DIR"

echo "[*] Starting continuous monitoring for: $TARGET_DOMAIN"
echo "[*] Check interval: $INTERVAL seconds ($(($INTERVAL / 60)) minutes)"
echo "[*] Press Ctrl+C to stop"
echo ""

# Initial baseline
if [ ! -f "$MONITOR_DIR/baseline-subs.txt" ]; then
    echo "[*] Creating baseline..."
    subfinder -d "$TARGET_DOMAIN" -all -silent -o "$MONITOR_DIR/baseline-subs.txt"
    httpx -l "$MONITOR_DIR/baseline-subs.txt" -silent -o "$MONITOR_DIR/baseline-alive.txt"
    echo "[+] Baseline created: $(wc -l < "$MONITOR_DIR/baseline-alive.txt") alive assets"
fi

ITERATION=0

while true; do
    ITERATION=$((ITERATION + 1))
    TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")
    
    echo "[*] [$TIMESTAMP] Check #$ITERATION"
    
    # Subdomain discovery
    subfinder -d "$TARGET_DOMAIN" -all -silent -o "$MONITOR_DIR/current-subs.txt"
    httpx -l "$MONITOR_DIR/current-subs.txt" -silent -o "$MONITOR_DIR/current-alive.txt"
    
    # Compare with baseline
    NEW_ASSETS=$(comm -13 <(sort "$MONITOR_DIR/baseline-alive.txt") <(sort "$MONITOR_DIR/current-alive.txt"))
    NEW_COUNT=$(echo "$NEW_ASSETS" | grep -c . || echo 0)
    
    if [ "$NEW_COUNT" -gt 0 ]; then
        echo "[+] ALERT: $NEW_COUNT new assets detected!"
        echo "$NEW_ASSETS"
        echo ""
        
        # Log alert
        echo "[$TIMESTAMP] New assets detected:" >> "$MONITOR_DIR/alerts.log"
        echo "$NEW_ASSETS" >> "$MONITOR_DIR/alerts.log"
        echo "" >> "$MONITOR_DIR/alerts.log"
        
        # Scan new assets
        echo "$NEW_ASSETS" > "$MONITOR_DIR/new-assets-$ITERATION.txt"
        nuclei -l "$MONITOR_DIR/new-assets-$ITERATION.txt" \
            -t ~/nuclei-templates/exposures/ \
            -severity critical,high \
            -silent \
            -o "$MONITOR_DIR/new-findings-$ITERATION.txt"
        
        # Update baseline
        cp "$MONITOR_DIR/current-alive.txt" "$MONITOR_DIR/baseline-alive.txt"
        cp "$MONITOR_DIR/current-subs.txt" "$MONITOR_DIR/baseline-subs.txt"
    else
        echo "[i] No changes detected"
    fi
    
    echo "[*] Next check in $INTERVAL seconds..."
    echo ""
    sleep "$INTERVAL"
done
