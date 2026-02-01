#!/bin/bash

# Rebuild Bug Bounty Framework Container

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}[*] Rebuilding container (this will stop the current container)${NC}"
echo ""

# Stop container if running
cd "$SCRIPT_DIR"
docker-compose down

# Rebuild
echo -e "${GREEN}[*] Rebuilding image...${NC}"
docker-compose build --no-cache

# Restart
echo -e "${GREEN}[*] Starting rebuilt container...${NC}"
docker-compose up -d

echo ""
echo -e "${GREEN}[+] Rebuild complete!${NC}"
echo "Enter container: ./docker/shell.sh"
echo ""
