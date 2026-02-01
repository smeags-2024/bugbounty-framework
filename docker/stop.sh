#!/bin/bash

# Stop Bug Bounty Framework Container

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}[*] Stopping Bug Bounty Framework Container${NC}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Stop the container
docker-compose down

echo ""
echo -e "${GREEN}[+] Container stopped${NC}"
echo ""
echo "Your data in ~/pentesting is preserved"
echo "To start again: ./docker/start.sh"
echo ""
