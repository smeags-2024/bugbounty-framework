#!/bin/bash

# View Bug Bounty Framework Container Logs

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors
GREEN='\033[0;32m'
NC='\033[0m'

echo -e "${GREEN}[*] Viewing container logs (Ctrl+C to exit)${NC}"
echo ""

cd "$SCRIPT_DIR"
docker-compose logs -f
