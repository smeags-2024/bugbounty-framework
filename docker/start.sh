#!/bin/bash

# Start Bug Bounty Framework Container

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}[*] Starting Bug Bounty Framework Container${NC}"

# Check if container is already running
if docker ps | grep -q bugbounty-kali; then
    echo -e "${YELLOW}[!] Container is already running${NC}"
    echo "Use './docker/shell.sh' to enter the container"
    exit 0
fi

# Create required directories on host if they don't exist
mkdir -p ~/pentesting
mkdir -p ~/wordlists
mkdir -p "$SCRIPT_DIR/outputs"

# Start the container
cd "$SCRIPT_DIR"
docker-compose up -d

echo ""
echo -e "${GREEN}[+] Container started successfully!${NC}"
echo ""
echo "Quick commands:"
echo "  Enter container: ./docker/shell.sh"
echo "  View logs:       ./docker/logs.sh"
echo "  Stop container:  ./docker/stop.sh"
echo ""
echo "Container name: bugbounty-kali"
echo "Access with: docker exec -it bugbounty-kali /bin/bash"
echo ""
