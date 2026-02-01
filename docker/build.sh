#!/bin/bash

# Build Bug Bounty Framework Docker Container

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}[*] Building Bug Bounty Framework Container${NC}"
echo ""

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo -e "${YELLOW}[!] Docker is not installed. Please install Docker first.${NC}"
    exit 1
fi

# Check if docker-compose is installed
if ! command -v docker-compose &> /dev/null; then
    echo -e "${YELLOW}[!] docker-compose is not installed. Please install docker-compose first.${NC}"
    exit 1
fi

# Build the image
echo -e "${GREEN}[*] Building Docker image (this may take 15-20 minutes)...${NC}"
cd "$SCRIPT_DIR"
docker-compose build --no-cache

echo ""
echo -e "${GREEN}[+] Build complete!${NC}"
echo ""
echo "Next steps:"
echo "  1. Start container: ./docker/start.sh"
echo "  2. Enter shell: ./docker/shell.sh"
echo "  3. View logs: ./docker/logs.sh"
echo ""
