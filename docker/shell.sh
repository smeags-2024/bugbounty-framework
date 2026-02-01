#!/bin/bash

# Enter Bug Bounty Framework Container Shell

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Check if container is running
if ! docker ps | grep -q bugbounty-kali; then
    echo -e "${RED}[!] Container is not running${NC}"
    echo "Start it with: ./docker/start.sh"
    exit 1
fi

echo -e "${GREEN}[*] Entering container shell...${NC}"
echo ""

# Enter the container
docker exec -it bugbounty-kali /bin/bash

echo ""
echo -e "${GREEN}[*] Exited container${NC}"
