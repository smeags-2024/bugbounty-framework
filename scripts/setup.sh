#!/bin/bash

# Bug Bounty Testing Environment Setup Script
# For Kali Linux / Debian-based systems
# Installs 100+ security tools for comprehensive penetration testing

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Functions
print_status() {
    echo -e "${GREEN}[*]${NC} $1"
}

print_error() {
    echo -e "${RED}[!]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check if running as root (not recommended for most tools)
if [ "$EUID" -eq 0 ]; then
    print_warning "Running as root. Some Go tools will install to /root/go/bin"
    print_warning "Consider running as regular user for proper Go path setup"
fi

# System Information
print_status "System Information:"
echo "  OS: $(lsb_release -d | cut -f2-)"
echo "  Kernel: $(uname -r)"
echo "  User: $(whoami)"
echo ""

# Update system
print_status "Updating system packages..."
sudo apt update -qq

# Install prerequisites
print_status "Installing prerequisites..."
sudo apt install -y -qq \
    curl wget git build-essential \
    python3 python3-pip python3-venv \
    golang-go jq libpcap-dev \
    nmap masscan nikto wfuzz sqlmap \
    john hashcat hydra medusa \
    dirb dirbuster gobuster \
    burpsuite zaproxy \
    metasploit-framework \
    apt-transport-https ca-certificates \
    > /dev/null 2>&1

# Check Go installation
if ! command_exists go; then
    print_error "Go is not installed. Installing latest Go version..."
    wget -q https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
    sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
    rm go1.21.5.linux-amd64.tar.gz
    export PATH=$PATH:/usr/local/go/bin
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
fi

# Setup Go environment
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin
echo 'export GOPATH=$HOME/go' >> ~/.bashrc
echo 'export PATH=$PATH:$GOPATH/bin' >> ~/.bashrc

print_status "Go version: $(go version)"

# Create directories
print_status "Creating directory structure..."
mkdir -p ~/tools
mkdir -p ~/wordlists
mkdir -p ~/pentesting
mkdir -p ~/.config/nuclei

# Install Go-based tools
print_status "Installing Go-based reconnaissance tools..."

# ProjectDiscovery tools
print_status "  Installing ProjectDiscovery suite..."
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
go install -v github.com/projectdiscovery/notify/cmd/notify@latest

# TomNomNom tools
print_status "  Installing TomNomNom tools..."
go install -v github.com/tomnomnom/waybackurls@latest
go install -v github.com/tomnomnom/assetfinder@latest
go install -v github.com/tomnomnom/unfurl@latest
go install -v github.com/tomnomnom/gf@latest
go install -v github.com/tomnomnom/httprobe@latest
go install -v github.com/tomnomnom/anew@latest

# Other Go tools
print_status "  Installing additional Go tools..."
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/hakluke/hakrawler@latest
go install -v github.com/ffuf/ffuf/v2@latest
go install -v github.com/OJ/gobuster/v3@latest
go install -v github.com/hahwul/dalfox/v2@latest
go install -v github.com/jaeles-project/gospider@latest
go install -v github.com/assetnote/kiterunner@latest
go install -v github.com/d3mondev/puredns/v2@latest
go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
go install -v github.com/projectdiscovery/cloudlist/cmd/cloudlist@latest
go install -v github.com/projectdiscovery/proxify/cmd/proxify@latest
go install -v github.com/projectdiscovery/tlsx/cmd/tlsx@latest
go install -v github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest
go install -v github.com/KathanP19/Gxss@latest
go install -v github.com/003random/getJS@latest
go install -v github.com/incogbyte/shosubgo@latest
go install -v github.com/tomnomnom/qsreplace@latest
go install -v github.com/takshal/freq@latest

# Update nuclei templates
print_status "Updating Nuclei templates..."
nuclei -update-templates -silent

# Install Python-based tools
print_status "Installing Python-based tools..."
pip3 install --quiet --upgrade pip
pip3 install --quiet \
    arjun sqlmap wapiti dirsearch \
    truffleHog gitleaks-scanner \
    uro wafw00f dnstwist \
    censys shodan pwntools \
    requests beautifulsoup4 \
    parameth urldedupe

# Clone GitHub repositories
print_status "Cloning GitHub tool repositories..."
cd ~/tools

# JavaScript analysis
if [ ! -d "LinkFinder" ]; then
    git clone -q https://github.com/GerbenJavado/LinkFinder.git
    cd LinkFinder && pip3 install -q -r requirements.txt && cd ..
fi

if [ ! -d "SecretFinder" ]; then
    git clone -q https://github.com/m4ll0k/SecretFinder.git
    cd SecretFinder && pip3 install -q -r requirements.txt && cd ..
fi

if [ ! -d "subjs" ]; then
    git clone -q https://github.com/lc/subjs.git
fi

# XSS tools
if [ ! -d "XSStrike" ]; then
    git clone -q https://github.com/s0md3v/XSStrike.git
    cd XSStrike && pip3 install -q -r requirements.txt && cd ..
fi

if [ ! -d "xsser" ]; then
    git clone -q https://github.com/epsylon/xsser.git
    cd xsser && sudo python3 setup.py install -q && cd ..
fi

# SQL injection
if [ ! -d "ghauri" ]; then
    git clone -q https://github.com/r0oth3x49/ghauri.git
    cd ghauri && pip3 install -q -r requirements.txt && cd ..
fi

# Command injection
if [ ! -d "commix" ]; then
    git clone -q https://github.com/commixproject/commix.git
fi

# SSRF
if [ ! -d "SSRFmap" ]; then
    git clone -q https://github.com/swisskyrepo/SSRFmap.git
    cd SSRFmap && pip3 install -q -r requirements.txt && cd ..
fi

# JWT tools
if [ ! -d "jwt_tool" ]; then
    git clone -q https://github.com/ticarpi/jwt_tool.git
    chmod +x jwt_tool/jwt_tool.py
fi

# GraphQL
if [ ! -d "graphql-cop" ]; then
    git clone -q https://github.com/dolevf/graphql-cop.git
    cd graphql-cop && pip3 install -q -r requirements.txt && cd ..
fi

if [ ! -d "graphw00f" ]; then
    git clone -q https://github.com/dolevf/graphw00f.git
    cd graphw00f && pip3 install -q -r requirements.txt && cd ..
fi

# CORS testing
if [ ! -d "Corsy" ]; then
    git clone -q https://github.com/s0md3v/Corsy.git
fi

# Subdomain takeover
if [ ! -d "subjack" ]; then
    git clone -q https://github.com/haccer/subjack.git
    cd subjack && go build && mv subjack $GOPATH/bin/ && cd ..
fi

# GitHub dorking
if [ ! -d "GitDorker" ]; then
    git clone -q https://github.com/obheda12/GitDorker.git
    cd GitDorker && pip3 install -q -r requirements.txt && cd ..
fi

# GF patterns for grep
if [ ! -d "Gf-Patterns" ]; then
    git clone -q https://github.com/1ndianl33t/Gf-Patterns.git
    mkdir -p ~/.gf
    cp Gf-Patterns/*.json ~/.gf/
fi

# Additional patterns
if [ ! -d "gf-patterns" ]; then
    git clone -q https://github.com/tomnomnom/gf.git gf-patterns
    cp gf-patterns/examples/* ~/.gf/
fi

# Wordlists
print_status "Installing wordlists..."
cd ~/wordlists

if [ ! -d "SecLists" ]; then
    print_status "  Cloning SecLists (may take a few minutes)..."
    git clone -q https://github.com/danielmiessler/SecLists.git
fi

# Additional wordlists
if [ ! -f "onelistforallmicro.txt" ]; then
    wget -q https://raw.githubusercontent.com/six2dez/OneListForAll/main/onelistforallmicro.txt
fi

if [ ! -f "jhaddix-all.txt" ]; then
    wget -q https://gist.githubusercontent.com/jhaddix/86a06c5dc309d08580a018c66354a056/raw/96f4e51d96b2203f19f6381c8c545b278eaa0837/all.txt -O jhaddix-all.txt
fi

# Custom wordlists
cat > ~/wordlists/backup-files.txt << 'EOF'
.git/HEAD
.git/config
.env
.env.local
.env.production
config.php
config.php.bak
config.php.old
config.php~
database.sql
db_backup.sql
backup.sql
backup.zip
backup.tar.gz
phpinfo.php
info.php
test.php
debug.php
admin.php.bak
EOF

cat > ~/wordlists/api-endpoints.txt << 'EOF'
v1
v2
v3
api
api/v1
api/v2
api/v3
graphql
graphiql
swagger
swagger.json
swagger.yaml
openapi.json
api-docs
docs
documentation
health
status
ping
version
users
user
admin
auth
login
logout
register
reset
forgot
profile
account
settings
orders
payments
products
search
upload
download
EOF

# Install additional security tools
print_status "Installing additional security tools..."

# CMS scanners
if ! command_exists wpscan; then
    sudo gem install wpscan -q
fi

# testssl.sh
if [ ! -f "/usr/local/bin/testssl.sh" ]; then
    cd /tmp
    git clone -q --depth 1 https://github.com/drwetter/testssl.sh.git
    sudo cp testssl.sh/testssl.sh /usr/local/bin/
    sudo chmod +x /usr/local/bin/testssl.sh
    rm -rf testssl.sh
fi

# Amass
if ! command_exists amass; then
    go install -v github.com/owasp-amass/amass/v4/...@master
fi

# Gowitness (screenshots)
if ! command_exists gowitness; then
    go install -v github.com/sensepost/gowitness@latest
fi

# Rustscan (fast port scanner)
if ! command_exists rustscan; then
    wget -q https://github.com/RustScan/RustScan/releases/download/2.1.1/rustscan_2.1.1_amd64.deb
    sudo dpkg -i rustscan_2.1.1_amd64.deb 2>/dev/null || true
    rm rustscan_2.1.1_amd64.deb
fi

# Verification
print_status "Verifying installations..."

TOOLS=(
    "subfinder" "httpx" "nuclei" "katana" "naabu" "dnsx"
    "waybackurls" "gau" "assetfinder" "unfurl" "gf"
    "ffuf" "gobuster" "dalfox" "gospider"
    "sqlmap" "arjun" "nmap" "masscan"
)

FAILED=()

for tool in "${TOOLS[@]}"; do
    if command_exists "$tool"; then
        echo -e "  ${GREEN}✓${NC} $tool"
    else
        echo -e "  ${RED}✗${NC} $tool"
        FAILED+=("$tool")
    fi
done

# Print summary
echo ""
print_status "Installation Summary:"
echo "  ✓ Go-based tools: $(ls $GOPATH/bin | wc -l) installed"
echo "  ✓ Python tools: $(pip3 list | grep -E 'arjun|sqlmap|wapiti' | wc -l) installed"
echo "  ✓ GitHub repos: $(ls ~/tools | wc -l) cloned"
echo "  ✓ Wordlists ready in ~/wordlists/"
echo "  ✓ Nuclei templates: $(nuclei -tl 2>/dev/null | wc -l) templates"

if [ ${#FAILED[@]} -gt 0 ]; then
    print_warning "Failed installations: ${FAILED[*]}"
    print_warning "Try installing manually or check error messages above"
fi

# Setup shell environment
print_status "Configuring shell environment..."

# Add tool paths to bashrc if not already present
if ! grep -q "Bug Bounty Environment" ~/.bashrc; then
    cat >> ~/.bashrc << 'EOF'

# Bug Bounty Environment
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin:/usr/local/go/bin
export TOOLS_DIR=$HOME/tools
export WORDLIST_DIR=$HOME/wordlists
export PENTESTING_DIR=$HOME/pentesting

# Default rate limiting
export RATE_LIMIT=10
export MAX_THREADS=50
export TIMEOUT=30

# Tool aliases
alias ll='ls -lah'
alias recon-fast='subfinder -d $1 -silent | httpx -silent'
alias recon-full='subfinder -d $1 -all -recursive -o subs.txt && httpx -l subs.txt -o alive.txt && nuclei -l alive.txt'
alias portscan='naabu -host $1 -top-ports 1000'
alias dirscan='ffuf -u https://$1/FUZZ -w ~/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories.txt'
alias nuclei-crit='nuclei -l $1 -t ~/nuclei-templates/ -severity critical,high'

# Quick functions
cdtest() { cd ~/pentesting/"$1" || return; }
newtest() {
    mkdir -p ~/pentesting/"$1"/{recon,scans,findings,scripts,notes}
    cd ~/pentesting/"$1" || return
    echo "# $1" > notes/README.md
}
EOF
fi

print_status "Shell environment configured. Run: source ~/.bashrc"

# Create update script
cat > ~/tools/update-tools.sh << 'EOF'
#!/bin/bash
echo "[*] Updating all security tools..."

# Update Go tools
echo "[*] Updating Go tools..."
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

# Update nuclei templates
echo "[*] Updating Nuclei templates..."
nuclei -update-templates -silent

# Update Python tools
echo "[*] Updating Python tools..."
pip3 install --upgrade pip sqlmap arjun wapiti dirsearch

# Update GitHub repos
echo "[*] Updating GitHub repositories..."
cd ~/tools || exit
for dir in */; do
    if [ -d "$dir/.git" ]; then
        echo "  Updating $dir..."
        (cd "$dir" && git pull -q)
    fi
done

# Update SecLists
echo "[*] Updating SecLists..."
cd ~/wordlists/SecLists && git pull -q

echo "[+] All tools updated!"
EOF

chmod +x ~/tools/update-tools.sh

# Final message
echo ""
echo "=========================================="
print_status "Installation Complete!"
echo "=========================================="
echo ""
echo "Next steps:"
echo "  1. source ~/.bashrc"
echo "  2. Test tools: subfinder -version"
echo "  3. Create new target: newtest <target-name>"
echo "  4. Update tools: ~/tools/update-tools.sh"
echo ""
echo "Directories:"
echo "  Tools:      ~/tools/"
echo "  Wordlists:  ~/wordlists/"
echo "  Testing:    ~/pentesting/"
echo ""
echo "Documentation: https://github.com/[your-repo]/BugBounty"
echo ""
print_status "Happy Hunting! 🎯"
