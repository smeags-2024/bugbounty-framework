# Use official Kali Linux rolling release as base
FROM kalilinux/kali-rolling:latest

# Metadata
LABEL maintainer="Bug Bounty Framework"
LABEL description="Kali Linux container with 100+ security tools for bug bounty hunting"
LABEL version="1.0.0"

# Avoid interactive prompts during build
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC

# Set working directory
WORKDIR /root

# Update and install prerequisites
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y \
        curl wget git build-essential \
        python3 python3-pip python3-venv \
        golang-go jq libpcap-dev \
        nmap masscan nikto wfuzz sqlmap \
        john hashcat hydra medusa \
        dirb dirbuster gobuster \
        burpsuite zaproxy \
        metasploit-framework \
        apt-transport-https ca-certificates \
        vim nano tmux screen \
        net-tools iputils-ping dnsutils \
        && apt-get clean \
        && rm -rf /var/lib/apt/lists/*

# Setup Go environment
ENV GOPATH=/root/go
ENV PATH=$PATH:/usr/local/go/bin:$GOPATH/bin

# Create directory structure
RUN mkdir -p /root/tools \
    /root/wordlists \
    /root/pentesting \
    /root/.config/nuclei

# Copy framework files
COPY scripts/setup.sh /tmp/setup.sh
COPY configs/.bashrc-additions /root/.bashrc-additions

# Make setup script executable and run it
RUN chmod +x /tmp/setup.sh && \
    /tmp/setup.sh || true

# Append bash configurations
RUN cat /root/.bashrc-additions >> /root/.bashrc

# Set up volumes for persistent data
VOLUME ["/root/pentesting", "/root/wordlists"]

# Expose ports (if needed for web tools)
EXPOSE 8080 8443

# Set default command
CMD ["/bin/bash"]

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD which subfinder && which nuclei && which httpx || exit 1
