# Docker Setup Guide

## Overview

The Bug Bounty Framework can run in a Docker container, providing:
- **Cross-platform compatibility** - Works on any Linux distro, macOS, Windows with WSL2
- **Security isolation** - Testing environment separated from host system
- **Clean environment** - No dependency conflicts with host
- **Easy deployment** - One command to get started
- **Reproducible** - Same environment every time

## Prerequisites

### Required
- Docker 20.10 or later
- Docker Compose 1.29 or later
- 8GB RAM minimum (16GB recommended)
- 20GB free disk space
- Linux host (Ubuntu, Fedora, Arch, etc.)

### Installation

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install docker.io docker-compose
sudo usermod -aG docker $USER
# Log out and back in for group changes
```

**Fedora:**
```bash
sudo dnf install docker docker-compose
sudo systemctl start docker
sudo systemctl enable docker
sudo usermod -aG docker $USER
```

**Arch:**
```bash
sudo pacman -S docker docker-compose
sudo systemctl start docker
sudo systemctl enable docker
sudo usermod -aG docker $USER
```

## Quick Start

### 1. Clone Repository
```bash
git clone https://github.com/smeags-2024/bugbounty-framework.git
cd bugbounty-framework
```

### 2. Build Container
```bash
cd docker
./build.sh
```
This will:
- Download Kali Linux base image (~1GB)
- Install all 100+ security tools
- Configure the environment
- Takes 15-20 minutes on first build

### 3. Start Container
```bash
./start.sh
```

### 4. Enter Container
```bash
./shell.sh
```

You're now inside the Kali container with all tools available!

## Container Management

### Start Container
```bash
./docker/start.sh
```
Starts the container in detached mode (runs in background).

### Stop Container
```bash
./docker/stop.sh
```
Stops the container. Data in volumes is preserved.

### Enter Container Shell
```bash
./docker/shell.sh
```
Opens an interactive bash shell inside the container.

### View Logs
```bash
./docker/logs.sh
```
Shows container logs (useful for troubleshooting).

### Rebuild Container
```bash
./docker/rebuild.sh
```
Rebuilds the container from scratch (use after updating Dockerfile).

## Directory Structure

### Host Directories (Automatically Created)
```
~/pentesting/     # Your testing workspaces (persistent)
~/wordlists/      # Wordlists (persistent)
docker/outputs/   # Tool outputs (persistent)
```

### Container Directories
```
/workspace/       # Framework files (read-only)
/root/pentesting/ # Mapped to ~/pentesting on host
/root/wordlists/  # Mapped to ~/wordlists on host
/root/tools/      # Installed tools
/root/outputs/    # Mapped to docker/outputs on host
```

## Usage Examples

### Create New Target Workspace
```bash
# Inside container
cd /workspace
./scripts/new-program.sh tryhackme-test
cd ~/pentesting/tryhackme-test
```

### Run Reconnaissance
```bash
# Inside container
bash /workspace/scripts/automation/recon-pipeline.sh target.com
```

### Access Results on Host
```bash
# On host machine
cd ~/pentesting/tryhackme-test
cat recon-*/summary.txt
```

## Advanced Configuration

### Resource Limits

Edit `docker/docker-compose.yml`:
```yaml
services:
  bugbounty-kali:
    mem_limit: 16g  # Increase memory
    cpus: 8.0       # Increase CPU cores
```

### Custom Ports

Expose additional ports:
```yaml
ports:
  - "9090:9090"  # Add custom port
```

### Environment Variables

Add custom environment variables:
```yaml
environment:
  - CUSTOM_VAR=value
```

## Troubleshooting

### Container Won't Start
```bash
# Check Docker is running
sudo systemctl status docker

# Check for port conflicts
sudo netstat -tulpn | grep 8080

# View detailed logs
docker logs bugbounty-kali
```

### Permission Issues
```bash
# Fix volume permissions
sudo chown -R $USER:$USER ~/pentesting
sudo chown -R $USER:$USER ~/wordlists
```

### Out of Disk Space
```bash
# Clean up Docker
docker system prune -a
docker volume prune
```

### Tools Not Working
```bash
# Rebuild container
./docker/rebuild.sh

# Or manually verify tools
docker exec -it bugbounty-kali bash
which subfinder
subfinder -version
```

### Slow Performance
```bash
# Increase resources in docker-compose.yml
# Allocate more RAM and CPU cores
```

## Comparison: Docker vs VM

### Docker Advantages
✅ Faster startup (seconds vs minutes)
✅ Lower resource usage
✅ Works on any Linux distro
✅ Easy to rebuild/reset
✅ Better for CI/CD integration
✅ Version control for environment

### VM Advantages
✅ Complete GUI support
✅ Better for Burp Suite with GUI
✅ More tool compatibility
✅ Easier for beginners

### Recommendation
- **Use Docker** for automated testing, CI/CD, multiple environments
- **Use VM** for heavy GUI tools, visual testing, learning

## Best Practices

### 1. Regular Updates
```bash
# Update container
cd docker
./rebuild.sh

# Update tools inside container
docker exec -it bugbounty-kali bash
~/tools/update-tools.sh
```

### 2. Backup Important Data
```bash
# Pentesting data is in ~/pentesting (automatic backup)
tar -czf pentesting-backup.tar.gz ~/pentesting
```

### 3. Clean Up Regularly
```bash
# Remove old scan data
docker exec -it bugbounty-kali bash
find ~/pentesting -name "recon-*" -mtime +30 -exec rm -rf {} \;
```

### 4. Security
```bash
# Don't expose container to internet
# Keep ports bound to localhost only
# Use separate container for each program (optional)
```

## Integration with GitHub Copilot CLI

The container is ready for GitHub Copilot CLI integration:

1. Install GitHub Copilot CLI on host
2. Configure to execute commands in container:
```bash
# Use docker exec wrapper
alias docker-exec="docker exec -it bugbounty-kali"
```

3. Commands execute inside container automatically

## Performance Tips

1. **Use volumes** - Don't copy large files into container
2. **Limit logs** - Configure log rotation
3. **Prune regularly** - Clean up unused images
4. **SSD recommended** - Better I/O performance
5. **Allocate resources** - Give enough RAM/CPU

## FAQ

**Q: Can I run multiple containers?**
A: Yes, edit `docker-compose.yml` and change container name:
```bash
cp docker-compose.yml docker-compose-target2.yml
# Edit container_name in new file
docker-compose -f docker-compose-target2.yml up -d
```

**Q: How do I copy files from host to container?**
A: Use volumes (automatic) or docker cp:
```bash
docker cp file.txt bugbounty-kali:/root/
```

**Q: Can I use GUI tools like Burp Suite?**
A: Limited support. For full GUI, use VM. For Burp command-line features, works great.

**Q: How do I update just one tool?**
A: Enter container and update manually:
```bash
./docker/shell.sh
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

**Q: Is data persistent?**
A: Yes, ~/pentesting and ~/wordlists are persistent volumes.

## Next Steps

1. **Read methodology**: cat /workspace/docs/skills.md
2. **Create target**: /workspace/scripts/new-program.sh yourname
3. **Run recon**: bash /workspace/scripts/automation/recon-pipeline.sh target.com
4. **Check results**: cd ~/pentesting/yourname/

## Support

- **Framework issues**: GitHub issues
- **Docker issues**: Check Docker documentation
- **Tool issues**: Check individual tool documentation

---

**Remember**: This is a testing environment. Always get proper authorization before testing any systems.
