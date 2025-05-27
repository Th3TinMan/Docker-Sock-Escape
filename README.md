# Docker Socket Container Escape PoC (v2)

## ⚠️ WARNING: EDUCATIONAL PURPOSE ONLY ⚠️

This tool is provided for **educational and authorized security testing purposes only**.
Usage of this tool against any system without explicit permission is illegal and unethical. The authors accept no liability for misuse. This tool is provided as-is without warranty of any kind. Use at your own risk.

## Overview

This proof-of-concept (PoC) script (v2) demonstrates the severe security vulnerabilities that arise when the Docker socket (`/var/run/docker.sock`) is mounted inside a container. This common misconfiguration can allow an attacker with access to such a container to escape its isolation and potentially achieve a complete host system compromise.

This version incorporates several improvements over the original, including:
-   **Fixes for previously problematic methods** (especially API command execution and build context exploitation).
-   **Dependency checking** for `docker`, `curl`, and `tar`, with attempts to install them if missing (requires appropriate container permissions and common package managers like `apk`, `apt`, or `yum`).
-   **Improved error handling** (`set -e`).
-   **Enhanced readability** through function-based methods and more comments.
-   **More robust cleanup** options for resources created by the PoC.

## Prerequisites

-   A container environment where the host's Docker socket (`/var/run/docker.sock`) is mounted into the container.
-   Shell access to this container.
-   Internet access from within the container may be required if `docker`, `curl`, or `tar` need to be downloaded/installed.
-   Root privileges within the container are likely needed if the script attempts to install missing dependencies (`curl`, `tar`).

## Features (Demonstrated Escape Techniques)

The PoC script provides a menu to demonstrate various container escape techniques:

1.  **Basic Privileged Container Escape**: Launches a new, fully privileged container that directly mounts and `chroot`s into the host's filesystem, granting interactive shell access on the host.
2.  **Docker Daemon Configuration Exploit**: Attempts to overwrite the host's Docker daemon configuration file (`/etc/docker/daemon.json`) with a malicious configuration. *This method requires a manual restart of the Docker daemon on the host to take effect.*
3.  **Custom Capabilities Escape**: Creates a container with the `SYS_ADMIN` capability (and disables AppArmor/Seccomp) to demonstrate mounting the host's filesystem from within this less-privileged (but still powerful) container.
4.  **Host Network Sidecar**: Deploys a "sidecar" container configured to use the host's network stack. This container then starts a `socat` listener on a specific port, effectively opening a shell accessible from the host's network.
5.  **Docker API Command Execution on Host**: Creates a temporary, privileged container that mounts the host's root filesystem and uses `chroot` to execute pre-defined commands directly on the host system, demonstrating non-interactive command execution.
6.  **Build Context File Access**: Exploits the Docker build process by providing a specially crafted Dockerfile via stdin. It uses the host's root directory (`/`) as the build context, allowing the Dockerfile's `COPY` instruction to access and embed sensitive host files (e.g., `/etc/shadow`, `/etc/hostname`) into the resulting image. A container is then run from this image to display the exfiltrated files.
7.  **Volume Mount Abuse**: Directly mounts sensitive host directories or files (e.g., `/`, `/etc/shadow`, `/root`) into a temporary container to read their contents. Mounts are read-only in the PoC for safety.
8.  **Host PID Namespace Exploitation**: Launches a container within the host's PID namespace, allowing it to see and potentially interact with all processes running on the host system (demonstrated by listing processes like `dockerd`, `sshd`).
9.  **Privileged `docker exec` Session**: Demonstrates how an attacker can use `docker exec` with the `--privileged` flag on *any* existing container (even non-privileged ones) to gain privileged access within that container's context, then leverage those privileges to mount the host filesystem.
10. **Full System Compromise (Persistent Backdoor)**: Deploys a highly privileged container configured for persistence (`--restart=always`). This container mounts the host's root filesystem, runs on the host's PID and network namespaces, and is intended to simulate a persistent backdoor an attacker might install.

## Usage

1.  Ensure you have explicit authorization to test on the target system.
2.  Transfer the script (e.g., `docker_escape_ssh_v2.sh`) into the vulnerable container that has the Docker socket mounted.
3.  Make the script executable: `chmod +x docker_escape_ssh_v2.sh`
4.  Run the script: `./docker_escape_ssh_v2.sh`
5.  The script will first check for the Docker socket and attempt to ensure the Docker CLI is available (installing `curl`, `tar`, and `docker` if necessary and possible).
6.  If checks pass, a menu of escape methods will be displayed. Select the desired method by number.
7.  Follow any on-screen prompts or instructions.
8.  After a method is executed, you will be prompted to run a cleanup routine.

## Sample Output (Illustrative)