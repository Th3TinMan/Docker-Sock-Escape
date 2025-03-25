# Docker Socket Container Escape Proof of Concept

## Warning ⚠️

This tool is provided for **EDUCATIONAL PURPOSES ONLY**. It demonstrates a critical container escape vulnerability that could be exploited in misconfigured Docker environments. Use only in controlled testing environments with proper authorization.

## Overview

This proof of concept demonstrates how a container with access to the Docker socket (`/var/run/docker.sock`) can escape its isolation and gain access to the host system. The script creates a persistent backdoor by adding an SSH key to the host system's root account.

## The Vulnerability

When containers are given access to the Docker socket, they effectively have the ability to:
- Create new containers
- Mount host file systems
- Run containers with elevated privileges

This breaks the security boundary that containers are designed to enforce.

## Prerequisites

- Docker installed on the host system
- A container with the Docker socket mounted (e.g., `-v /var/run/docker.sock:/var/run/docker.sock`)
- Docker CLI installed within the container

## How It Works

1. The script verifies access to the Docker socket
2. It generates a temporary SSH key pair
3. Using the Docker socket, it creates a new privileged container
4. The new container mounts the host's root filesystem
5. It adds the generated SSH public key to the host's root account
6. A proof file is created to demonstrate successful exploitation

## Detection

Signs this exploit has been used:
- Unauthorized containers being created
- Unexpected SSH keys in `authorized_keys` files
- Evidence of file access outside container boundaries

## Mitigation

To prevent this vulnerability:

1. **Never** mount the Docker socket in containers unless absolutely necessary
2. If the Docker socket must be used:
   - Apply strict security constraints
   - Consider using a socket proxy with limited permissions
   - Monitor container activities closely
3. Regularly audit SSH keys across all systems
4. Use read-only file systems where possible
5. Implement least privilege principles for all containers

## Usage

```bash
# Clone the repository
git clone https://github.com/your-username/docker-escape-poc.git

# Navigate to the directory
cd docker-escape-poc

# Make the script executable
chmod +x docker_escape_ssh.sh

# Run the script (only in authorized testing environments)
./docker_escape_ssh.sh
```

## Cleanup

After testing:

1. Remove any added SSH keys from `/root/.ssh/authorized_keys`
2. Delete proof files from `/tmp/`
3. Check for any other unauthorized changes to the host system

## Further Reading

- [Docker Security Documentation](https://docs.docker.com/engine/security/)
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker)
- [OWASP Docker Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)