# Docker Socket Container Escape PoC

## ⚠️ WARNING: EDUCATIONAL PURPOSE ONLY ⚠️

This tool is provided for **educational and authorized security testing purposes only**. 
Usage of this tool against any system without explicit permission is illegal and unethical.

## Overview

This proof-of-concept (PoC) demonstrates the security vulnerability that arises when the Docker socket (`/var/run/docker.sock`) is mounted inside a container. This common misconfiguration can lead to a complete host system compromise.

The tool provides multiple methods to demonstrate how an attacker with access to the Docker socket could escape container isolation and gain access to the host system.

## Prerequisites

- Container with Docker socket mounted (`/var/run/docker.sock`)
- Basic shell access to the container
- Docker CLI tools (script can attempt to install if missing)

## Features

The PoC demonstrates multiple container escape techniques:

1. **Basic Privileged Container Escape**: Creates a privileged container that mounts the host filesystem
2. **Docker Daemon Configuration Exploit**: Modifies Docker daemon settings 
3. **Custom Capabilities Escape**: Uses SYS_ADMIN capability to break out
4. **Network Namespace Escape**: Deploys container with host network access
5. **Docker API Command Execution**: Runs commands on the host via Docker API
6. **Build Context Exploitation**: Accesses host files during image builds
7. **Volume Mount Abuse**: Accesses sensitive host directories
8. **PID Namespace Exploitation**: Accesses host processes
9. **Exec API Exploitation**: Creates privileged exec sessions
10. **Full System Compromise**: Demonstrates persistence techniques

## Usage

1. Download the script onto a container with the Docker socket mounted
2. Make the script executable: `chmod +x docker_escape_poc.sh`
3. Run the script: `./docker_escape_poc.sh`
4. Select the desired escape method from the menu

## Sample Output

```
[*] Docker Socket Container Escape - Enhanced PoC
[*] Starting vulnerability check...
[+] Docker socket found. Container may be vulnerable.

Available escape methods:
1. Basic privileged container escape (mount host filesystem)
2. Docker daemon configuration exploit (write to daemon config)
3. Create container with custom capabilities
...

Select escape method (1-10): 1
[+] Executing basic privileged container escape...
[+] Container escape successful. Now running on the host with root privileges.
[+] Hostname: host-machine-name
[+] Host files: [host file listing]
```

## Mitigation Strategies

To protect your systems against Docker socket container escapes:

1. **Never** mount the Docker socket (`/var/run/docker.sock`) into containers unless absolutely necessary
2. If Docker API access is required, use socket proxies with strict access controls
3. Implement proper authentication and authorization for Docker API access
4. Use rootless Docker or alternative container runtimes
5. Implement security monitoring for container activities
6. Apply the principle of least privilege to container configurations
7. Use seccomp, AppArmor, or SELinux profiles to restrict container capabilities
8. Keep Docker and host systems updated with security patches
9. Implement runtime security monitoring and container scanning
10. Consider using container security platforms for added protection

## Additional Security Resources

- [Docker Security Documentation](https://docs.docker.com/engine/security/)
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker)
- [OWASP Docker Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)
- [NIST Container Security Guide](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-190.pdf)

## Responsible Disclosure

If you discover vulnerable configurations in production environments, please follow responsible disclosure procedures and inform the system owners before taking any action.

## Disclaimer

The authors of this tool accept no liability for misuse. This tool is provided as-is without warranty of any kind. Use at your own risk and only in authorized environments.

## License

This project is released under the MIT License.