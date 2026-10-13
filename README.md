# Sentinel: Linux System Security & Compliance Auditor

An automated Linux security auditing script designed for system hardening and posture assessment.

## Features
- **Account Integrity Checks:** Identifies unauthorized UID 0 accounts and checks for blank password credentials.
- **Filesystem Security:** Inspects permissions on sensitive assets (e.g., `/etc/shadow`) and identifies world-writable directories missing sticky bits.
- **Network Surface Auditing:** Scans listening TCP/UDP endpoints and verifies OpenSSH configuration directives.
- **Automated Reporting:** Generates timestamped compliance reports with an objective 100-point security score.

## Usage
```bash
chmod +x sentinel.sh
sudo ./sentinel.sh
