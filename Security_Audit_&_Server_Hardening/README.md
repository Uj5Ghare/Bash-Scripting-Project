## This script performs various security checks and hardening tasks on Linux servers to enhance their security. It generates a summary report of the findings and sends an email alert if critical issues are found.

## Overview

**This script performs security audits and hardens Linux servers. It is designed to:**
- Audit the system for security issues.
- Apply hardening measures to improve security.
- Generate a summary report of the findings.
- Send an email alert if critical issues are found.

## Script Overview
**Author:** *Ujwal Pachghare*  
**Email Recipient for Alerts:** admin@example.com         
**Email Sender:** john.doe@example.com  
**Email Subject:** Security Audit Alert: Critical Issues Found

### Requirements

- The script must be run as root.
- Run on Debian-based linux.
- Ensure the script is executable: `chmod +x script.sh`
- Prerequisites: `iptables` `ufw` `logwatch` `grub-common` `mailutils`

### Global Variables

- `SUMMARY_REPORT`: File where the summary of the audit is stored.
- `EMAIL_RECIPIENT`: Recipient of email alerts.
- `EMAIL_SENDER`: Sender's email address.
- `EMAIL_SUBJECT`: Subject line for email alerts.

### Options:

`-usr-grp-audit`: Perform user and group audit.     
`-check-perms`: Check file and directory permissions.   
`-service-audit`: Audit running services.   
`-check-firewall`: Check firewall settings.   
`-check-ip`: Check IP addresses and secure SSH.   
`-check-update`: Check for available updates.   
`-check-log`: Check logs for suspicious entries.   
`-hardern-ssh`: Harden SSH configuration.   
`-disable-ipv6`: Disable IPv6.   
`-secure-grub`: Secure the GRUB bootloader.   
`-configure-iptables`: Configure iptables.   
`-auto-update`: Configure automatic updates.   
`-execute_check`: Execute commands from the configuration file.   
`-all`: Run all the checks and hardening tasks.

### Command Line Arguments
```bash 
sudo ./security-checks.sh [ -usr-grp-audit | -check-perms | -service-audit |  -check-firewall |  -check-ip | -check-update |  -check-log | -hardern-ssh | -disable-ipv6 | -secure-grub | -configure-iptables | -auto-update | -execute_check | -all ]
```

### Examples
To run all checks and hardening tasks:
```bash
sudo ./script.sh -all
```

To check permissions and audit services only:
```bash
sudo ./script.sh -check-perms -service-audit
```

## Configuration
#### Configuration File (config.conf)
- This file is read by the execute_checks function.
- Place additional checks or commands in this file as needed.
#### Modify Email Addresses
- Update `EMAIL_RECIPIENT` and `EMAIL_SENDER` with appropriate email addresses.
#### Password for GRUB
- Set `GRUB_PASSWORD` with a secure password for the GRUB bootloader.
#### Disable IPv6
- Set `DISABLE_IPV6` to **true** if you want to disable IPv6.

## Audit and Hardening Functions

### 1. audit_users_groups

- Lists users and groups.
- Checks for UID 0 users (root access).
- Identifies users with weak or no passwords.

### 2. check_permissions

- Identifies world-writable files and directories.
- Checks .ssh directory permissions.
- Lists files with SUID/SGID bits set.

### 3. audit_services

- Lists all running services.
- Checks for unauthorized services.
- Verifies critical services are running.
- Checks for non-standard or insecure ports.

### 4. check_firewall

- Checks if iptables and ufw are active.
- Reviews firewall rules.
- Checks open ports and IP forwarding status.

### 5. check_ip_addr

- Classifies IP addresses as private or public.
- Secures SSH port access to trusted IPs.

### 6. check_updates

- Checks for available security updates.
- Ensures automatic security updates are configured.

### 7. check_logs

- Searches log files for suspicious entries (failed SSH login attempts).

### 8. harden_ssh

- Updates SSH configuration to disable password authentication and root login.
- Checks SSH key permissions.

### 9. disable_ipv6

- Disables IPv6 if configured to do so.
- Checks SafeSquid for IPv4.

### 10. secure_grub

- Secures the GRUB bootloader configuration.

### 11. configure_iptables

- Configures iptables rules to secure the system.

### 12. configure_auto_updates

- Configures automatic updates using unattended-upgrades.

### 13. execute_checks

- Reads and executes commands from a configuration file (config.conf).


