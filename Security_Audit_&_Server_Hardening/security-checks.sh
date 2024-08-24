#!/bin/bash

# Security Audit and Hardening Script
# Author: Ujwal Pachghare
# Description: This script performs security audits and hardens Linux servers.

# Define global variables
SUMMARY_REPORT="summary_report.txt"
EMAIL_RECIPIENT="admin@example.com"
EMAIL_SENDER="john.doe@example.com"
EMAIL_SUBJECT="Security Audit Alert: Critical Issues Found"

# Ensure the script is run as root
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root."
    exit 1
fi

# Function to print messages
print_msg() {
    local msg_type="$1"
    local msg="$2"
    case "$msg_type" in
    INFO) echo -e "\033[1;34m[INFO] $msg\033[0m" ;;
    WARN) echo -e "\033[1;33m[WARN] $msg\033[0m" ;;
    DATA) echo -e "\033[1;32m[DATA] $msg\033[0m" ;;
    ERROR) echo -e "\033[1;31m[ERROR] $msg\033[0m" ;;
    esac
}

# Function to initialize the summary report
initialize_summary_report() {
    echo "Security Audit and Hardening Report" >"$SUMMARY_REPORT"
    echo "===================================" >>"$SUMMARY_REPORT"
    echo "" >>"$SUMMARY_REPORT"
}

# Function to append to the summary report
append_to_summary_report() {
    local msg="$1"
    echo "$msg" >>"$SUMMARY_REPORT"
}

# Function to send email alerts
send_email_alert() {
    local subject="$1"
    local body="$2"
    echo "$body" | mail -s "$subject" -r "$EMAIL_SENDER" "$EMAIL_RECIPIENT"
}

# Function to list all users and groups
audit_users_groups() {
    local output
    local critical_issues=0
    output=$(mktemp)
    {
        print_msg INFO "List of all users:"
        getent passwd | awk -F: '{ print $1, $3 }' | sort
        echo ""

        print_msg INFO "List of all groups:"
        getent group | awk -F: '{ print $1 }' | sort
        echo ""

        print_msg INFO "Checking for UID 0 users:"
        awk -F: '$3 == 0 { print $1 }' /etc/passwd
        echo ""

        print_msg INFO "Checking for users without passwords or with weak passwords:"
        sudo awk -F: '($2 == "" || $2 == "*" || $2 == "!" || $2 == "!*") {print $1}' /etc/shadow
        echo ""
    } >"$output"

    append_to_summary_report "Audit Users and Groups:"
    cat "$output"
    append_to_summary_report "---------------------------------"

    if [ $critical_issues -eq 1 ]; then
        send_email_alert "$EMAIL_SUBJECT" "Critical issues found during user and group audit. Please check the attached summary report."
    fi
}

# Function to check file and directory permissions
check_permissions() {
    local output
    local critical_issues=0
    output=$(mktemp)
    {
        print_msg INFO "Files and directories with world-writable permissions:"
        find / -not -type l -perm -777 -print
        echo ""

        print_msg INFO "Checking .ssh directory permissions:"
        if [ $(find / -type d -name ".ssh" -exec stat -c "%a" {} \;) -eq 700 ]; then
            print_msg DATA "Secured"
        else
            print_msg WARN "Not Secured"
        fi
        echo ""

        print_msg INFO "Files with SUID/SGID bits set:"
        find / -type f -user root -perm -6000 -exec ls -ldb {} \;
        echo ""
    } > "$output"

    append_to_summary_report "Check Permissions:"
    cat "$output"
    append_to_summary_report "---------------------------------"

    if [ $critical_issues -eq 1 ]; then
        send_email_alert "$EMAIL_SUBJECT" "Critical issues found during user and group audit. Please check the attached summary report."
    fi
}

# Function to audit services
audit_services() {
    local output
    local critical_issues=0
    output=$(mktemp)
    {
        AUTHORIZED_SERVICES=(
            "sshd"
            "cron"
            "nginx"
            "apache2"
            "mysql"
            # Add other authorized services here
        )

        AUTHORIZED_SERVICES_STR=$(printf "%s\n" "${AUTHORIZED_SERVICES[@]}")
        if command -v systemctl; then
            RUNNING_SERVICES=$(systemctl --type=service --state=running --no-pager | awk '{print $1}' | sed 's/.service//')
        else
            RUNNING_SERVICES=$(service --status-all | grep '+' | awk '{print $4}')
        fi
        echo ""

        print_msg INFO "List of all running services:"
        ss -tuln

        print_msg INFO "Checking for unauthorized services:"
        for service in $RUNNING_SERVICES; do
            if ! echo "$AUTHORIZED_SERVICES_STR" | grep -q -w "$service"; then
                print_msg WARN "Unauthorized or unnecessary service found: $service"
            fi
        done
        echo ""

        print_msg INFO "Ensuring critical services are running:"
        for service in $AUTHORIZED_SERVICES; do
            print_msg DATA "$service is running"
        done
        echo ""

        print_msg INFO "Checking for non-standard or insecure ports:"
        netstat -tuln
        echo ""
    } >"$output"

    append_to_summary_report "Audit Services:"
    cat "$output"
    append_to_summary_report "---------------------------------"

    if [ $critical_issues -eq 1 ]; then
        send_email_alert "$EMAIL_SUBJECT" "Critical issues found during user and group audit. Please check the attached summary report."
    fi
}

# Function to verify firewall and network security
check_firewall() {
    local output
    local critical_issues=0
    output=$(mktemp)
    {
        print_msg INFO "Checking if iptables is active:"
        iptables -L -n -v
        echo ""

        print_msg INFO "Checking if ufw is active:"
        ufw status verbose
        echo ""

        print_msg WARN "Please manually review the firewall rules to Verify that unauthorized ports are blocked."
        echo ""

        # Function to check for open ports and services
        print_msg INFO "Checking open ports and services..."
        sudo netstat -tuln
        echo ""

        # Function to check IP forwarding status
        print_msg INFO "Checking IP forwarding..."
        ip_forwarding=$(sysctl net.ipv4.ip_forward | awk '{print $3}')
        print_msg WARN "IP forwarding status: $ip_forwarding"
        echo ""
    } >"$output"

    append_to_summary_report "Check Firewall:"
    cat "$output"
    append_to_summary_report "---------------------------------"

    if [ $critical_issues -eq 1 ]; then
        send_email_alert "$EMAIL_SUBJECT" "Critical issues found during user and group audit. Please check the attached summary report."
    fi
}

check_ip_addr() {
    local output
    local critical_issues=0
    output=$(mktemp)
    {
        # check IP addresses and classify them
        print_msg INFO "Checking IP addresses..."
        ip addr show | grep 'inet\|inet6' | while read -r line; do
            ip_addr=$(echo "$line" | awk '{print $2}')
            if [[ "$ip_addr" =~ ^10\. || "$ip_addr" =~ ^172\.1[6-9]\. || "$ip_addr" =~ ^172\.2[0-9]\. || "$ip_addr" =~ ^192\.168\. ]]; then
                print_msg DATA "Private IP Address: $ip_addr"
            else
                print_msg DATA "Public IP Address: $ip_addr"
            fi
        done
        echo ""

        # Ensuring only trusted ips can access port 22
        print_msg INFO "Securing SSH port..."
        sudo ufw allow from 127.0.0.1 to any port 22
        sudo ufw delete allow 22
        echo ""
    } >"$output"

    append_to_summary_report "Check IP Address:"
    cat "$output"
    append_to_summary_report "---------------------------------"

    if [ $critical_issues -eq 1 ]; then
        send_email_alert "$EMAIL_SUBJECT" "Critical issues found during user and group audit. Please check the attached summary report."
    fi
}

# Function to check for available security updates
check_updates() {
    local output
    local critical_issues=0
    output=$(mktemp)
    {
        print_msg INFO "Checking for available security updates..."
        if command -v apt-get; then
            apt-get update && apt-get upgrade -s | grep "upgraded"
        elif command -v yum; then
            yum check-update
        else
            print_msg WARN "No known package manager (apt-get or yum) found."
        fi
        echo ""

        print_msg INFO "Ensuring server is configured to install security updates regularly..."
        grep -q "1" /etc/apt/apt.conf.d/20auto-upgrades
        # Check the exit status of the grep command
        if [ $? -eq 0 ]; then
            print_msg DATA "Server is configured to install security updates regularly"
        else
            print_msg WARN "Server is not configured to install security updates regularly"
        fi
        echo ""
    } >"$output"

    append_to_summary_report "Check Updates:"
    cat "$output"
    append_to_summary_report "---------------------------------"

    if [ $critical_issues -eq 1 ]; then
        send_email_alert "$EMAIL_SUBJECT" "Critical issues found during user and group audit. Please check the attached summary report."
    fi
}

# Function to check log files for suspicious entries
check_logs() {
    local output
    local critical_issues=0
    output=$(mktemp)
    {
        print_msg INFO "Checking log files for suspicious entries..."
        if [[ -f "/var/log/auth.log" ]]; then
            grep 'Failed password' /var/log/auth.log
        elif [[ -f "/var/log/secure" ]]; then
            grep 'Failed password' /var/log/secure
        else
            print_msg WARN "No log file found for SSH authentication."
        fi
        echo ""
    } >"$output"

    append_to_summary_report "Check Logs:"
    cat "$output"
    append_to_summary_report "---------------------------------"

    if [ $critical_issues -eq 1 ]; then
        send_email_alert "$EMAIL_SUBJECT" "Critical issues found during user and group audit. Please check the attached summary report."
    fi
}

# Function to harden SSH configuration
harden_ssh() {
    local output
    local critical_issues=0
    output=$(mktemp)
    {
        print_msg INFO "Hardening SSH configuration..."
        if [[ -f "/etc/ssh/sshd_config" ]]; then
            sed -i 's/^#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
            sed -i 's/^#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
            systemctl reload sshd
            print_msg INFO "SSH configuration updated and service reloaded."
        else
            print_msg WARN "SSH configuration file not found."
        fi
        echo ""

        print_msg INFO "Ensuring that SSH keys are secure..."
        if [ $(stat -c %a ~/.ssh/id_rsa 2>/dev/null) -eq 600 ] || [ $(stat -c %a /root/.ssh/id_rsa 2>/dev/null) -eq 600 ]; then
            print_msg DATA "Keys are secured"
        else
            print_msg WARN "Keys are not secured."
        fi
        echo ""
    } >"$output"

    append_to_summary_report "Harden SSH:"
    cat "$output"
    append_to_summary_report "---------------------------------"

    if [ $critical_issues -eq 1 ]; then
        send_email_alert "$EMAIL_SUBJECT" "Critical issues found during user and group audit. Please check the attached summary report."
    fi
}

# Function to disable IPv6 if not required
disable_ipv6() {
    local output
    local critical_issues=0
    output=$(mktemp)
    {
        print_msg INFO "Disabling IPv6..."
        if [[ "$DISABLE_IPV6" == "true" ]]; then
            sysctl -w net.ipv6.conf.all.disable_ipv6=1
            sysctl -w net.ipv6.conf.default.disable_ipv6=1
            sysctl -w net.ipv6.conf.lo.disable_ipv6=1
            print_msg INFO "IPv6 has been disabled."
        else
            print_msg WARN "IPv6 disabling is not configured."
        fi
        echo ""

        print_msg INFO "Checking ipv4 for safesquide"
        if ! pgrep -x "safesquid" >/dev/null; then
            print_msg WARN "SafeSquid is not running."
        else
            print_msg INFO "Checking SafeSquid with default port 8080"
            ss -tuln | grep 8080
            if [$? -eq 0]; then
                print_msg DATA "Checking Successful of SafeSquid for ipv4"
            else
                print_msg WARN "Checking Failed of SafeSquid for ipv4"
            fi
        fi
        echo ""
    } >"$output"

    append_to_summary_report "Disable IPv6:"
    cat "$output"
    append_to_summary_report "---------------------------------"

    if [ $critical_issues -eq 1 ]; then
        send_email_alert "$EMAIL_SUBJECT" "Critical issues found during user and group audit. Please check the attached summary report."
    fi
}

# Function to secure GRUB bootloader
secure_grub() {
    local output
    local critical_issues=0
    output=$(mktemp)
    {
        print_msg INFO "Securing GRUB bootloader..."
        if [[ -f "/etc/default/grub" ]]; then
            echo "GRUB_PASSWORD=$GRUB_PASSWORD" >>/etc/default/grub
            grub-mkconfig -o /boot/grub/grub.cfg
            print_msg INFO "GRUB configuration updated."
        else
            print_msg WARN "GRUB configuration file not found."
        fi
    } >"$output"

    append_to_summary_report "Secure Grub:"
    cat "$output"
    append_to_summary_report "---------------------------------"

    if [ $critical_issues -eq 1 ]; then
        send_email_alert "$EMAIL_SUBJECT" "Critical issues found during user and group audit. Please check the attached summary report."
    fi
}

# Function to configure iptables rules
configure_iptables() {
    local output
    local critical_issues=0
    output=$(mktemp)
    {
        # Flush existing rules
        iptables -F
        iptables -t nat -F
        iptables -t mangle -F
        iptables -X

        # Set default policies to drop all traffic
        iptables -P INPUT DROP
        iptables -P FORWARD DROP
        iptables -P OUTPUT ACCEPT

        # Allow loopback interface traffic
        iptables -A INPUT -i lo -j ACCEPT
        iptables -A OUTPUT -o lo -j ACCEPT

        # Allow established and related incoming connections
        iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

        # Allow specific ports (modify as needed)
        iptables -A INPUT -p tcp --dport 22 -j ACCEPT
        iptables -A INPUT -p tcp --dport 80 -j ACCEPT
        iptables -A INPUT -p tcp --dport 443 -j ACCEPT

        # Allow ICMP (ping)
        iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT
        if command -v iptables-save; then
            if [ ! -d "/etc/iptables" ]; then
                print_msg INFO "Creating directory /etc/iptables/"
                mkdir -p /etc/iptables
            fi
            iptables-save >/etc/iptables/rules.v4
            print_msg DATA "iptables rules saved to /etc/iptables/rules.v4"
        else
            print_msg WARN "iptables-save command not found. Cannot save rules."
        fi
        print_msg DATA "iptables rules have been configured and saved."
        print_msg ERROR "Please Press Enter to continue"
        echo ""
    } >"$output"

    append_to_summary_report "Configure IPtables:"
    cat "$output"
    append_to_summary_report "---------------------------------"

    if [ $critical_issues -eq 1 ]; then
        send_email_alert "$EMAIL_SUBJECT" "Critical issues found during user and group audit. Please check the attached summary report."
    fi
}

# Function to configure unattended-upgrades
configure_auto_updates() {
    local output
    local critical_issues=0
    output=$(mktemp)
    {
        print_msg INFO "Configuring automatic updates..."
        if command -v unattended-upgrade; then
            dpkg-reconfigure --priority=low unattended-upgrades
            print_msg INFO "Removing unused packages"
            sudo apt-get autoremove -y
            sudo apt-get autoclean -y
            sudo apt-get clean -y
        else
            echo "Installing unattended-upgrades..."
            apt-get install -y unattended-upgrades
            dpkg-reconfigure --priority=low unattended-upgrades
            print_msg INFO "Removing unused packages"
            sudo apt-get autoremove -y
            sudo apt-get autoclean -y
            sudo apt-get clean -y
        fi

        if [[ $USER == "root" ]]; then
            print_msg DATA "Unattended-upgrades configured."
        fi
        echo ""
    } >"$output"

    append_to_summary_report "Configure Auto Updates:"
    cat "$output"
    append_to_summary_report "---------------------------------"

    if [ $critical_issues -eq 1 ]; then
        send_email_alert "$EMAIL_SUBJECT" "Critical issues found during user and group audit. Please check the attached summary report."
    fi
}

execute_checks() {
    local output
    local critical_issues=0
    output=$(mktemp)
    {
        local config_file="./config.conf"

        print_msg INFO "Starting security checks..."
        # Check if the configuration file exists
        if [ ! -f "$config_file" ]; then
            print_msg ERROR "Configuration file '$config_file' not found!"
            exit 1
        fi

        # Read and execute commands from the configuration file
        while IFS= read -r line; do
            [[ -z "$line" || "$line" =~ ^# ]] && continue
            eval "$line"
            if [ $? -ne 0 ]; then
                print_msg WARN "Check failed: $line"
            else
                print_msg DATA "Check passed: $line"
            fi
        done <"$config_file"
        print_msg INFO "Security checks completed."
    } >"$output"

    append_to_summary_report "Execute Checks:"
    cat "$output"
    append_to_summary_report "---------------------------------"

    if [ $critical_issues -eq 1 ]; then
        send_email_alert "$EMAIL_SUBJECT" "Critical issues found during user and group audit. Please check the attached summary report."
    fi
}

# Function to handle command-line arguments
function custom_dashboard {
    initialize_summary_report

    print_msg INFO "Starting security checks..."

    while [[ $# -gt 0 ]]; do
        case $1 in
            -usr-grp-audit)
                audit_users_groups
                ;;
            -check-perms)
                check_permissions
                ;;
            -service-audit)
                audit_services
                ;;
            -check-firewall)
                check_firewall
                ;;
            -check-ip)
                check_ip_addr
                ;;
            -check-update)
                check_updates
                ;;
            -check-log)
                check_logs
                ;;
            -hardern-ssh)
                harden_ssh
                ;;
            -disable-ipv6)
                disable_ipv6
                ;;
            -secure-grub)
                secure_grub
                ;;
            -configure-iptables)
                configure_iptables
                ;;
            -auto-update)
                configure_auto_updates
                ;;
            -execute_check)
                execute_checks
                ;;
            -all)
                audit_users_groups
                check_permissions
                audit_services
                check_firewall
                check_ip_addr
                check_updates
                check_logs
                harden_ssh
                disable_ipv6
                secure_grub
                configure_iptables
                configure_auto_updates
                execute_checks
                print_msg INFO "Security checks completed."
                print_msg INFO "Summary report is generating at $SUMMARY_REPORT ........"
                send_email_alert "$EMAIL_SUBJECT" "Security audit completed. Please find the summary report attached."
                ;;
            *)
                echo "Invalid option: $1"
                echo "Usage: $0 [ -usr-grp-audit | -check-perms | -service-audit |  -check-firewall |  -check-ip | -check-update |  -check-log | -hardern-ssh | -disable-ipv6 | -secure-grub | -configure-iptables | -auto-update | -execute_check | -all ]"
                exit 1
                ;;
        esac
        shift
    done
}

# Check for command-line arguments
if [[ $# -eq 0 ]]; then
    echo "No options provided. Running all sections."
    custom_dashboard -all
else
    custom_dashboard "$@"
fi

print_msg INFO "Security checks completed."
