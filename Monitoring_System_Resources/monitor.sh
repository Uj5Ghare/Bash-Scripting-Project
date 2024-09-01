#!/bin/bash

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

# Function to display the top 10 most used applications
function top_apps {
    print_msg INFO "Top 10 Most Used Applications:"
    echo "---------------------------------"
    ps aux --sort=-%cpu,%mem | head -n 11 | sed '1d'
    echo ""
    echo ""
}

# Function to display network monitoring information
function network_monitor {
    print_msg INFO "Network Monitoring:"
    echo "--------------------"
    print_msg DATA "No of concurrent connection:"
    netstat -an | grep ESTABLISHED | wc -l
    print_msg WARN "Packet drops:"
    netstat -i | grep 'eth0' | awk '{print $6}'
    print_msg WARN "Network usage (MB in/out):"
    vnstat --oneline | awk -F';' '{print $1}'
    echo ""
}

# Function to display disk usage
function disk_usage {
    print_msg INFO "Disk Usage:"
    echo "-------------"
    df -h
    echo ""
    print_msg INFO "Partitions using more than 80% of space:"
    df -h | awk '{if ($5+0 > 80) print $0}'
    echo ""
}

# Function to display system load
function system_load {
    print_msg INFO "System Load:"
    echo "--------------"
    uptime
    echo ""
    print_msg INFO "CPU usage breakdown:"
    mpstat
    echo ""
}

# Function to display memory usage
function memory_usage {
    print_msg INFO "Memory Usage:"
    echo "---------------"
    free -h
    echo ""
    print_msg INF "Swap memory usage:"
    swapon --show
    echo ""
}

# Function to display process monitoring
function process_monitor {
    print_msg INFO "Process Monitoring:"
    echo "--------------------"
    print_msg DATA "Number of active processes:"
    ps aux | wc -l
    echo ""
    print_msg DATA "Top 5 processes by CPU usage:"
    ps aux --sort=-%cpu,%mem | head -n 6
    echo ""
}

# Function to display service monitoring
function service_monitor {
    print_msg INFO "Service Monitoring:"
    echo "---------------------"
#   systemctl status sshd nginx apache2 iptables | grep 'Active'
    echo "Nginx: $(systemctl is-active nginx)"
    echo "sshd: $(systemctl is-active sshd)"
    echo "Apache2: $(systemctl is-active apache2)"
    echo "Iptables: $(systemctl is-active iptables)"
    echo ""
}

# Function to handle command-line arguments
function custom_dashboard {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -cpu)
                top_apps
                ;;
            -memory)
                memory_usage
                ;;
            -network)
                network_monitor
                ;;
            -disk)
                disk_usage
                ;;
            -load)
                system_load
                ;;
            -process)
                process_monitor
                ;;
            -service)
                service_monitor
                ;;
            -all)
                top_apps
                memory_usage
                network_monitor
                disk_usage
                system_load
                process_monitor
                service_monitor
                ;;
            *)
                print_msg WARN "Invalid option: $1"
                print_msg DATA "Usage: $0 [-cpu | -memory | -network | -disk | -load | -process | -service | -all]"
                exit 1
                ;;
        esac
        shift
    done
}

# Check for command-line arguments
if [[ $# -eq 0 ]]; then
    print_msg WARN "No options provided. Running all sections."
    custom_dashboard -all
else
    custom_dashboard "$@"
fi
