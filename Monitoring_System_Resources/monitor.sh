#!/bin/bash

# Function to display the top 10 most used applications
function top_apps {
    echo "Top 10 Most Used Applications:"
    echo "---------------------------------"
    ps aux --sort=-%cpu,%mem | head -n 11 | sed '1d'
    echo ""
    echo ""
}

# Function to display network monitoring information
function network_monitor {
    echo "Network Monitoring:"
    echo "--------------------"
    echo "No of concurrent connection:"
    netstat -an | grep ESTABLISHED | wc -l
    echo "Packet drops:"
    netstat -i | grep 'eth0' | awk '{print $6}'
    echo "Network usage (MB in/out):"
    vnstat --oneline | awk -F';' '{print $1}'
    echo ""
}

# Function to display disk usage
function disk_usage {
    echo "Disk Usage:"
    echo "-------------"
    df -h
    echo ""
    echo "Partitions using more than 80% of space:"
    df -h | awk '{if ($5+0 > 80) print $0}'
    echo ""
}

# Function to display system load
function system_load {
    echo "System Load:"
    echo "--------------"
    uptime
    echo ""
    echo "CPU usage breakdown:"
    mpstat
    echo ""
}

# Function to display memory usage
function memory_usage {
    echo "Memory Usage:"
    echo "---------------"
    free -h
    echo ""
    echo "Swap memory usage:"
    swapon --show
    echo ""
}

# Function to display process monitoring
function process_monitor {
    echo "Process Monitoring:"
    echo "--------------------"
    echo "Number of active processes:"
    ps aux | wc -l
    echo ""
    echo "Top 5 processes by CPU usage:"
    ps aux --sort=-%cpu,%mem | head -n 6
    echo ""
}

# Function to display service monitoring
function service_monitor {
    echo "Service Monitoring:"
    echo "---------------------"
#    systemctl status sshd nginx apache2 iptables | grep 'Active'
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
                echo "Invalid option: $1"
                echo "Usage: $0 [-cpu | -memory | -network | -disk | -load | -process | -service | -all]"
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
