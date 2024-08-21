## This script provides a dashboard for monitoring various system resources and allows users to call specific parts of the dashboard using command-line switches.

### Usage:
- Save script as: **monitor.sh** <br>
- Make it executable: **chmod +x monitor.sh** <br>
- Run it: **./monitor.sh [-cpu | -memory | -network | -disk | -load | -process | -service | -all]**

### Explanation:

1. #### Top Applications (-cpu):  **Displays the top 10 CPU and memory-consuming applications.**

2. #### Network Monitoring (-network):  *Shows the number of concurrent connections, packet drops, and network usage.*

3. #### Disk Usage (-disk):  *Displays disk space usage and highlights partitions using more than 80% of their space.*

4. #### System Load (-load):  *Shows the current system load and CPU usage breakdown.*

5. #### Memory Usage (-memory):  *Provides information on total, used, free, and swap memory.*

6. #### Process Monitoring (-process):  *Displays the number of active processes and top 5 processes by CPU and memory usage.*

7. #### Service Monitoring (-service):  *Shows the status of essential services like sshd, nginx, apache2, and iptables.*

8. #### Custom Dashboard (-all):  *Allows users to call specific sections or all sections of the dashboard using command-line switches.*
