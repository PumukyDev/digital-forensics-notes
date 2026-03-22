#!/bin/bash

# --- Live Evidence Acquisition Script (Linux) ---
# This script collects live evidence from a running Linux system
# and stores it in a timestamped directory.

# 1. Setup
DATE_TIME=$(date +%Y%m%d_%H%M%S)
BASE_DIR="$(pwd)/evidence_$DATE_TIME"
mkdir -p "$BASE_DIR/logs" "$BASE_DIR/system" "$BASE_DIR/network" "$BASE_DIR/users"

echo "[+] Starting live evidence acquisition..."

# 2. System Information
date > "$BASE_DIR/system/01_system_date.txt"
hostname > "$BASE_DIR/system/02_hostname.txt"
uname -a > "$BASE_DIR/system/03_system_info.txt"
uptime > "$BASE_DIR/system/04_uptime.txt"
lscpu > "$BASE_DIR/system/05_cpu_info.txt"
cat /proc/cpuinfo > "$BASE_DIR/system/06_cpuinfo_raw.txt"
lsb_release -a > "$BASE_DIR/system/07_distro_info.txt"
ls -l /boot > "$BASE_DIR/system/08_boot_contents.txt"
env > "$BASE_DIR/system/09_environment_variables.txt"

# 3. Users and Logins
who > "$BASE_DIR/users/01_current_users.txt"
whoami > "$BASE_DIR/users/02_whoami.txt"
logname > "$BASE_DIR/users/03_logname.txt"
id > "$BASE_DIR/users/04_groups_id.txt"
# last > "$BASE_DIR/users/05_last_logins.txt"   # Removed for compatibility
# lastlog > "$BASE_DIR/users/06_last_login_per_user.txt" # Removed for compatibility
cp -a /etc/passwd "$BASE_DIR/users/etc_passwd.txt"
cp -a /etc/group "$BASE_DIR/users/etc_group.txt"

# Collect bash histories
for home_dir in /home/* /root; do
    user_name=$(basename "$home_dir")
    if [ -f "$home_dir/.bash_history" ]; then
        cp -a "$home_dir/.bash_history" "$BASE_DIR/users/history_$user_name.txt"
    fi
done

# 4. Processes and Memory
ps aux --forest > "$BASE_DIR/system/10_process_tree.txt"
pstree -ap > "$BASE_DIR/system/11_pstree_args.txt"
top -b -n1 > "$BASE_DIR/system/12_top_snapshot.txt"
free -m > "$BASE_DIR/system/13_memory_usage.txt"
ps -o rss,vsz,command -p $$ > "$BASE_DIR/system/14_script_memory.txt"
systemctl list-units --type=service --state=running > "$BASE_DIR/system/15_running_services.txt"

# 5. Storage and Disk
mount > "$BASE_DIR/system/16_mounted_devices.txt"
lsblk > "$BASE_DIR/system/17_partitions_lsblk.txt"
fdisk -l > "$BASE_DIR/system/18_partitions_fdisk.txt"
df -h > "$BASE_DIR/system/19_disk_usage.txt"

# 6. Kernel and Modules
lsmod > "$BASE_DIR/system/20_loaded_modules.txt"
cat /proc/modules > "$BASE_DIR/system/21_all_modules.txt"
cat /proc/cmdline > "$BASE_DIR/system/22_kernel_boot_params.txt"

# Optional: Apache modules if installed (warnings silenced)
if command -v apache2ctl >/dev/null 2>&1; then
    apache2ctl -M &> "$BASE_DIR/system/23_apache_modules.txt"
fi

# 7. Network and Connectivity
ip addr > "$BASE_DIR/network/01_network_interfaces.txt"
ss -tunap > "$BASE_DIR/network/02_current_connections.txt"
ss -s > "$BASE_DIR/network/03_socket_stats.txt"
ss -lntu > "$BASE_DIR/network/04_open_ports.txt"
ip route > "$BASE_DIR/network/05_routing_table.txt"
ip neigh > "$BASE_DIR/network/06_arp_table.txt"
cat /etc/hosts > "$BASE_DIR/network/07_static_hosts.txt"
cat /etc/hosts.allow > "$BASE_DIR/network/08_allowed_hosts.txt"
cat /etc/hosts.deny > "$BASE_DIR/network/09_denied_hosts.txt"
cat /etc/resolv.conf > "$BASE_DIR/network/10_dns_gateway.txt"

# 8. Logs
cp -a /var/log/* "$BASE_DIR/logs/" 2>/dev/null

# 9. SUID/GUID Files
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null > "$BASE_DIR/system/24_suid_guid_files.txt"

# 10. Generate SHA256 Hashes
echo "[+] Generating SHA256 checksums..."
cd "$BASE_DIR"
find . -type f -exec sha256sum {} + > "$BASE_DIR/checksums_sha256.txt"

echo "[SUCCESS] Evidence stored in $BASE_DIR"