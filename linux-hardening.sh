#!/bin/bash
set -euo pipefail
LOGDIR="/home/centos/poc/logs"
mkdir -p "$LOGDIR"
LOGFILE="/home/centos/poc/logs/linux-hardening-$(date +%Y%m%d-%H%M%S).log"
exec > >(tee -a "$LOGFILE") 2>&1

echo "========================================"
echo "Linux Server Hardening - $(date)"
echo "========================================"

# --------------------------------------------
# 1. SELINUX — disable
# --------------------------------------------
echo "[1] Disabling SELinux..."
if [[ -f /etc/selinux/config ]]; then
    sed -i 's/^SELINUX=.*/SELINUX=disabled/' /etc/selinux/config
    echo "  SELINUX set to disabled in config"
fi

# --------------------------------------------
# 2. SYSCTL — kernel tuning
# --------------------------------------------
echo "[2] Applying sysctl kernel tuning..."

SYSCTL_FILE="/etc/sysctl.d/99-sysctl.conf.conf"

# Build config content
read -r -d '' SYSCTL_CONFIG << 'EOF' || true
# Custom kernel tuning — applied idempotently
net.ipv4.ip_local_port_range = 10000 65000
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_fin_timeout = 30
net.core.somaxconn = 10240
fs.inotify.max_user_instances = 256
fs.inotify.max_user_watches = 16384
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
EOF

# Backup old config if exists
if [[ -f "$SYSCTL_FILE" ]]; then
    cp "$SYSCTL_FILE" "${SYSCTL_FILE}.bak.$(date +%Y%m%d%H%M%S)"
fi
# List of keys to update
SYSCTL_KEYS="net.ipv4.ip_local_port_range net.ipv4.tcp_window_scaling net.ipv4.tcp_fin_timeout net.core.somaxconn fs.inotify.max_user_instances fs.inotify.max_user_watches net.ipv4.conf.all.rp_filter net.ipv4.conf.default.rp_filter net.ipv6.conf.all.disable_ipv6 net.ipv6.conf.default.disable_ipv6"

# Process each key=value: comment out existing line, then append our line
while IFS='=' read -r key value; do
    # Remove leading/trailing whitespace
    key=$(echo "$key" | xargs)
    value=$(echo "$value" | xargs)
    # Skip empty lines and comments
    [[ -z "$key" || "$key" =~ ^# ]] && continue
    # Comment out any existing line for this key (handles spaces around =)
    sed -i "s/^${key}[[:space:]]*=[[:space:]]*/# &/" "$SYSCTL_FILE" 2>/dev/null || true
    # Append our desired line
    echo "${key} = ${value}" >> "$SYSCTL_FILE"
done <<< "$SYSCTL_CONFIG"

# Apply the settings
sysctl -p "$SYSCTL_FILE" >/dev/null 2>&1
echo "  sysctl tuning applied via $SYSCTL_FILE"

# Remove entries from /etc/sysctl.conf if they were added there previously
for key in $SYSCTL_KEYS; do
    sed -i "/^${key}[[:space:]]*=/d" /etc/sysctl.conf 2>/dev/null || true
done

# --------------------------------------------
# 3. LIMITS — file descriptors
# --------------------------------------------
echo "[3] Setting file descriptor limits..."

if grep -q "^\*\s\+soft\s\+nofile" /etc/security/limits.conf; then
    sed -i 's/^\*\s\+soft\s\+nofile.*/* soft nofile 65536/' /etc/security/limits.conf
else
    echo "* soft nofile 65536" >> /etc/security/limits.conf
fi

if grep -q "^\*\s\+hard\s\+nofile" /etc/security/limits.conf; then
    sed -i 's/^\*\s\+hard\s\+nofile.*/* hard nofile 65536/' /etc/security/limits.conf
else
    echo "* hard nofile 65536" >> /etc/security/limits.conf
fi
echo "  limits.conf updated (nofile 65536)"

# --------------------------------------------
# 4. PROFILE — ulimit
# --------------------------------------------
echo "[4] Setting ulimit in /etc/profile..."

if grep -q "^ulimit -n 65536" /etc/profile; then
    echo "  ulimit already present in /etc/profile"
else
    echo "" >> /etc/profile
    echo "# Custom ulimit settings" >> /etc/profile
    echo "ulimit -n 65536" >> /etc/profile
    echo "  ulimit added to /etc/profile"
fi

# --------------------------------------------
# 5. BASH COMPLETION (source if exists)
# --------------------------------------------
echo "[5] Checking bash_completion..."
if [[ -f /etc/profile.d/bash_completion.sh ]]; then
    # shellcheck source=/dev/null
    source /etc/profile.d/bash_completion.sh
    echo "  bash_completion sourced"
else
    echo "  bash_completion not found — skipping"
fi

# --------------------------------------------
# 6. SSH HARDENING
# --------------------------------------------
echo "[6] Hardening SSH configuration..."

SSHD_CONF="/etc/ssh/sshd_config"
[[ -f "$SSHD_CONF" ]] && cp "$SSHD_CONF" "${SSHD_CONF}.bak.$(date +%Y%m%d%H%M%S)"

apply_sshd_setting() {
    local key="$1"
    local value="$2"
    # Remove any existing line (commented or uncommented)
    sed -i "/^[#[:space:]]*${key}[[:space:]]/d" "$SSHD_CONF"
    # Add at top of file for precedence
    sed -i "1i${key} ${value}" "$SSHD_CONF"
}

apply_sshd_setting "PermitRootLogin" "no"
apply_sshd_setting "Protocol" "2"
apply_sshd_setting "X11Forwarding" "no"
apply_sshd_setting "MaxAuthTries" "4"
apply_sshd_setting "ClientAliveInterval" "300"
apply_sshd_setting "ClientAliveCountMax" "0"
apply_sshd_setting "PasswordAuthentication" "no"

sshd -t && systemctl restart sshd && echo "  SSH hardening applied and restarted" \
    || echo "  FAIL: sshd config invalid — check ${SSHD_CONF}"

# --------------------------------------------
# 7. AUDITD
# --------------------------------------------
echo "[7] Configuring auditd..."

systemctl enable --now auditd 2>/dev/null || true

AUDIT_CONF="/etc/audit/auditd.conf"

if [[ -f "$AUDIT_CONF" ]]; then
    cp "$AUDIT_CONF" "${AUDIT_CONF}.bak.$(date +%Y%m%d%H%M%S)"

    if grep -q "^max_log_file_action" "$AUDIT_CONF"; then
        sed -i 's/^max_log_file_action[[:space:]]*=.*/max_log_file_action = ROTATE/' "$AUDIT_CONF"
        echo "  max_log_file_action updated to ROTATE"
    else
        echo "max_log_file_action = ROTATE" >> "$AUDIT_CONF"
        echo "  max_log_file_action = ROTATE added"
    fi
else
    mkdir -p /etc/audit
    cat > "$AUDIT_CONF" << 'EOF'
# Auditd config — created by hardening script
max_log_file_action = ROTATE
log_file = /var/log/audit/audit.log
log_format = RAW
flush = INCREMENTAL
freq = 50
max_log_file = 256
num_logs = 10
space_left_action = SYSLOG
admin_space_left_action = SUSPEND
disk_full_action = SUSPEND
disk_error_action = SUSPEND
EOF
    echo "  auditd.conf created with ROTATE"
fi

systemctl restart auditd 2>/dev/null || true
echo "  auditd restarted"

# --------------------------------------------
# SUMMARY
# --------------------------------------------
echo ""
echo "========================================"
echo "Hardening Complete"
echo "Log: $LOGFILE"
echo "========================================"
echo ""
echo "IMPORTANT: Test SSH access in a NEW session before disconnecting."
echo "PasswordAuthentication is now OFF — ensure SSH keys are deployed."
echo "========================================"
