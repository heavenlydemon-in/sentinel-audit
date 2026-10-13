#!/usr/bin/env bash
#
# Sentinel: Linux System Security & Compliance Auditor
#

LOGFILE="audit_report_$(date +%Y%m%d_%H%M%S).txt"
SCORE=100

log_status() {
    local status="$1"
    local message="$2"
    echo -e "[$status] $message" | tee -a "$LOGFILE"
}

# 1. Enforce Execution Environment
if [ "$EUID" -ne 0 ]; then
    echo "[-] Error: Sentinel must be executed with root/sudo privileges."
    exit 1
fi

echo "=============================================" | tee "$LOGFILE"
echo "  SENTINEL: AUTOMATED SECURITY AUDIT REPORT  " | tee -a "$LOGFILE"
echo "  Timestamp: $(date)                         " | tee -a "$LOGFILE"
echo "=============================================" | tee -a "$LOGFILE"
echo "" | tee -a "$LOGFILE"

# 2. Account Security & UID Audit
echo "--- 1. Account Integrity Checks ---" | tee -a "$LOGFILE"
UID_ZERO_COUNT=$(awk -F: '($3 == 0) { print $1 }' /etc/passwd | wc -l)
if [ "$UID_ZERO_COUNT" -gt 1 ]; then
    log_status "FAIL" "Multiple accounts detected with UID 0 (root level)!"
    SCORE=$((SCORE - 25))
else
    log_status "PASS" "Only standard root user possesses UID 0."
fi

# Check for blank passwords in /etc/shadow
EMPTY_PW_USERS=$(awk -F: '($2 == "" ) { print $1 }' /etc/shadow 2>/dev/null | wc -l)
if [ "$EMPTY_PW_USERS" -gt 0 ]; then
    log_status "FAIL" "Accounts with blank passwords detected in /etc/shadow!"
    SCORE=$((SCORE - 20))
else
    log_status "PASS" "No blank password entries found."
fi

# 3. Filesystem Vulnerability Inspection
echo "" | tee -a "$LOGFILE"
echo "--- 2. Filesystem Security ---" | tee -a "$LOGFILE"

# Look for world-writable directories lacking sticky bits (exclude virtual mounts)
WORLD_WRITABLE=$(find / -maxdepth 3 -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null | wc -l)
if [ "$WORLD_WRITABLE" -gt 0 ]; then
    log_status "WARN" "Found $WORLD_WRITABLE world-writable directories without sticky bit set."
    SCORE=$((SCORE - 15))
else
    log_status "PASS" "World-writable directory permissions conform to standard."
fi

# Verify /etc/shadow permissions
SHADOW_PERMS=$(stat -c "%a" /etc/shadow)
if [ "$SHADOW_PERMS" -eq 640 ] || [ "$SHADOW_PERMS" -eq 600 ] || [ "$SHADOW_PERMS" -eq 000 ]; then
    log_status "PASS" "/etc/shadow permissions securely restricted ($SHADOW_PERMS)."
else
    log_status "FAIL" "/etc/shadow permissions too permissive: $SHADOW_PERMS (Expected: 640/600/000)."
    SCORE=$((SCORE - 20))
fi

# 4. Network Exposure Check
echo "" | tee -a "$LOGFILE"
echo "--- 3. Network & Exposure Audit ---" | tee -a "$LOGFILE"
LISTEN_PORTS=$(ss -tuln | grep -c "LISTEN")
log_status "INFO" "Active listening ports identified: $LISTEN_PORTS"

# Check standard SSH root login policy if file exists
if [ -f /etc/ssh/sshd_config ]; then
    if grep -Eq "^PermitRootLogin\s+yes" /etc/ssh/sshd_config; then
        log_status "FAIL" "SSH configuration permits direct root login."
        SCORE=$((SCORE - 20))
    else
        log_status "PASS" "Direct SSH root login is disabled or protected."
    fi
else
    log_status "INFO" "OpenSSH server configuration file not present (Skipping SSH check)."
fi

# Final Summary
echo "" | tee -a "$LOGFILE"
echo "=============================================" | tee -a "$LOGFILE"
echo "  FINAL COMPLIANCE SCORE: $SCORE / 100        " | tee -a "$LOGFILE"
echo "=============================================" | tee -a "$LOGFILE"
echo "Detailed report written to: $LOGFILE"
