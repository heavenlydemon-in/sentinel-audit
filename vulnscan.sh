#!/usr/bin/env bash
#
# VulnScan: Static Vulnerability Scanner for Server Source Code
#

TARGET_DIR="${1:-.}"
REPORT_FILE="vulnerability_scan_$(date +%Y%m%d_%H%M%S).log"
TOTAL_ISSUES=0

RED="\033[0;31m"
YELLOW="\033[0;33m"
GREEN="\033[0;32m"
BLUE="\033[0;34m"
NC="\033[0m"

log_finding() {
    local severity="$1"
    local desc="$2"
    local file_line="$3"
    local color="$NC"

    if [ "$severity" == "HIGH" ]; then
        color="$RED"
    elif [ "$severity" == "MEDIUM" ]; then
        color="$YELLOW"
    fi

    echo -e "${color}[$severity]${NC} $desc -> $file_line" | tee -a "$REPORT_FILE"
    ((TOTAL_ISSUES++))
}

echo "==========================================================" | tee "$REPORT_FILE"
echo "  VULNSCAN: SOURCE CODE STATIC SECURITY AUDITOR           " | tee -a "$REPORT_FILE"
echo "  Scanning Path: $TARGET_DIR                              " | tee -a "$REPORT_FILE"
echo "  Timestamp:     $(date)                                  " | tee -a "$REPORT_FILE"
echo "==========================================================" | tee -a "$REPORT_FILE"
echo "" | tee -a "$REPORT_FILE"

# Exclude version control directories
GREP_OPTS="-rnI --exclude-dir=.git --exclude-dir=node_modules --exclude=*.log"

echo -e "${BLUE}[*] Checking for Exposed Credentials & Private Keys...${NC}"
# Check for RSA/SSH private keys committed to source
while IFS= read -r match; do
    [ -n "$match" ] && log_finding "HIGH" "Private Key Detected" "$match"
done < <(grep $GREP_OPTS "BEGIN PRIVATE KEY\|BEGIN RSA PRIVATE KEY" "$TARGET_DIR" 2>/dev/null)

# Check for hardcoded credentials
while IFS= read -r match; do
    [ -n "$match" ] && log_finding "HIGH" "Potential Hardcoded Secret/Token" "$match"
done < <(grep -Ei $GREP_OPTS "(password|secret|api_key|token)[[:space:]]*[:=][[:space:]]*['\"][a-zA-Z0-9_\-]{8,}['\"]" "$TARGET_DIR" 2>/dev/null)

echo -e "${BLUE}[*] Checking for Remote Code & Command Injection Vectors...${NC}"
# Shell execution calls (Python, Node.js, PHP, C)
while IFS= read -r match; do
    [ -n "$match" ] && log_finding "HIGH" "Dangerous Execution Vector (os.system/eval/exec)" "$match"
done < <(grep -Ei $GREP_OPTS "\b(eval\(|os\.system\(|subprocess\.Popen\(|child_process\.exec\()" "$TARGET_DIR" 2>/dev/null)

echo -e "${BLUE}[*] Checking for Insecure Network & Transport Configurations...${NC}"
# Disabled TLS/SSL certificate checks
while IFS= read -r match; do
    [ -n "$match" ] && log_finding "MEDIUM" "Disabled SSL/TLS Certificate Verification" "$match"
done < <(grep -Ei $GREP_OPTS "verify[[:space:]]*=[[:space:]]*False|rejectUnauthorized[[:space:]]*:[[:space:]]*false" "$TARGET_DIR" 2>/dev/null)

# Public interface exposure
while IFS= read -r match; do
    [ -n "$match" ] && log_finding "MEDIUM" "Server Bound to All Interfaces (0.0.0.0)" "$match"
done < <(grep -Ei $GREP_OPTS "(host|bind|address)[[:space:]]*[:=][[:space:]]*['\"]0\.0\.0\.0['\"]" "$TARGET_DIR" 2>/dev/null)

# Permissive CORS headers
while IFS= read -r match; do
    [ -n "$match" ] && log_finding "MEDIUM" "Permissive Wildcard CORS Configuration" "$match"
done < <(grep -Ei $GREP_OPTS "Access-Control-Allow-Origin['\"][[:space:]]*:[[:space:]]*['\"]\*" "$TARGET_DIR" 2>/dev/null)

echo "" | tee -a "$REPORT_FILE"
echo "==========================================================" | tee -a "$REPORT_FILE"
if [ "$TOTAL_ISSUES" -eq 0 ]; then
    echo -e "${GREEN}Scan Complete: No basic vulnerabilities identified.${NC}" | tee -a "$REPORT_FILE"
else
    echo -e "${RED}Scan Complete: $TOTAL_ISSUES potential vulnerability flag(s) identified.${NC}" | tee -a "$REPORT_FILE"
fi
echo "Log stored in: $REPORT_FILE" | tee -a "$REPORT_FILE"
echo "==========================================================" | tee -a "$REPORT_FILE"
