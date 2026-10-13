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
# Exposed Database Credentials
echo -e "${BLUE}[*] Checking for Exposed Database URIs...${NC}"
while IFS= read -r match; do
    [ -n "$match" ] && log_finding "HIGH" "Database Connection String Detected" "$match"
done < <(grep -Ei $GREP_OPTS "(mongodb(\+srv)?|postgres(ql)?|mysql)://[a-zA-Z0-9_]+:[^@\s]+@" "$TARGET_DIR" 2>/dev/null)

# Insecure HTTP Traffic
echo -e "${BLUE}[*] Checking for Unencrypted HTTP Usage...${NC}"
while IFS= read -r match; do
    [ -n "$match" ] && log_finding "MEDIUM" "Insecure HTTP URL Detected (Use HTTPS)" "$match"
done < <(grep -Ei $GREP_OPTS "http://[a-zA-Z0-9\-\.]+" "$TARGET_DIR" | grep -v "http://localhost\|http://127.0.0.1" 2>/dev/null)

# Public .env Files
echo -e "${BLUE}[*] Checking for Exposed .env Files...${NC}"
ENV_FILES=$(find "$TARGET_DIR" -type f -name "*.env" 2>/dev/null)
if [ -n "$ENV_FILES" ]; then
    for file in $ENV_FILES; do
        log_finding "HIGH" "Exposed .env Configuration File" "$file"
    done
fi

# JWT Secrets & Hardcoded API Keys
echo -e "${BLUE}[*] Checking for JWT Secrets & Common API Keys...${NC}"
while IFS= read -r match; do
    [ -n "$match" ] && log_finding "HIGH" "Potential JWT Secret or API Key" "$match"
done < <(grep -Ei $GREP_OPTS "(jwt_secret|jwt_key|sk_test_|sk_live_|AIza[0-9A-Za-z-_]{35})[[:space:]]*[:=]" "$TARGET_DIR" 2>/dev/null)

# Verbose Production Errors & Exposed Logs
echo -e "${BLUE}[*] Checking for Verbose Logging (Debug/Errors)...${NC}"
while IFS= read -r match; do
    [ -n "$match" ] && log_finding "LOW" "Verbose Logging Command Detected" "$match"
done < <(grep -Ei $GREP_OPTS "\b(console\.log|print_r|var_dump)\(" "$TARGET_DIR" 2>/dev/null)
echo "" | tee -a "$REPORT_FILE"
echo "==========================================================" | tee -a "$REPORT_FILE"
if [ "$TOTAL_ISSUES" -eq 0 ]; then
    echo -e "${GREEN}Scan Complete: No basic vulnerabilities identified.${NC}" | tee -a "$REPORT_FILE"
else
    echo -e "${RED}Scan Complete: $TOTAL_ISSUES potential vulnerability flag(s) identified.${NC}" | tee -a "$REPORT_FILE"
fi
echo "Log stored in: $REPORT_FILE" | tee -a "$REPORT_FILE"
echo "==========================================================" | tee -a "$REPORT_FILE"
