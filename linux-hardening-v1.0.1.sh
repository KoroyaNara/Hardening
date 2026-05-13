#!/bin/bash
# ==============================================================================
# Linux Blue Team Automation & Hardening Script
# Mode: --audit-only | --apply | --rollback | --help
# ==============================================================================

# Variables
MODE=$1
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_DIR="/root/blueteam_backup_$TIMESTAMP"
REPORT_FILE="/root/blueteam_report_$TIMESTAMP.txt"
SCORE=0

# Scoring Flags (10 points each)
FLAG_OS_ID=0
FLAG_BACKUP=0
FLAG_SSH_SAFE=0
FLAG_FW_ACTIVE=0
FLAG_F2B_ACTIVE=0
FLAG_WAZUH=0
FLAG_NO_UID0=0
FLAG_NO_BAD_CONN=0
FLAG_NO_BAD_CRON=0
FLAG_NO_WEBSHELL=0

# Formatting
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

log() { echo -e "${CYAN}[*]${NC} $1" | tee -a "$REPORT_FILE"; }
success() { echo -e "${GREEN}[+]${NC} $1" | tee -a "$REPORT_FILE"; }
warning() { echo -e "${YELLOW}[!]${NC} $1" | tee -a "$REPORT_FILE"; }
error() { echo -e "${RED}[x]${NC} $1" | tee -a "$REPORT_FILE"; }

show_help() {
    echo "Usage: ./blueteam-defender.sh [MODE]"
    echo "Modes:"
    echo "  --audit-only  : Hanya mengecek sistem dan membuat laporan. Tidak ada perubahan."
    echo "  --apply       : Melakukan backup lalu menerapkan hardening dasar yang aman."
    echo "  --rollback    : Mengembalikan konfigurasi dari direktori backup terakhir."
    echo "  --help        : Menampilkan bantuan ini."
    exit 0
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        error "Script harus dijalankan sebagai root!"
        exit 1
    fi
}

init_report() {
    echo "=========================================================" > "$REPORT_FILE"
    echo "        BLUE TEAM SECURITY REPORT - $TIMESTAMP           " >> "$REPORT_FILE"
    echo "=========================================================" >> "$REPORT_FILE"
}

# 1. Pre-check & Identifikasi
identify_system() {
    log "Identifikasi Sistem..."
    OS=$(grep PRETTY_NAME /etc/os-release | cut -d '"' -f 2)
    KERNEL=$(uname -r)
    HOSTNAME=$(hostname)
    IP=$(hostname -I | awk '{print $1}')
    VIRT=$(systemd-detect-virt 2>/dev/null || echo "Unknown")
    
    echo -e "\n[+] SYSTEM INFO" >> "$REPORT_FILE"
    echo "OS: $OS | Kernel: $KERNEL | Hostname: $HOSTNAME | IP: $IP | Virt: $VIRT" >> "$REPORT_FILE"
    
    if command -v systemctl >/dev/null; then
        echo "Systemd: Detected" >> "$REPORT_FILE"
        FLAG_OS_ID=10
    fi
}

# 2. Inventaris Service & Port
inventory() {
    log "Mengumpulkan inventaris layanan dan port..."
    echo -e "\n[+] ACTIVE SERVICES" >> "$REPORT_FILE"
    systemctl list-units --type=service --state=running | grep -v "systemd" | head -n 15 >> "$REPORT_FILE"
    
    echo -e "\n[+] LISTENING PORTS" >> "$REPORT_FILE"
    ss -tulnp >> "$REPORT_FILE"
    
    # Deteksi Port Penting
    SSH_PORT=$(ss -tulnp | grep sshd | awk '{print $5}' | cut -d ':' -f 2 | head -n 1)
    if [ -z "$SSH_PORT" ]; then SSH_PORT=22; fi
    log "Port SSH terdeteksi di: $SSH_PORT"
    
    HAS_WEB=$(ss -tulnp | grep -E ':(80|443)\b')
    HAS_WAZUH=$(systemctl is-active wazuh-agent 2>/dev/null)
    if [ "$HAS_WAZUH" == "active" ]; then FLAG_WAZUH=10; fi
}

# 3. Backup Konfigurasi
do_backup() {
    if [ "$MODE" == "--apply" ]; then
        log "Membuat backup di $BACKUP_DIR..."
        mkdir -p "$BACKUP_DIR"
        
        cp -a /etc/ssh/sshd_config "$BACKUP_DIR/" 2>/dev/null
        [ -d /etc/ufw ] && cp -a /etc/ufw "$BACKUP_DIR/" 2>/dev/null
        [ -d /etc/fail2ban ] && cp -a /etc/fail2ban "$BACKUP_DIR/" 2>/dev/null
        cp -a /etc/crontab "$BACKUP_DIR/" 2>/dev/null
        [ -d /var/spool/cron/crontabs ] && cp -a /var/spool/cron/crontabs "$BACKUP_DIR/" 2>/dev/null
        
        echo -e "\n[+] BACKUP CREATED" >> "$REPORT_FILE"
        echo "Lokasi: $BACKUP_DIR" >> "$REPORT_FILE"
        FLAG_BACKUP=10
        success "Backup selesai."
    fi
}

# 4. & 6. Audit Defense & Deteksi Indikator
audit_and_detect() {
    log "Melakukan audit keamanan dan deteksi anomali..."
    echo -e "\n[+] SECURITY AUDIT & FINDINGS" >> "$REPORT_FILE"
    
    # Check UID 0
    UID0=$(awk -F: '($3 == "0" && $1 != "root") {print $1}' /etc/passwd)
    if [ -n "$UID0" ]; then
        warning "Ditemukan user dengan UID 0 selain root: $UID0"
        echo "CRITICAL: UID 0 terdeteksi -> $UID0" >> "$REPORT_FILE"
    else
        FLAG_NO_UID0=10
    fi
    
    # Check Suspicious Processes
    SUSP_PROC=$(ps aux | grep -E "nc -e|ncat|bash -i|python -c 'import pty" | grep -v grep)
    if [ -n "$SUSP_PROC" ]; then
        warning "Ditemukan proses mencurigakan (kemungkinan reverse shell)!"
        echo "SUSPICIOUS PROCESS: $SUSP_PROC" >> "$REPORT_FILE"
    else
        FLAG_NO_BAD_CONN=10
    fi
    
    # Check PHP Webshells
    if [ -d "/var/www" ]; then
        log "Mengecek kemungkinan PHP webshell di /var/www..."
        WEBSHELL=$(grep -REn "(eval\(|system\(|shell_exec\(|passthru\()" /var/www/ 2>/dev/null | head -n 10)
        if [ -n "$WEBSHELL" ]; then
            warning "Indikasi Webshell ditemukan!"
            echo "WEBSHELL INDICATORS:" >> "$REPORT_FILE"
            echo "$WEBSHELL" >> "$REPORT_FILE"
        else
            FLAG_NO_WEBSHELL=10
        fi
    else
        FLAG_NO_WEBSHELL=10 # No webserver, safe from webshells
    fi
    
    # Check Cronjobs (System & User)
    SUSP_CRON=$(cat /etc/crontab 2>/dev/null | grep -E "wget|curl|nc|bash -i")
    if [ -n "$SUSP_CRON" ]; then
        warning "Cronjob sistem mencurigakan ditemukan."
        echo "SUSPICIOUS CRON: $SUSP_CRON" >> "$REPORT_FILE"
    else
        FLAG_NO_BAD_CRON=10
    fi
}

# 5. Hardening Aman
apply_hardening() {
    if [ "$MODE" != "--apply" ]; then return; fi
    log "Menerapkan Hardening (Safe Mode)..."
    echo -e "\n[+] HARDENING ACTIONS" >> "$REPORT_FILE"
    
    # SSH Hardening
    log "Hardening SSH..."
    sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
    sed -i 's/^#*MaxAuthTries.*/MaxAuthTries 3/' /etc/ssh/sshd_config
    sed -i 's/^#*LoginGraceTime.*/LoginGraceTime 20/' /etc/ssh/sshd_config
    sed -i 's/^#*X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config
    sed -i 's/^#*UseDNS.*/UseDNS no/' /etc/ssh/sshd_config
    
    # Validasi SSH
    if sshd -t; then
        systemctl restart sshd || systemctl restart ssh
        success "SSH berhasil diamankan dan direstart."
        echo "SSH Hardened & Validated." >> "$REPORT_FILE"
        FLAG_SSH_SAFE=10
    else
        error "Validasi SSH gagal! Melakukan rollback SSH..."
        cp "$BACKUP_DIR/sshd_config" /etc/ssh/sshd_config
        echo "SSH Hardening FAILED. Rolled back." >> "$REPORT_FILE"
    fi
    
    # UFW Hardening
    log "Mengonfigurasi UFW..."
    if command -v ufw >/dev/null; then
        ufw --force reset >/dev/null
        ufw default deny incoming
        ufw default allow outgoing
        ufw limit "$SSH_PORT"/tcp comment 'SSH Rate Limit'
        
        if [ -n "$HAS_WEB" ]; then
            ufw allow 80/tcp comment 'HTTP'
            ufw allow 443/tcp comment 'HTTPS'
        fi
        
        if [ "$HAS_WAZUH" == "active" ]; then
            ufw allow 1514/tcp comment 'Wazuh Agent'
            ufw allow 1515/tcp comment 'Wazuh Auth'
        fi
        
        ufw --force enable >/dev/null
        success "UFW dikonfigurasi dan diaktifkan."
        echo "UFW Enabled (Default Deny, Limit SSH, Allow Web/Wazuh if present)." >> "$REPORT_FILE"
        FLAG_FW_ACTIVE=10
    fi
    
    # Fail2ban
    log "Memeriksa Fail2ban..."
    if ! command -v fail2ban-client >/dev/null; then
        log "Menginstal Fail2ban..."
        apt-get update -qq && apt-get install -y -qq fail2ban
    fi
    
    systemctl enable --now fail2ban >/dev/null 2>&1
    if fail2ban-client ping | grep -q "pong"; then
        success "Fail2ban aktif."
        echo "Fail2ban is active." >> "$REPORT_FILE"
        FLAG_F2B_ACTIVE=10
    fi
}

do_rollback() {
    LATEST_BACKUP=$(ls -td /root/blueteam_backup_* 2>/dev/null | head -n 1)
    if [ -z "$LATEST_BACKUP" ]; then
        error "Tidak ditemukan direktori backup."
        exit 1
    fi
    
    log "Melakukan rollback dari $LATEST_BACKUP..."
    [ -f "$LATEST_BACKUP/sshd_config" ] && cp "$LATEST_BACKUP/sshd_config" /etc/ssh/
    [ -d "$LATEST_BACKUP/ufw" ] && cp -a "$LATEST_BACKUP/ufw/"* /etc/ufw/
    [ -d "$LATEST_BACKUP/fail2ban" ] && cp -a "$LATEST_BACKUP/fail2ban/"* /etc/fail2ban/
    [ -f "$LATEST_BACKUP/crontab" ] && cp "$LATEST_BACKUP/crontab" /etc/
    
    systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null
    command -v ufw >/dev/null && ufw reload >/dev/null
    systemctl restart fail2ban 2>/dev/null
    
    success "Rollback selesai."
    exit 0
}

# 8 & 9. Laporan dan Scoring
finalize_report() {
    # Audit mode checks defenses passively to add to score if they were already good
    if [ "$MODE" == "--audit-only" ]; then
        if sshd -T 2>/dev/null | grep -iq "permitrootlogin no"; then FLAG_SSH_SAFE=10; fi
        if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then FLAG_FW_ACTIVE=10; fi
        if command -v fail2ban-client >/dev/null && fail2ban-client ping 2>/dev/null | grep -q "pong"; then FLAG_F2B_ACTIVE=10; fi
        FLAG_BACKUP=10 # Skip backup penalty in audit
    fi

    SCORE=$((FLAG_OS_ID + FLAG_BACKUP + FLAG_SSH_SAFE + FLAG_FW_ACTIVE + FLAG_F2B_ACTIVE + FLAG_WAZUH + FLAG_NO_UID0 + FLAG_NO_BAD_CONN + FLAG_NO_BAD_CRON + FLAG_NO_WEBSHELL))
    
    if [ "$SCORE" -ge 85 ]; then RATING="A (Sangat Baik)"
    elif [ "$SCORE" -ge 70 ]; then RATING="B (Baik)"
    elif [ "$SCORE" -ge 55 ]; then RATING="C (Cukup)"
    elif [ "$SCORE" -ge 40 ]; then RATING="D (Lemah)"
    else RATING="E (Berisiko Tinggi)"
    fi
    
    echo -e "\n=========================================================" >> "$REPORT_FILE"
    echo "SECURITY RATING: $SCORE / 100" >> "$REPORT_FILE"
    echo "GRADE: $RATING" >> "$REPORT_FILE"
    echo "=========================================================" >> "$REPORT_FILE"
    
    echo -e "\n[+] RECOMMENDATIONS" >> "$REPORT_FILE"
    echo "- Tinjau manual user di /etc/passwd yang mencurigakan." >> "$REPORT_FILE"
    echo "- Periksa authorized_keys di direktori home tiap user." >> "$REPORT_FILE"
    echo "- Analisis isi dari file crontab jika ada flag suspicious." >> "$REPORT_FILE"
    
    success "Eksekusi selesai. Laporan tersimpan di: $REPORT_FILE"
    log "Security Score: $SCORE/100 ($RATING)"
}

# ==================== MAIN EXECUTION ====================
if [[ "$MODE" != "--audit-only" && "$MODE" != "--apply" && "$MODE" != "--rollback" ]]; then
    show_help
fi

check_root
if [ "$MODE" == "--rollback" ]; then
    do_rollback
fi

init_report
identify_system
inventory
do_backup
audit_and_detect
apply_hardening
finalize_report