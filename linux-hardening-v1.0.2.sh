#!/bin/bash
# ==============================================================================
# Linux Blue Team Automation & Hardening Script - V2 (Integrated Guide)
# Mode: --audit-only | --apply | --rollback | --help
# ==============================================================================

MODE=$1
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_DIR="/root/blueteam_backup_$TIMESTAMP"
REPORT_FILE="/var/log/report_$TIMESTAMP.txt"
SCORE=0

# Scoring Flags
FLAG_OS_ID=0; FLAG_BACKUP=0; FLAG_SSH_SAFE=0; FLAG_FW_ACTIVE=0; FLAG_F2B_ACTIVE=0
FLAG_WAZUH=0; FLAG_NO_UID0=0; FLAG_NO_BAD_CONN=0; FLAG_NO_BAD_CRON=0; FLAG_NO_WEBSHELL=0

# Formatting
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; CYAN='\033[0;36m'; NC='\033[0m'

log() { echo -e "${CYAN}[*]${NC} $1" | tee -a "$REPORT_FILE"; }
success() { echo -e "${GREEN}[+]${NC} $1" | tee -a "$REPORT_FILE"; }
warning() { echo -e "${YELLOW}[!]${NC} $1" | tee -a "$REPORT_FILE"; }
error() { echo -e "${RED}[x]${NC} $1" | tee -a "$REPORT_FILE"; }

show_help() {
    echo "Usage: ./blueteam-defender.sh [MODE]"
    echo "  --audit-only  : Hanya mengecek sistem dan membuat laporan. Tidak ada perubahan."
    echo "  --apply       : Melakukan backup lalu menerapkan hardening dasar (termasuk Wazuh Active Response)."
    echo "  --rollback    : Mengembalikan konfigurasi dari direktori backup terakhir."
    echo "  --help        : Menampilkan bantuan."
    exit 0
}

check_root() {
    if [ "$EUID" -ne 0 ]; then error "Script harus dijalankan sebagai root!"; exit 1; fi
}

init_report() {
    echo "=========================================================" > "$REPORT_FILE"
    echo "      BLUE TEAM SECURITY REPORT - V2 - $TIMESTAMP        " >> "$REPORT_FILE"
    echo "=========================================================" >> "$REPORT_FILE"
}

# --- 1 & 2. Pre-check & Inventory ---
identify_and_inventory() {
    log "Identifikasi Sistem & Inventaris Port..."
    OS=$(grep PRETTY_NAME /etc/os-release | cut -d '"' -f 2 2>/dev/null || echo "Unknown")
    IP=$(hostname -I | awk '{print $1}')
    
    echo -e "\n[+] SYSTEM INFO\nOS: $OS | IP: $IP" >> "$REPORT_FILE"
    FLAG_OS_ID=10
    
    SSH_PORT=$(ss -tulnp | grep sshd | awk '{print $5}' | cut -d ':' -f 2 | head -n 1)
    [ -z "$SSH_PORT" ] && SSH_PORT=22
    
    HAS_WEB=$(ss -tulnp | grep -E ':(80|443)\b')
    HAS_WAZUH_MGR=$(systemctl is-active wazuh-manager 2>/dev/null)
    HAS_WAZUH_AGT=$(systemctl is-active wazuh-agent 2>/dev/null)
    
    if [ "$HAS_WAZUH_MGR" == "active" ] || [ "$HAS_WAZUH_AGT" == "active" ]; then FLAG_WAZUH=10; fi
}

do_backup() {
    if [ "$MODE" == "--apply" ]; then
        log "Membuat backup di $BACKUP_DIR..."
        mkdir -p "$BACKUP_DIR"
        cp -a /etc/ssh/sshd_config "$BACKUP_DIR/" 2>/dev/null
        [ -d /etc/ufw ] && cp -a /etc/ufw "$BACKUP_DIR/" 2>/dev/null
        [ -d /var/ossec/etc ] && cp -a /var/ossec/etc "$BACKUP_DIR/ossec_etc" 2>/dev/null
        FLAG_BACKUP=10
        success "Backup selesai."
    fi
}

# --- Fase 9 & 10: Audit, Deteksi Manual, & IR Triage ---
audit_and_detect() {
    log "Melakukan Audit & Deteksi Lanjutan (Fase 9 & 10)..."
    echo -e "\n[+] SECURITY AUDIT & FINDINGS" >> "$REPORT_FILE"
    
    # Deteksi UID 0 / Backdoor User
    UID0=$(awk -F: '($3 == "0" && $1 != "root") {print $1}' /etc/passwd)
    if [ -n "$UID0" ]; then
        warning "Ditemukan user dengan UID 0 selain root: $UID0"
        echo "CRITICAL: UID 0 terdeteksi -> $UID0" >> "$REPORT_FILE"
    else FLAG_NO_UID0=10; fi

    echo "INFO: 5 User terakhir di /etc/passwd:" >> "$REPORT_FILE"
    tail -n 5 /etc/passwd >> "$REPORT_FILE"
    
    # Deteksi Reverse Shell Aktif (Fase 9)
    SUSP_PORTS=$(ss -tnp | grep -E ":4444|:9999|:1234|:5555|:6666")
    if [ -n "$SUSP_PORTS" ]; then
        warning "Koneksi mencurigakan ke port reverse shell umum terdeteksi!"
        echo "SUSPICIOUS CONNECTIONS:" >> "$REPORT_FILE"
        echo "$SUSP_PORTS" >> "$REPORT_FILE"
    else FLAG_NO_BAD_CONN=10; fi
    
    # Deteksi Webshell (Fase 9)
    if [ -d "/var/www" ]; then
        WEBSHELL=$(grep -REn "(eval\(|system\(|shell_exec\(|passthru\()" /var/www/ 2>/dev/null | head -n 10)
        if [ -n "$WEBSHELL" ]; then
            warning "Indikasi Webshell ditemukan!"
            echo "WEBSHELL INDICATORS:" >> "$REPORT_FILE"
            echo "$WEBSHELL" >> "$REPORT_FILE"
        else FLAG_NO_WEBSHELL=10; fi
    else FLAG_NO_WEBSHELL=10; fi
    
    # Deteksi Cronjob Backdoor (Fase 9)
    echo -e "\n[+] SUSPICIOUS CRONJOBS:" >> "$REPORT_FILE"
    CRON_FOUND=0
    for user in $(cut -f1 -d: /etc/passwd); do
        CRON=$(crontab -u "$user" -l 2>/dev/null | grep -v "^#" | grep -v "^$")
        if [ -n "$CRON" ]; then
            echo "User $user: $CRON" >> "$REPORT_FILE"
            CRON_FOUND=1
        fi
    done
    if [ $CRON_FOUND -eq 0 ]; then FLAG_NO_BAD_CRON=10; fi

    # Deteksi Injeksi SSH Key (Fase 9)
    echo -e "\n[+] AUTHORIZED KEYS FOUND:" >> "$REPORT_FILE"
    for user in $(cut -f1 -d: /etc/passwd); do
        home=$(eval echo ~$user)
        if [ -f "$home/.ssh/authorized_keys" ]; then
            echo "=== Key User: $user ===" >> "$REPORT_FILE"
            cat "$home/.ssh/authorized_keys" >> "$REPORT_FILE"
        fi
    done

    # Triage Insiden SSH (Fase 10)
    if [ -f "/var/log/auth.log" ]; then
        echo -e "\n[+] TOP 5 FAILED LOGIN IPs (Fase 10):" >> "$REPORT_FILE"
        grep "Failed password" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -rn | head -5 >> "$REPORT_FILE"
    fi
}

# --- Fase 3 & 8: Hardening & Wazuh Active Response ---
apply_hardening() {
    if [ "$MODE" != "--apply" ]; then return; fi
    log "Menerapkan Hardening (Fase 3 & 8)..."
    
    # SSH Hardening Aman
    sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
    if sshd -t; then
        systemctl restart sshd || systemctl restart ssh
        FLAG_SSH_SAFE=10
    else
        cp "$BACKUP_DIR/sshd_config" /etc/ssh/sshd_config
    fi
    
    # Wazuh Active Response Hardening (Fase 8)
    if [ -f "/var/ossec/etc/ossec.conf" ]; then
        log "Konfigurasi Wazuh Manager terdeteksi. Menyuntikkan Active Response..."
        if ! grep -q "firewall-drop" /var/ossec/etc/ossec.conf; then
            # Inject active response XML before closing tag
            sed -i '/<\/ossec_config>/i \  <active-response>\n    <command>firewall-drop<\/command>\n    <location>local<\/location>\n    <rules_id>5712,5710,31151,40101<\/rules_id>\n    <timeout>600<\/timeout>\n  <\/active-response>' /var/ossec/etc/ossec.conf
        fi
        
        # Tambah Local Rule untuk Nmap
        if [ -f "/var/ossec/etc/rules/local_rules.xml" ]; then
            if ! grep -q "nmap,scan" /var/ossec/etc/rules/local_rules.xml; then
                sed -i '/<\/group>/i \  <rule id="100001" level="10">\n    <if_sid>1002<\/if_sid>\n    <match>nmap<\/match>\n    <description>Nmap scan detected<\/description>\n  <\/rule>' /var/ossec/etc/rules/local_rules.xml
            fi
        fi
        systemctl restart wazuh-manager 2>/dev/null
        success "Wazuh Active Response dan Rule Nmap diaktifkan."
    fi

    # UFW Hardening
    if command -v ufw >/dev/null; then
        ufw --force reset >/dev/null
        ufw default deny incoming
        ufw default allow outgoing
        ufw limit "$SSH_PORT"/tcp comment 'SSH Rate Limit'
        [ -n "$HAS_WEB" ] && ufw allow 80/tcp && ufw allow 443/tcp
        if [ "$HAS_WAZUH_AGT" == "active" ] || [ "$HAS_WAZUH_MGR" == "active" ]; then
            ufw allow 55000/tcp comment 'Wazuh Agent'
            ufw allow 1514/tcp comment 'Wazuh Manager Logs'
        fi
        ufw --force enable >/dev/null
        FLAG_FW_ACTIVE=10
    fi
}

do_rollback() {
    LATEST_BACKUP=$(ls -td /root/blueteam_backup_* 2>/dev/null | head -n 1)
    if [ -z "$LATEST_BACKUP" ]; then error "Tidak ditemukan direktori backup."; exit 1; fi
    log "Melakukan rollback dari $LATEST_BACKUP..."
    [ -f "$LATEST_BACKUP/sshd_config" ] && cp "$LATEST_BACKUP/sshd_config" /etc/ssh/
    [ -d "$LATEST_BACKUP/ossec_etc" ] && cp -a "$LATEST_BACKUP/ossec_etc/"* /var/ossec/etc/
    systemctl restart sshd 2>/dev/null; systemctl restart wazuh-manager 2>/dev/null
    success "Rollback selesai."
    exit 0
}

finalize_report() {
    if [ "$MODE" == "--audit-only" ]; then FLAG_BACKUP=10; fi # Skip penalty
    SCORE=$((FLAG_OS_ID + FLAG_BACKUP + FLAG_SSH_SAFE + FLAG_FW_ACTIVE + FLAG_F2B_ACTIVE + FLAG_WAZUH + FLAG_NO_UID0 + FLAG_NO_BAD_CONN + FLAG_NO_BAD_CRON + FLAG_NO_WEBSHELL))
    
    if [ "$SCORE" -ge 85 ]; then RATING="A (Sangat Baik)"
    elif [ "$SCORE" -ge 70 ]; then RATING="B (Baik)"
    else RATING="C / D / E (Butuh Perhatian)"
    fi
    
    echo -e "\n=========================================================" >> "$REPORT_FILE"
    echo "SECURITY RATING: $SCORE / 100  |  GRADE: $RATING" >> "$REPORT_FILE"
    echo "=========================================================" >> "$REPORT_FILE"
    
    echo -e "\n[+] INCIDENT RESPONSE RECOMMENDATIONS (FASE 10)" >> "$REPORT_FILE"
    echo "- Jika ada IP yang dominan di 'FAILED LOGIN', blokir via: sudo ufw deny from <IP>" >> "$REPORT_FILE"
    echo "- Jika ada User backdoor di akhir file /etc/passwd, hapus via: sudo userdel -r <user>" >> "$REPORT_FILE"
    echo "- Jika ada PID reverse shell, matikan via: kill -9 <PID>" >> "$REPORT_FILE"
    echo "- PENTING: Screenshot log ini dan log Wazuh/OPNsense untuk write-up kompetisi." >> "$REPORT_FILE"
    
    success "Laporan tersimpan di: $REPORT_FILE"
}

# ==================== MAIN EXECUTION ====================
if [[ "$MODE" != "--audit-only" && "$MODE" != "--apply" && "$MODE" != "--rollback" ]]; then show_help; fi
check_root
if [ "$MODE" == "--rollback" ]; then do_rollback; fi

init_report
identify_and_inventory
do_backup
audit_and_detect
apply_hardening
finalize_report
