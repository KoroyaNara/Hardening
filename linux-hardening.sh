#!/usr/bin/env bash
# =============================================================================
# linux-hardening.sh
# Blue Team Automation - Audit, Hardening, dan Deteksi Ancaman
# Target: Debian/Ubuntu (systemd)
# Penggunaan: sudo bash linux-hardening.sh [--check|-c] [--enforce|-e] [--rollback|-r] [--help|-h]
# =============================================================================

set -euo pipefail

# =============================================================================
# KONFIGURASI GLOBAL
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP_DIR="${SCRIPT_DIR}/backup-${TIMESTAMP}"
LOG_DIR="/var/log/laporan"
LOG_FILE="${LOG_DIR}/hardening-${TIMESTAMP}.txt"
SSH_PORT=22
MODE=""

# Scoring
SCORE=0
MAX_SCORE=100
declare -a SCORE_LOG=()

# Warna terminal
RED='\033[0;31m'
YEL='\033[1;33m'
GRN='\033[0;32m'
CYN='\033[0;36m'
BLD='\033[1m'
RST='\033[0m'

# =============================================================================
# UTILITAS
# =============================================================================

log() {
    local level="$1"; shift
    local msg="$*"
    local ts; ts="$(date '+%H:%M:%S')"
    echo "[$ts][$level] $msg" >> "$LOG_FILE"
    case "$level" in
        INFO)  echo -e "${CYN}[*]${RST} $msg" ;;
        OK)    echo -e "${GRN}[+]${RST} $msg" ;;
        WARN)  echo -e "${YEL}[!]${RST} $msg" ;;
        ERR)   echo -e "${RED}[-]${RST} $msg" ;;
        HEAD)  echo -e "\n${BLD}${CYN}=== $msg ===${RST}" ;;
    esac
}

add_score() {
    local pts="$1"
    local reason="$2"
    SCORE=$((SCORE + pts))
    SCORE_LOG+=("  +${pts}pt : ${reason}")
}

section_header() {
    local title="$1"
    echo "" >> "$LOG_FILE"
    echo "================================================================" >> "$LOG_FILE"
    echo "  $title" >> "$LOG_FILE"
    echo "================================================================" >> "$LOG_FILE"
    log HEAD "$title"
}

# =============================================================================
# INISIALISASI LOG
# =============================================================================

init_log() {
    mkdir -p "$LOG_DIR"
    touch "$LOG_FILE"
    {
        echo "================================================================"
        echo "  LAPORAN HARDENING LINUX"
        echo "  Waktu   : $(date)"
        echo "  Host    : $(hostname)"
        echo "  Mode    : $MODE"
        echo "================================================================"
    } >> "$LOG_FILE"
}

# =============================================================================
# TAHAP 0: TANYA PORT SSH
# =============================================================================

ask_ssh_port() {
    echo ""
    echo -e "${BLD}Konfigurasi awal${RST}"
    echo -e "  Port SSH default adalah ${BLD}22${RST}."
    read -rp "  Masukkan port SSH yang aktif di server ini [22]: " input_port
    if [[ -z "$input_port" ]]; then
        SSH_PORT=22
    elif [[ "$input_port" =~ ^[0-9]+$ ]] && (( input_port >= 1 && input_port <= 65535 )); then
        SSH_PORT="$input_port"
    else
        echo -e "${YEL}[!]${RST} Input tidak valid, menggunakan port 22."
        SSH_PORT=22
    fi
    echo -e "  Port SSH yang digunakan: ${BLD}${SSH_PORT}${RST}"
    echo ""
}

# =============================================================================
# TAHAP 1: PRE-CHECK DAN IDENTIFIKASI SISTEM
# =============================================================================

check_root() {
    if [[ "$EUID" -ne 0 ]]; then
        echo -e "${RED}[-]${RST} Script harus dijalankan sebagai root. Gunakan: sudo bash $0 $MODE"
        exit 1
    fi
}

detect_system() {
    section_header "1. IDENTIFIKASI SISTEM"

    local os kernel hostname_val ip_addr virt pkg_mgr init_sys

    os="$(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"' || echo 'Tidak diketahui')"
    kernel="$(uname -r)"
    hostname_val="$(hostname)"
    ip_addr="$(hostname -I 2>/dev/null | awk '{print $1}' || echo 'N/A')"

    # Deteksi virtualisasi
    if command -v systemd-detect-virt &>/dev/null; then
        virt="$(systemd-detect-virt 2>/dev/null || echo 'none')"
    else
        virt="tidak dapat dideteksi"
    fi

    # Deteksi package manager
    if command -v apt-get &>/dev/null; then
        pkg_mgr="apt (Debian/Ubuntu)"
    elif command -v dnf &>/dev/null; then
        pkg_mgr="dnf (RHEL/Fedora)"
    elif command -v yum &>/dev/null; then
        pkg_mgr="yum (CentOS/RHEL lama)"
    else
        pkg_mgr="tidak diketahui"
    fi

    # Deteksi init system
    if [[ -d /run/systemd/system ]]; then
        init_sys="systemd"
    else
        init_sys="non-systemd (SysV/OpenRC?)"
    fi

    log INFO "OS        : $os"
    log INFO "Kernel    : $kernel"
    log INFO "Hostname  : $hostname_val"
    log INFO "IP        : $ip_addr"
    log INFO "Virt      : $virt"
    log INFO "Pkg mgr   : $pkg_mgr"
    log INFO "Init      : $init_sys"

    {
        echo ""
        echo "--- Sistem ---"
        echo "OS        : $os"
        echo "Kernel    : $kernel"
        echo "Hostname  : $hostname_val"
        echo "IP        : $ip_addr"
        echo "Virt      : $virt"
        echo "Pkg mgr   : $pkg_mgr"
        echo "Init      : $init_sys"
    } >> "$LOG_FILE"

    add_score 10 "Sistem berhasil diidentifikasi"
}

# =============================================================================
# TAHAP 2: INVENTARIS SERVICE DAN PORT
# =============================================================================

inventory_services() {
    section_header "2. INVENTARIS SERVICE DAN PORT"

    log INFO "Mengambil daftar service aktif..."
    {
        echo ""
        echo "--- Service Aktif ---"
        systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null \
            | awk '{print $1, $4}' || echo "(gagal membaca service)"
    } >> "$LOG_FILE"

    log INFO "Mengambil daftar port listening..."
    {
        echo ""
        echo "--- Port Listening ---"
        ss -tlnup 2>/dev/null || netstat -tlnup 2>/dev/null || echo "(ss/netstat tidak tersedia)"
    } >> "$LOG_FILE"

    # Deteksi service kritis
    log INFO "Deteksi service kritis..."
    {
        echo ""
        echo "--- Deteksi Service Kritis ---"
    } >> "$LOG_FILE"

    local services_found=()

    # SSH
    if systemctl is-active --quiet sshd 2>/dev/null || systemctl is-active --quiet ssh 2>/dev/null; then
        log OK "SSH       : aktif"
        echo "SSH       : aktif (port dikonfigurasi: $SSH_PORT)" >> "$LOG_FILE"
        services_found+=("ssh")
    else
        log WARN "SSH       : tidak aktif"
        echo "SSH       : tidak aktif" >> "$LOG_FILE"
    fi

    # HTTP/HTTPS
    for svc in apache2 nginx lighttpd httpd; do
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            log OK "Web ($svc): aktif"
            echo "Web ($svc): aktif" >> "$LOG_FILE"
            services_found+=("web")
            break
        fi
    done

    # Database
    for svc in mysql mariadb postgresql mongod; do
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            log OK "DB ($svc) : aktif"
            echo "DB ($svc) : aktif" >> "$LOG_FILE"
            services_found+=("db")
            break
        fi
    done

    # Wazuh
    if systemctl is-active --quiet wazuh-agent 2>/dev/null; then
        log OK "Wazuh Agent  : aktif"
        echo "Wazuh Agent  : aktif" >> "$LOG_FILE"
        services_found+=("wazuh-agent")
    fi
    if systemctl is-active --quiet wazuh-manager 2>/dev/null; then
        log OK "Wazuh Manager: aktif"
        echo "Wazuh Manager: aktif" >> "$LOG_FILE"
        services_found+=("wazuh-manager")
    fi

    # Fail2ban
    if systemctl is-active --quiet fail2ban 2>/dev/null; then
        log OK "Fail2ban  : aktif"
        echo "Fail2ban  : aktif" >> "$LOG_FILE"
        services_found+=("fail2ban")
    else
        log WARN "Fail2ban  : tidak aktif / tidak terpasang"
        echo "Fail2ban  : tidak aktif" >> "$LOG_FILE"
    fi

    # UFW
    if command -v ufw &>/dev/null; then
        local ufw_status; ufw_status="$(ufw status 2>/dev/null | head -1)"
        log INFO "UFW       : $ufw_status"
        echo "UFW       : $ufw_status" >> "$LOG_FILE"
        services_found+=("ufw")
    else
        log WARN "UFW       : tidak terpasang"
        echo "UFW       : tidak terpasang" >> "$LOG_FILE"
    fi

    # Simpan ke variabel global untuk dipakai tahap lain
    SERVICES_FOUND=("${services_found[@]}")
}

# =============================================================================
# TAHAP 3: BACKUP KONFIGURASI
# =============================================================================

backup_configs() {
    section_header "3. BACKUP KONFIGURASI"

    mkdir -p "$BACKUP_DIR"
    log INFO "Folder backup: $BACKUP_DIR"
    echo "" >> "$LOG_FILE"
    echo "--- Backup ---" >> "$LOG_FILE"
    echo "Folder: $BACKUP_DIR" >> "$LOG_FILE"

    local files_to_backup=(
        "/etc/ssh/sshd_config"
        "/etc/fail2ban/jail.conf"
        "/etc/fail2ban/jail.local"
        "/etc/ufw/ufw.conf"
        "/etc/ufw/before.rules"
        "/etc/ufw/user.rules"
        "/var/ossec/etc/ossec.conf"
        "/etc/wazuh-agent/ossec.conf"
    )

    for f in "${files_to_backup[@]}"; do
        if [[ -f "$f" ]]; then
            local dest="${BACKUP_DIR}$(dirname "$f")"
            mkdir -p "$dest"
            if cp -p "$f" "${dest}/$(basename "$f")" 2>/dev/null; then
                log OK "Backup OK : $f"
                echo "OK  : $f" >> "$LOG_FILE"
            else
                log WARN "Backup GAGAL: $f"
                echo "GAGAL: $f" >> "$LOG_FILE"
            fi
        fi
    done

    # Backup crontab
    local cron_backup="${BACKUP_DIR}/crontab-backup.txt"
    {
        echo "--- Crontab Root ---"
        crontab -l 2>/dev/null || echo "(kosong)"
        echo ""
        echo "--- Crontab System ---"
        ls /etc/cron* /var/spool/cron/crontabs/ 2>/dev/null || echo "(tidak ada)"
    } > "$cron_backup"
    log OK "Backup crontab: $cron_backup"
    echo "OK  : crontab -> $cron_backup" >> "$LOG_FILE"

    add_score 10 "Backup konfigurasi berhasil dibuat"
}

# =============================================================================
# TAHAP 4: AUDIT DEFENSE YANG ADA
# =============================================================================

audit_defenses() {
    section_header "4. AUDIT DEFENSE"

    echo "" >> "$LOG_FILE"
    echo "--- Audit SSH ---" >> "$LOG_FILE"

    local sshd_cfg="/etc/ssh/sshd_config"
    if [[ -f "$sshd_cfg" ]]; then
        local permit_root max_auth x11 pass_auth grace_time use_dns
        permit_root="$(grep -i '^\s*PermitRootLogin' "$sshd_cfg" | awk '{print $2}' | head -1 || echo 'tidak diset')"
        max_auth="$(grep -i '^\s*MaxAuthTries' "$sshd_cfg" | awk '{print $2}' | head -1 || echo 'tidak diset')"
        x11="$(grep -i '^\s*X11Forwarding' "$sshd_cfg" | awk '{print $2}' | head -1 || echo 'tidak diset')"
        pass_auth="$(grep -i '^\s*PasswordAuthentication' "$sshd_cfg" | awk '{print $2}' | head -1 || echo 'tidak diset')"
        grace_time="$(grep -i '^\s*LoginGraceTime' "$sshd_cfg" | awk '{print $2}' | head -1 || echo 'tidak diset')"
        use_dns="$(grep -i '^\s*UseDNS' "$sshd_cfg" | awk '{print $2}' | head -1 || echo 'tidak diset')"

        [[ "$permit_root" == "yes" ]] && log WARN "PermitRootLogin: yes (berisiko)" || log OK "PermitRootLogin: $permit_root"
        [[ "${max_auth:-6}" -gt 5 ]] 2>/dev/null && log WARN "MaxAuthTries: $max_auth (terlalu tinggi)" || log OK "MaxAuthTries: $max_auth"
        [[ "$x11" == "yes" ]] && log WARN "X11Forwarding: yes (tidak perlu)" || log OK "X11Forwarding: $x11"
        log INFO "PasswordAuthentication: $pass_auth"
        log INFO "LoginGraceTime: $grace_time"
        log INFO "UseDNS: $use_dns"

        {
            echo "PermitRootLogin        : $permit_root"
            echo "MaxAuthTries           : $max_auth"
            echo "X11Forwarding          : $x11"
            echo "PasswordAuthentication : $pass_auth"
            echo "LoginGraceTime         : $grace_time"
            echo "UseDNS                 : $use_dns"
        } >> "$LOG_FILE"

        # Skor SSH
        if [[ "$permit_root" != "yes" ]] && [[ "${max_auth:-6}" -le 5 ]] 2>/dev/null && [[ "$x11" != "yes" ]]; then
            add_score 15 "Konfigurasi SSH sudah aman"
        fi
    else
        log WARN "sshd_config tidak ditemukan"
    fi

    # Audit UFW
    echo "" >> "$LOG_FILE"
    echo "--- Audit UFW ---" >> "$LOG_FILE"
    if command -v ufw &>/dev/null; then
        local ufw_out; ufw_out="$(ufw status verbose 2>/dev/null)"
        echo "$ufw_out" >> "$LOG_FILE"
        if echo "$ufw_out" | grep -q "Status: active"; then
            log OK "UFW aktif"
            add_score 15 "Firewall UFW aktif"
        else
            log WARN "UFW tidak aktif"
        fi
    fi

    # Audit Fail2ban
    echo "" >> "$LOG_FILE"
    echo "--- Audit Fail2ban ---" >> "$LOG_FILE"
    if systemctl is-active --quiet fail2ban 2>/dev/null; then
        log OK "Fail2ban aktif"
        fail2ban-client status 2>/dev/null >> "$LOG_FILE" || true
        add_score 10 "Fail2ban aktif"
    else
        log WARN "Fail2ban tidak aktif"
        echo "Fail2ban: tidak aktif" >> "$LOG_FILE"
    fi

    # Audit Wazuh
    echo "" >> "$LOG_FILE"
    echo "--- Audit Wazuh ---" >> "$LOG_FILE"
    local wazuh_found=0
    for svc in wazuh-agent wazuh-manager; do
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            log OK "$svc aktif"
            echo "$svc: aktif" >> "$LOG_FILE"
            wazuh_found=1
        fi
    done
    if [[ $wazuh_found -eq 1 ]]; then
        add_score 10 "Wazuh aktif"
    else
        log INFO "Wazuh tidak terdeteksi (opsional)"
        echo "Wazuh: tidak terdeteksi" >> "$LOG_FILE"
    fi
}

# =============================================================================
# TAHAP 5: HARDENING (hanya --enforce)
# =============================================================================

harden_ssh() {
    log INFO "Menerapkan hardening SSH..."

    local sshd_cfg="/etc/ssh/sshd_config"
    [[ ! -f "$sshd_cfg" ]] && log ERR "sshd_config tidak ditemukan, skip SSH hardening" && return

    # Fungsi helper untuk set/tambah parameter
    set_sshd_param() {
        local param="$1"
        local value="$2"
        if grep -qiE "^\s*#?\s*${param}\s" "$sshd_cfg"; then
            sed -i -E "s|^\s*#?\s*(${param})\s+.*|\1 ${value}|I" "$sshd_cfg"
        else
            echo "${param} ${value}" >> "$sshd_cfg"
        fi
    }

    set_sshd_param "PermitRootLogin"  "no"
    set_sshd_param "MaxAuthTries"     "3"
    set_sshd_param "LoginGraceTime"   "20"
    set_sshd_param "X11Forwarding"    "no"
    set_sshd_param "UseDNS"           "no"

    # Validasi sebelum restart
    if sshd -t 2>/dev/null; then
        log OK "Validasi sshd -t berhasil, melakukan restart..."
        systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true
        log OK "SSH berhasil di-restart"
        echo "SSH hardening: diterapkan dan direstart" >> "$LOG_FILE"
        add_score 15 "SSH hardening berhasil diterapkan"
    else
        log ERR "Validasi sshd -t GAGAL, rollback konfigurasi SSH..."
        cp -p "${BACKUP_DIR}/etc/ssh/sshd_config" "$sshd_cfg" 2>/dev/null \
            && log OK "Rollback SSH berhasil" \
            || log ERR "Rollback SSH gagal, periksa manual"
        echo "SSH hardening: GAGAL validasi, rollback dilakukan" >> "$LOG_FILE"
    fi
}

harden_ufw() {
    log INFO "Mengkonfigurasi UFW..."

    if ! command -v ufw &>/dev/null; then
        log INFO "UFW tidak ada, coba install..."
        apt-get install -y ufw &>/dev/null && log OK "UFW berhasil diinstall" || {
            log ERR "Gagal install UFW, skip"
            return
        }
    fi

    # Catat rule lama
    {
        echo ""
        echo "--- UFW Rules Sebelum Perubahan ---"
        ufw status numbered 2>/dev/null || echo "(tidak ada rule)"
    } >> "$LOG_FILE"

    # Default policy
    ufw default deny incoming  &>/dev/null
    ufw default allow outgoing &>/dev/null
    log OK "UFW default: deny incoming, allow outgoing"

    # Allow SSH port yang dikonfigurasi user
    ufw allow "$SSH_PORT"/tcp comment "SSH" &>/dev/null
    log OK "UFW allow SSH port $SSH_PORT/tcp"

    # Allow HTTP/HTTPS hanya jika web service terdeteksi
    if printf '%s\n' "${SERVICES_FOUND[@]}" | grep -q "web"; then
        ufw allow 80/tcp  comment "HTTP"  &>/dev/null
        ufw allow 443/tcp comment "HTTPS" &>/dev/null
        log OK "UFW allow HTTP/HTTPS (web service terdeteksi)"
        echo "UFW: HTTP/HTTPS diizinkan" >> "$LOG_FILE"
    fi

    # Allow Wazuh hanya jika terdeteksi
    if printf '%s\n' "${SERVICES_FOUND[@]}" | grep -q "wazuh"; then
        ufw allow 1514/tcp comment "Wazuh" &>/dev/null
        ufw allow 1515/tcp comment "Wazuh" &>/dev/null
        log OK "UFW allow Wazuh ports (Wazuh terdeteksi)"
        echo "UFW: Wazuh ports diizinkan" >> "$LOG_FILE"
    fi

    # Rate limit SSH
    ufw limit "$SSH_PORT"/tcp comment "SSH rate limit" &>/dev/null
    log OK "UFW rate limit SSH aktif"

    # Enable UFW
    ufw --force enable &>/dev/null
    log OK "UFW diaktifkan"

    {
        echo ""
        echo "--- UFW Rules Setelah Perubahan ---"
        ufw status numbered 2>/dev/null
    } >> "$LOG_FILE"

    echo "UFW hardening: diterapkan" >> "$LOG_FILE"
}

harden_fail2ban() {
    log INFO "Mengkonfigurasi Fail2ban..."

    if ! command -v fail2ban-server &>/dev/null; then
        log INFO "Fail2ban tidak ada, coba install..."
        apt-get install -y fail2ban &>/dev/null && log OK "Fail2ban berhasil diinstall" || {
            log ERR "Gagal install Fail2ban, skip"
            return
        }
    fi

    local jail_local="/etc/fail2ban/jail.local"
    if [[ ! -f "$jail_local" ]]; then
        cat > "$jail_local" <<EOF
[DEFAULT]
bantime  = 3600
findtime = 600
maxretry = 3
backend  = systemd

[sshd]
enabled  = true
port     = ${SSH_PORT}
logpath  = %(sshd_log)s
EOF
        log OK "Fail2ban jail.local dibuat untuk SSH (port $SSH_PORT)"
        echo "Fail2ban: jail.local dibuat" >> "$LOG_FILE"
    else
        log INFO "jail.local sudah ada, tidak ditimpa"
        echo "Fail2ban: jail.local sudah ada, tidak diubah" >> "$LOG_FILE"
    fi

    systemctl enable fail2ban &>/dev/null
    systemctl restart fail2ban &>/dev/null && log OK "Fail2ban aktif" || log WARN "Fail2ban gagal start"
    add_score 10 "Fail2ban dikonfigurasi"
}

apply_hardening() {
    section_header "5. HARDENING"
    harden_ssh
    harden_ufw
    harden_fail2ban
}

# =============================================================================
# TAHAP 6: DETEKSI INDIKATOR MENCURIGAKAN
# =============================================================================

detect_threats() {
    section_header "6. DETEKSI INDIKATOR MENCURIGAKAN"

    local threats_found=0

    echo "" >> "$LOG_FILE"
    echo "--- User UID 0 (selain root) ---" >> "$LOG_FILE"
    local uid0_users; uid0_users="$(awk -F: '($3==0 && $1!="root"){print $1}' /etc/passwd)"
    if [[ -n "$uid0_users" ]]; then
        log WARN "User UID 0 selain root ditemukan: $uid0_users"
        echo "DITEMUKAN: $uid0_users" >> "$LOG_FILE"
        threats_found=$((threats_found + 1))
    else
        log OK "Tidak ada user UID 0 selain root"
        echo "Bersih" >> "$LOG_FILE"
        add_score 10 "Tidak ada user UID 0 mencurigakan"
    fi

    echo "" >> "$LOG_FILE"
    echo "--- User baru (UID >= 1000) ---" >> "$LOG_FILE"
    awk -F: '($3>=1000 && $1!="nobody"){print $1, "UID="$3, "shell="$7}' /etc/passwd >> "$LOG_FILE"
    log INFO "Daftar user (UID >= 1000) dicatat ke laporan"

    echo "" >> "$LOG_FILE"
    echo "--- Authorized_keys semua user ---" >> "$LOG_FILE"
    while IFS=: read -r username _ uid _ _ home _; do
        if [[ "$uid" -ge 1000 ]] || [[ "$username" == "root" ]]; then
            local ak="${home}/.ssh/authorized_keys"
            if [[ -f "$ak" ]]; then
                echo "[$username] $ak :" >> "$LOG_FILE"
                cat "$ak" >> "$LOG_FILE"
                log WARN "authorized_keys ditemukan: $ak"
                threats_found=$((threats_found + 1))
            fi
        fi
    done < /etc/passwd

    echo "" >> "$LOG_FILE"
    echo "--- Cronjob mencurigakan ---" >> "$LOG_FILE"
    {
        crontab -l 2>/dev/null || echo "(root crontab kosong)"
        echo ""
        cat /etc/crontab 2>/dev/null || true
        ls /etc/cron.d/ 2>/dev/null | xargs -I{} cat /etc/cron.d/{} 2>/dev/null || true
    } >> "$LOG_FILE"
    log INFO "Cronjob dicatat ke laporan (periksa manual)"

    echo "" >> "$LOG_FILE"
    echo "--- Koneksi established ---" >> "$LOG_FILE"
    local suspicious_conns
    suspicious_conns="$(ss -tnp state established 2>/dev/null | grep -v "127.0.0.1\|::1" || true)"
    if [[ -n "$suspicious_conns" ]]; then
        echo "$suspicious_conns" >> "$LOG_FILE"
        log WARN "Koneksi established ke luar ditemukan, periksa laporan"
        threats_found=$((threats_found + 1))
    else
        log OK "Tidak ada koneksi established mencurigakan"
        echo "Bersih" >> "$LOG_FILE"
        add_score 10 "Tidak ada koneksi mencurigakan"
    fi

    echo "" >> "$LOG_FILE"
    echo "--- Proses mencurigakan ---" >> "$LOG_FILE"
    local sus_procs
    sus_procs="$(ps aux 2>/dev/null | grep -E 'nc |ncat |bash -i|python.*-c.*socket|perl.*socket|php.*shell|/dev/tcp' | grep -v grep || true)"
    if [[ -n "$sus_procs" ]]; then
        log WARN "Proses mencurigakan ditemukan:"
        echo "$sus_procs" | tee -a "$LOG_FILE"
        threats_found=$((threats_found + 1))
    else
        log OK "Tidak ada proses mencurigakan terdeteksi"
        echo "Bersih" >> "$LOG_FILE"
        add_score 10 "Tidak ada proses mencurigakan"
    fi

    echo "" >> "$LOG_FILE"
    echo "--- Deteksi webshell PHP ---" >> "$LOG_FILE"
    if [[ -d /var/www ]]; then
        log INFO "Scanning /var/www untuk pola webshell..."
        local webshells
        webshells="$(grep -rEl '(system|exec|passthru|shell_exec|eval|base64_decode|str_rot13)\s*\(' /var/www/ 2>/dev/null | head -20 || true)"
        if [[ -n "$webshells" ]]; then
            log WARN "File PHP dengan pola webshell ditemukan:"
            echo "$webshells" | tee -a "$LOG_FILE"
            threats_found=$((threats_found + 1))
        else
            log OK "Tidak ada indikasi webshell di /var/www"
            echo "Bersih" >> "$LOG_FILE"
            add_score 10 "Tidak ada indikasi webshell"
        fi
    else
        log INFO "/var/www tidak ada, skip deteksi webshell"
        echo "/var/www tidak ada" >> "$LOG_FILE"
        add_score 10 "Tidak ada /var/www (tidak relevan)"
    fi

    if [[ $threats_found -gt 0 ]]; then
        log WARN "Total $threats_found indikator mencurigakan ditemukan. Periksa laporan: $LOG_FILE"
    else
        log OK "Tidak ada ancaman yang terdeteksi"
    fi

    echo "" >> "$LOG_FILE"
    echo "Total indikator mencurigakan: $threats_found" >> "$LOG_FILE"
}

# =============================================================================
# TAHAP 7: LAPORAN AKHIR DAN RATING
# =============================================================================

generate_report() {
    section_header "7. LAPORAN AKHIR"

    local grade
    if   (( SCORE >= 85 )); then grade="A - Sangat baik"
    elif (( SCORE >= 70 )); then grade="B - Baik"
    elif (( SCORE >= 55 )); then grade="C - Cukup"
    elif (( SCORE >= 40 )); then grade="D - Lemah"
    else                         grade="E - Berisiko tinggi"
    fi

    {
        echo ""
        echo "================================================================"
        echo "  SECURITY RATING"
        echo "================================================================"
        echo "  Score : ${SCORE} / ${MAX_SCORE}"
        echo "  Grade : ${grade}"
        echo ""
        echo "  Detail skor:"
        for entry in "${SCORE_LOG[@]}"; do
            echo "    $entry"
        done
        echo ""
        echo "================================================================"
        echo "  REKOMENDASI MANUAL"
        echo "================================================================"
        echo "  1. Periksa authorized_keys semua user, hapus yang tidak dikenal"
        echo "  2. Audit crontab dan hapus job mencurigakan secara manual"
        echo "  3. Pertimbangkan menonaktifkan PasswordAuthentication jika"
        echo "     sudah menggunakan SSH key"
        echo "  4. Periksa koneksi established ke IP asing secara berkala"
        echo "  5. Update sistem: apt-get update && apt-get upgrade"
        echo "  6. Pasang monitoring log (auditd, logwatch, atau Wazuh)"
        echo "  7. Tinjau file hasil scan webshell jika ada temuan"
        echo ""
        echo "  File laporan  : $LOG_FILE"
        echo "  Folder backup : $BACKUP_DIR"
        echo "================================================================"
    } >> "$LOG_FILE"

    echo ""
    echo -e "${BLD}  Security Score : ${SCORE} / ${MAX_SCORE}${RST}"
    echo -e "${BLD}  Grade          : ${grade}${RST}"
    echo ""
    echo -e "  Laporan lengkap : ${CYN}${LOG_FILE}${RST}"
    [[ "$MODE" == "--enforce" || "$MODE" == "-e" ]] && \
        echo -e "  Backup          : ${CYN}${BACKUP_DIR}${RST}"
    echo ""
}

# =============================================================================
# ROLLBACK
# =============================================================================

do_rollback() {
    section_header "ROLLBACK"

    local latest_backup
    latest_backup="$(ls -dt "${SCRIPT_DIR}"/backup-* 2>/dev/null | head -1)"

    if [[ -z "$latest_backup" ]]; then
        log ERR "Tidak ada folder backup ditemukan di $SCRIPT_DIR"
        exit 1
    fi

    log INFO "Menggunakan backup dari: $latest_backup"

    local files_to_restore=(
        "/etc/ssh/sshd_config"
        "/etc/fail2ban/jail.conf"
        "/etc/fail2ban/jail.local"
        "/etc/ufw/ufw.conf"
        "/etc/ufw/user.rules"
    )

    for f in "${files_to_restore[@]}"; do
        local src="${latest_backup}${f}"
        if [[ -f "$src" ]]; then
            cp -p "$src" "$f" && log OK "Restored: $f" || log WARN "Gagal restore: $f"
        fi
    done

    # Restart service
    systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true
    systemctl restart fail2ban 2>/dev/null || true

    log OK "Rollback selesai. Verifikasi manual disarankan."
}

# =============================================================================
# TAMPILKAN BANTUAN
# =============================================================================

show_help() {
    cat <<EOF

${BLD}linux-hardening.sh${RST} - Blue Team Automation

Penggunaan:
  sudo bash linux-hardening.sh [MODE]

Mode:
  -c, --check     Audit sistem dan buat laporan. Tidak mengubah apapun.
  -e, --enforce   Terapkan hardening setelah backup otomatis.
  -r, --rollback  Kembalikan konfigurasi dari backup terakhir.
  -h, --help      Tampilkan bantuan ini.

Contoh:
  sudo bash linux-hardening.sh --check
  sudo bash linux-hardening.sh --enforce
  sudo bash linux-hardening.sh --rollback

Laporan disimpan di  : /var/log/laporan/hardening-[waktu].txt
Backup disimpan di   : [direktori script]/backup-[waktu]/

EOF
}

# =============================================================================
# MAIN
# =============================================================================

main() {
    case "${1:-}" in
        -c|--check)    MODE="--check" ;;
        -e|--enforce)  MODE="--enforce" ;;
        -r|--rollback) MODE="--rollback" ;;
        -h|--help)     show_help; exit 0 ;;
        *)
            echo -e "${RED}[-]${RST} Mode tidak dikenal. Gunakan --help untuk bantuan."
            exit 1
            ;;
    esac

    check_root
    ask_ssh_port
    init_log

    log INFO "Mode: $MODE | Port SSH: $SSH_PORT | Log: $LOG_FILE"
    echo ""

    if [[ "$MODE" == "--rollback" || "$MODE" == "-r" ]]; then
        do_rollback
        exit 0
    fi

    SERVICES_FOUND=()

    detect_system
    inventory_services
    backup_configs
    audit_defenses
    detect_threats

    if [[ "$MODE" == "--enforce" || "$MODE" == "-e" ]]; then
        apply_hardening
    fi

    generate_report
}

main "$@"
