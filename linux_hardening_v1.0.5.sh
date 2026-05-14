#!/usr/bin/env bash
# ============================================================
#  linux_hardening_v1.0.4.sh
#  Linux Blue Team Automation — Audit, Hardening & Monitoring
#  Target: Debian/Ubuntu VM (Blue Team / CTF environment)
#
#  Mode:
#    -c / --check    : Audit saja, tidak mengubah sistem
#    -e / --enforce  : Backup + Hardening aman
#    -r / --rollback : Restore dari backup terakhir
#    -h / --help     : Tampilkan bantuan
#
#  PERINGATAN: Jalankan sebagai root di VM yang sudah di-snapshot
#  Script ini TIDAK menghapus user, file, atau proses secara otomatis.
# ============================================================

set -euo pipefail

# ============================================================
# KONSTANTA & DIREKTORI OUTPUT
# ============================================================
SCRIPT_VERSION="1.0.4"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPORT_DIR="${BASE_DIR}/report"
BACKUP_DIR="${BASE_DIR}/backup/${TIMESTAMP}"
ROLLBACK_DIR="${BASE_DIR}/rollback"
DEBUG_DIR="${BASE_DIR}/debug"

REPORT_FILE="${REPORT_DIR}/laporan_${TIMESTAMP}.txt"
DEBUG_FILE="${DEBUG_DIR}/debug_${TIMESTAMP}.log"
ROLLBACK_LOG="${ROLLBACK_DIR}/rollback_${TIMESTAMP}.txt"

# Buat semua direktori yang diperlukan
mkdir -p "${REPORT_DIR}" "${BACKUP_DIR}" "${ROLLBACK_DIR}" "${DEBUG_DIR}"

# ============================================================
# WARNA & HELPER OUTPUT
# ============================================================
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${BLUE}[INFO]${NC}  $*"; log_debug "INFO: $*"; }
ok()      { echo -e "${GREEN}[OK]${NC}    $*"; log_debug "OK: $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; log_debug "WARN: $*"; }
bad()     { echo -e "${RED}[BAD]${NC}   $*"; log_debug "BAD: $*"; }
section() { echo -e "\n${BOLD}${CYAN}══════════════════════════════════════════${NC}"; \
            echo -e "${BOLD}${CYAN}  $*${NC}"; \
            echo -e "${BOLD}${CYAN}══════════════════════════════════════════${NC}"; \
            log_debug "SECTION: $*"; }

log_debug() { echo "[$(date '+%H:%M:%S')] $*" >> "${DEBUG_FILE}"; }

# Tulis ke laporan dan stdout
rpt() { echo "$*" | tee -a "${REPORT_FILE}"; }
rpt_raw() { echo "$*" >> "${REPORT_FILE}"; }

# ============================================================
# VARIABEL GLOBAL (akan diisi saat runtime)
# ============================================================
OS_ID=""; OS_VERSION=""; KERNEL=""; HOSTNAME_VAL=""
IP_ADDR=""; VIRT_TYPE=""; PKG_MGR=""; HAS_SYSTEMD=false

SSH_PORT=22
HAS_UFW=false; HAS_FAIL2BAN=false; HAS_WAZUH_AGENT=false; HAS_WAZUH_MGR=false
HAS_APACHE=false; HAS_NGINX=false; HAS_MYSQL=false; HAS_FTP=false

# Scoring
SCORE=0
SCORE_MAX=100

# ============================================================
# FUNGSI: TAMPILKAN BANTUAN
# ============================================================
show_help() {
    echo -e "${BOLD}linux_hardening_v${SCRIPT_VERSION}.sh — Blue Team Automation${NC}"
    echo ""
    echo "  Penggunaan: sudo $0 [MODE]"
    echo ""
    echo "  Mode:"
    echo "    -c, --check     Audit sistem, buat laporan. TIDAK mengubah konfigurasi."
    echo "    -e, --enforce   Backup + terapkan hardening aman. Perlu konfirmasi."
    echo "    -r, --rollback  Restore konfigurasi dari backup terakhir."
    echo "    -h, --help      Tampilkan bantuan ini."
    echo ""
    echo "  Contoh:"
    echo "    sudo $0 --check"
    echo "    sudo $0 --enforce"
    echo "    sudo $0 --rollback"
    echo ""
    echo "  Output:"
    echo "    Laporan : ${REPORT_DIR}/laporan_<timestamp>.txt"
    echo "    Debug   : ${DEBUG_DIR}/debug_<timestamp>.log"
    echo "    Backup  : ${BASE_DIR}/backup/<timestamp>/"
    echo ""
    echo "  PERINGATAN: Jalankan di VM yang sudah di-snapshot terlebih dahulu!"
}

# ============================================================
# FUNGSI: PRE-FLIGHT CHECK
# ============================================================
preflight_check() {
    section "PRE-FLIGHT CHECK"

    # Cek root
    if [[ $EUID -ne 0 ]]; then
        bad "Script harus dijalankan sebagai root."
        echo "  → Jalankan: sudo $0 $MODE"
        exit 1
    fi
    ok "Berjalan sebagai root"

    # Deteksi OS
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        OS_ID="${ID:-unknown}"
        OS_VERSION="${VERSION_ID:-unknown}"
        info "OS: ${PRETTY_NAME:-$OS_ID $OS_VERSION}"
    else
        OS_ID="unknown"; OS_VERSION="unknown"
        warn "Tidak dapat mendeteksi OS (/etc/os-release tidak ada)"
    fi

    # Cek OS kompatibel (Debian/Ubuntu)
    if [[ "${OS_ID}" != "ubuntu" && "${OS_ID}" != "debian" && \
          "${OS_ID}" != "kali" && "${OS_ID}" != "raspbian" ]]; then
        warn "OS '${OS_ID}' bukan Debian/Ubuntu. Beberapa fitur mungkin tidak bekerja."
    fi

    # Deteksi kernel
    KERNEL=$(uname -r)
    ok "Kernel: ${KERNEL}"

    # Hostname dan IP
    HOSTNAME_VAL=$(hostname 2>/dev/null || echo "unknown")
    IP_ADDR=$(hostname -I 2>/dev/null | awk '{print $1}' || ip route get 1 2>/dev/null | awk '{print $7; exit}' || echo "unknown")
    ok "Hostname: ${HOSTNAME_VAL} | IP: ${IP_ADDR}"

    # Deteksi virtualisasi
    if command -v systemd-detect-virt &>/dev/null; then
        VIRT_TYPE=$(systemd-detect-virt 2>/dev/null || echo "none")
    elif [[ -f /proc/cpuinfo ]]; then
        if grep -qi "hypervisor" /proc/cpuinfo; then
            VIRT_TYPE="hypervisor"
        else
            VIRT_TYPE="baremetal"
        fi
    else
        VIRT_TYPE="unknown"
    fi
    ok "Virtualisasi: ${VIRT_TYPE}"

    # Deteksi package manager
    if command -v apt-get &>/dev/null; then PKG_MGR="apt"
    elif command -v dnf &>/dev/null;     then PKG_MGR="dnf"
    elif command -v yum &>/dev/null;     then PKG_MGR="yum"
    else PKG_MGR="unknown"; warn "Package manager tidak dikenali"; fi
    ok "Package manager: ${PKG_MGR}"

    # Deteksi systemd
    if pidof systemd &>/dev/null || [[ "$(ps -p 1 -o comm=)" == "systemd" ]]; then
        HAS_SYSTEMD=true
        ok "systemd: aktif"
    else
        warn "systemd tidak terdeteksi — beberapa fungsi mungkin terbatas"
    fi

    log_debug "Preflight selesai: OS=${OS_ID} VER=${OS_VERSION} KERNEL=${KERNEL} VIRT=${VIRT_TYPE}"
}

# ============================================================
# FUNGSI: INVENTARIS SERVICE DAN PORT
# ============================================================
inventory_services() {
    section "INVENTARIS SERVICE & PORT"
    rpt ""; rpt "=== SERVICE AKTIF ==="; rpt ""

    if $HAS_SYSTEMD; then
        systemctl list-units --type=service --state=running --no-pager \
            --no-legend 2>/dev/null | tee -a "${REPORT_FILE}" | head -40
    else
        service --status-all 2>/dev/null | grep "[ + ]" | tee -a "${REPORT_FILE}" || true
    fi

    rpt ""; rpt "=== PORT LISTENING ==="; rpt ""

    # Gunakan ss (lebih modern dari netstat)
    if command -v ss &>/dev/null; then
        ss -tlnp 2>/dev/null | tee -a "${REPORT_FILE}"
    elif command -v netstat &>/dev/null; then
        netstat -tlnp 2>/dev/null | tee -a "${REPORT_FILE}"
    else
        warn "ss dan netstat tidak tersedia"
    fi

    # Deteksi service penting
    section "DETEKSI SERVICE PENTING"

    # Cek SSH dan port-nya
    if systemctl is-active --quiet ssh 2>/dev/null || \
       systemctl is-active --quiet sshd 2>/dev/null; then
        ok "SSH: aktif"
        # Deteksi port SSH dari config
        SSH_PORT=$(grep -E "^Port " /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | head -1)
        SSH_PORT=${SSH_PORT:-22}
        info "SSH Port: ${SSH_PORT}"
    else
        warn "SSH: tidak aktif atau tidak terdeteksi"
    fi

    # Cek HTTP/HTTPS
    if systemctl is-active --quiet apache2 2>/dev/null; then
        HAS_APACHE=true; ok "Apache2: aktif"
    fi
    if systemctl is-active --quiet nginx 2>/dev/null; then
        HAS_NGINX=true; ok "Nginx: aktif"
    fi

    # Cek MySQL/MariaDB
    if systemctl is-active --quiet mysql 2>/dev/null || \
       systemctl is-active --quiet mariadb 2>/dev/null; then
        HAS_MYSQL=true; ok "Database (MySQL/MariaDB): aktif"
    fi

    # Cek FTP
    if systemctl is-active --quiet vsftpd 2>/dev/null || \
       systemctl is-active --quiet proftpd 2>/dev/null; then
        HAS_FTP=true; warn "FTP service terdeteksi — pastikan ini diperlukan"
    fi

    # Cek Wazuh Agent
    if systemctl is-active --quiet wazuh-agent 2>/dev/null; then
        HAS_WAZUH_AGENT=true; ok "Wazuh Agent: aktif"
    elif systemctl list-units --all | grep -q "wazuh-agent" 2>/dev/null; then
        warn "Wazuh Agent: terinstal tapi tidak aktif"
    fi

    # Cek Wazuh Manager
    if systemctl is-active --quiet wazuh-manager 2>/dev/null; then
        HAS_WAZUH_MGR=true; ok "Wazuh Manager: aktif"
    fi

    # Cek Fail2ban
    if command -v fail2ban-server &>/dev/null; then
        HAS_FAIL2BAN=true
        if systemctl is-active --quiet fail2ban 2>/dev/null; then
            ok "Fail2ban: terinstal & aktif"
        else
            warn "Fail2ban: terinstal tapi tidak aktif"
        fi
    fi

    # Cek UFW
    if command -v ufw &>/dev/null; then
        HAS_UFW=true
        UFW_STATUS=$(ufw status 2>/dev/null | head -1)
        if echo "${UFW_STATUS}" | grep -q "active"; then
            ok "UFW: aktif"
        else
            warn "UFW: terinstal tapi tidak aktif"
        fi
    fi
}

# ============================================================
# FUNGSI: AUDIT DEFENSE YANG ADA
# ============================================================
audit_defense() {
    section "AUDIT KONFIGURASI DEFENSE"
    rpt ""; rpt "=== AUDIT DEFENSE ===" ; rpt ""

    # --- Audit UFW ---
    rpt "[UFW]"
    if $HAS_UFW; then
        ufw status verbose 2>/dev/null | tee -a "${REPORT_FILE}" || true
    else
        rpt "UFW tidak terinstal"
        warn "UFW tidak terinstal"
    fi

    # --- Audit Fail2ban ---
    rpt ""; rpt "[FAIL2BAN]"
    if $HAS_FAIL2BAN; then
        fail2ban-client status 2>/dev/null | tee -a "${REPORT_FILE}" || true
        fail2ban-client status sshd 2>/dev/null | tee -a "${REPORT_FILE}" || true
    else
        rpt "Fail2ban tidak terinstal"
    fi

    # --- Audit Wazuh ---
    rpt ""; rpt "[WAZUH]"
    if $HAS_WAZUH_AGENT; then
        systemctl status wazuh-agent --no-pager 2>/dev/null | head -10 | tee -a "${REPORT_FILE}" || true
        # Cek koneksi ke manager
        tail -20 /var/ossec/logs/ossec.log 2>/dev/null | grep -i "error\|connect" | \
            tee -a "${REPORT_FILE}" || true
    fi
    if $HAS_WAZUH_MGR; then
        systemctl status wazuh-manager --no-pager 2>/dev/null | head -10 | tee -a "${REPORT_FILE}" || true
    fi
    if ! $HAS_WAZUH_AGENT && ! $HAS_WAZUH_MGR; then
        rpt "Wazuh tidak terdeteksi"
    fi

    # --- Audit SSH Config ---
    section "AUDIT KONFIGURASI SSH"
    rpt ""; rpt "[SSH CONFIG AUDIT]"; rpt ""

    SSHD_CFG="/etc/ssh/sshd_config"
    if [[ ! -f "${SSHD_CFG}" ]]; then
        bad "sshd_config tidak ditemukan!"; return
    fi

    # Helper: baca nilai parameter SSH (case-insensitive, skip komentar)
    get_ssh_val() {
        grep -iE "^${1}\s" "${SSHD_CFG}" 2>/dev/null | tail -1 | awk '{print $2}'
    }

    check_ssh_param() {
        local PARAM="$1"; local SAFE_VAL="$2"; local CURRENT
        CURRENT=$(get_ssh_val "${PARAM}")
        CURRENT=${CURRENT:-"(default/tidak di-set)"}
        if [[ "${CURRENT,,}" == "${SAFE_VAL,,}" ]]; then
            ok "  SSH ${PARAM}: ${CURRENT} ✓"
            rpt "  [OK] ${PARAM} = ${CURRENT}"
        else
            warn "  SSH ${PARAM}: ${CURRENT} (disarankan: ${SAFE_VAL})"
            rpt "  [WARN] ${PARAM} = ${CURRENT} (disarankan: ${SAFE_VAL})"
        fi
    }

    check_ssh_param "PermitRootLogin"      "no"
    check_ssh_param "MaxAuthTries"         "3"
    check_ssh_param "LoginGraceTime"       "20"
    check_ssh_param "X11Forwarding"        "no"
    check_ssh_param "UseDNS"              "no"

    # PasswordAuthentication — hanya lapor, tidak ubah
    PA_VAL=$(get_ssh_val "PasswordAuthentication")
    PA_VAL=${PA_VAL:-"(default/tidak di-set)"}
    rpt ""
    rpt "  [INFO] PasswordAuthentication = ${PA_VAL}"
    info "SSH PasswordAuthentication: ${PA_VAL} (tidak diubah otomatis — verifikasi SSH key dulu)"

    # Cek Banner
    BANNER_VAL=$(get_ssh_val "Banner")
    if [[ -n "${BANNER_VAL}" && "${BANNER_VAL}" != "none" ]]; then
        ok "  SSH Banner: ${BANNER_VAL}"
        rpt "  [OK] Banner = ${BANNER_VAL}"
    else
        warn "  SSH Banner belum dikonfigurasi"
        rpt "  [WARN] Banner belum dikonfigurasi"
    fi
}

# ============================================================
# FUNGSI: DETEKSI INDIKATOR MENCURIGAKAN (IOC)
# ============================================================
detect_ioc() {
    section "DETEKSI INDIKATOR MENCURIGAKAN (IOC)"
    rpt ""; rpt "=== INDIKATOR MENCURIGAKAN ==="; rpt ""

    local FINDINGS=0

    # --- User UID 0 selain root ---
    rpt "[1] User dengan UID 0 (selain root):"
    UID0_USERS=$(awk -F: '($3 == 0 && $1 != "root") {print $1}' /etc/passwd 2>/dev/null)
    if [[ -n "${UID0_USERS}" ]]; then
        bad "  TEMUAN: User UID 0 selain root: ${UID0_USERS}"
        rpt "  [!] ${UID0_USERS}"
        FINDINGS=$((FINDINGS + 1))
    else
        ok "  Tidak ada user UID 0 selain root"
        rpt "  [OK] Tidak ditemukan"
    fi

    # --- User baru (UID >= 1000) ---
    rpt ""; rpt "[2] User dengan UID >= 1000:"
    awk -F: '$3 >= 1000 && $1 != "nobody" {printf "  UID=%s USER=%s HOME=%s\n", $3, $1, $6}' \
        /etc/passwd 2>/dev/null | tee -a "${REPORT_FILE}"

    # --- Authorized keys semua user ---
    rpt ""; rpt "[3] SSH Authorized Keys:"
    while IFS=: read -r USER _ _ _ _ HOMEDIR _; do
        KEYFILE="${HOMEDIR}/.ssh/authorized_keys"
        if [[ -f "${KEYFILE}" ]]; then
            KEY_COUNT=$(wc -l < "${KEYFILE}" 2>/dev/null || echo 0)
            warn "  ${USER}: ${KEYFILE} (${KEY_COUNT} key)"
            rpt "  [!] ${USER}: ${KEYFILE} (${KEY_COUNT} key)"
            # Tampilkan fingerprint tanpa isi penuh
            ssh-keygen -l -f "${KEYFILE}" 2>/dev/null | while read -r LINE; do
                rpt "      ${LINE}"
            done
            FINDINGS=$((FINDINGS + 1))
        fi
    done < /etc/passwd

    # --- Cronjob user ---
    rpt ""; rpt "[4] Cronjob semua user (non-kosong):"
    while IFS=: read -r USER _; do
        CRON_OUT=$(crontab -u "${USER}" -l 2>/dev/null | grep -v "^#" | grep -v "^$" || true)
        if [[ -n "${CRON_OUT}" ]]; then
            warn "  Cronjob user '${USER}':"
            rpt "  [!] Cronjob user '${USER}':"
            echo "${CRON_OUT}" | while read -r LINE; do
                rpt "      ${LINE}"
                warn "      ${LINE}"
            done
            FINDINGS=$((FINDINGS + 1))
        fi
    done < /etc/passwd

    # System-wide cron
    rpt ""; rpt "[4b] System crontab & cron.d:"
    if [[ -f /etc/crontab ]]; then
        grep -v "^#" /etc/crontab | grep -v "^$" | tee -a "${REPORT_FILE}" || true
    fi
    if [[ -d /etc/cron.d ]]; then
        for f in /etc/cron.d/*; do
            [[ -f "$f" ]] || continue
            grep -v "^#" "$f" | grep -v "^$" | while read -r LINE; do
                rpt "  [cron.d/$(basename $f)] ${LINE}"
            done
        done
    fi

    # --- Koneksi mencurigakan ---
    rpt ""; rpt "[5] Koneksi ESTABLISHED (non-standar):"
    SUSPICIOUS_PORTS="4444|9999|1234|5555|6666|31337|4545|8888"
    SUSPECT_CONNS=$(ss -tnp 2>/dev/null | grep "ESTAB" | \
        grep -E ":($SUSPICIOUS_PORTS)" || true)
    if [[ -n "${SUSPECT_CONNS}" ]]; then
        bad "  TEMUAN koneksi ke port mencurigakan:"
        echo "${SUSPECT_CONNS}" | tee -a "${REPORT_FILE}"
        FINDINGS=$((FINDINGS + 1))
    else
        ok "  Tidak ada koneksi ke port reverse shell umum"
        rpt "  [OK] Tidak ditemukan koneksi mencurigakan ke port umum"
    fi

    # Semua koneksi established (untuk referensi)
    rpt ""; rpt "[5b] Semua koneksi ESTABLISHED:"
    ss -tnp 2>/dev/null | grep "ESTAB" | tee -a "${REPORT_FILE}" || rpt "  (tidak ada)"

    # --- Proses mencurigakan ---
    rpt ""; rpt "[6] Proses mencurigakan:"
    SUSPECT_PROC=$(ps aux 2>/dev/null | grep -E \
        "nc -l|ncat -l|bash -i|/dev/tcp|python.*-c.*socket|perl.*socket|ruby.*socket|\
mkfifo.*nc|socat.*exec" | grep -v grep || true)
    if [[ -n "${SUSPECT_PROC}" ]]; then
        bad "  TEMUAN proses mencurigakan:"
        echo "${SUSPECT_PROC}" | tee -a "${REPORT_FILE}"
        FINDINGS=$((FINDINGS + 1))
    else
        ok "  Tidak ada proses reverse shell yang terdeteksi"
        rpt "  [OK] Tidak ditemukan proses mencurigakan"
    fi

    # --- Webshell PHP ---
    rpt ""; rpt "[7] Potensi Webshell PHP:"
    if [[ -d /var/www ]]; then
        WEBSHELL_FILES=$(grep -rl \
            "system\s*(\|exec\s*(\|passthru\s*(\|shell_exec\s*(\|eval\s*(\|base64_decode\s*(" \
            /var/www --include="*.php" 2>/dev/null || true)
        if [[ -n "${WEBSHELL_FILES}" ]]; then
            bad "  TEMUAN file PHP mencurigakan:"
            echo "${WEBSHELL_FILES}" | while read -r FILE; do
                rpt "  [!] ${FILE}"
                bad "  [!] ${FILE}"
            done
            FINDINGS=$((FINDINGS + 1))
        else
            ok "  Tidak ada indikasi webshell di /var/www"
            rpt "  [OK] Tidak ditemukan webshell di /var/www"
        fi

        # Cek PHP file baru (< 2 jam)
        rpt ""; rpt "[7b] File PHP yang dimodifikasi dalam 2 jam terakhir:"
        NEW_PHP=$(find /var/www -name "*.php" -mmin -120 -type f 2>/dev/null || true)
        if [[ -n "${NEW_PHP}" ]]; then
            warn "  File PHP baru/dimodifikasi:"
            echo "${NEW_PHP}" | tee -a "${REPORT_FILE}"
        else
            rpt "  [OK] Tidak ada file PHP baru"
        fi
    else
        rpt "  /var/www tidak ada — skip webshell check"
        ok "/var/www tidak ada, skip webshell check"
    fi

    # --- Analisis auth.log ---
    rpt ""; rpt "[8] Analisis auth.log — Top IP gagal login:"
    if [[ -f /var/log/auth.log ]]; then
        grep "Failed password" /var/log/auth.log 2>/dev/null | \
            awk '{print $11}' | sort | uniq -c | sort -rn | head -10 | \
            tee -a "${REPORT_FILE}" || true
        rpt ""
        rpt "[8b] Login berhasil (PERHATIKAN jika bukan dari kamu):"
        grep "Accepted password\|Accepted publickey" /var/log/auth.log 2>/dev/null | \
            tail -10 | tee -a "${REPORT_FILE}" || true
    else
        rpt "  /var/log/auth.log tidak ditemukan"
    fi

    rpt ""; rpt "[RINGKASAN IOC] Total kategori temuan mencurigakan: ${FINDINGS}"
    if [[ $FINDINGS -gt 0 ]]; then
        bad "  Ada ${FINDINGS} kategori IOC — periksa laporan dan tindak lanjuti secara MANUAL"
    else
        ok "  Tidak ada IOC kritikal yang ditemukan"
    fi

    echo "${FINDINGS}"
}

# ============================================================
# FUNGSI: MONITORING (untuk mode check)
# ============================================================
run_monitoring() {
    section "SNAPSHOT MONITORING"
    rpt ""; rpt "=== MONITORING SNAPSHOT ==="; rpt ""

    # File dimodifikasi dalam 1 jam
    rpt "[MON-1] File dimodifikasi dalam 1 jam terakhir (bukan /proc/sys/run/dev):"
    find / -mmin -60 -type f 2>/dev/null \
        | grep -v "/proc\|/sys\|/run\|/dev\|${BASE_DIR}" \
        | head -30 | tee -a "${REPORT_FILE}" || rpt "  (tidak ada / error)"

    # Proses top CPU
    rpt ""; rpt "[MON-2] Proses top CPU:"
    ps aux --sort=-%cpu 2>/dev/null | head -10 | tee -a "${REPORT_FILE}" || true

    # Login aktif saat ini
    rpt ""; rpt "[MON-3] User yang sedang login:"
    who 2>/dev/null | tee -a "${REPORT_FILE}" || true
    rpt ""; w 2>/dev/null | tee -a "${REPORT_FILE}" || true

    # History login terakhir
    rpt ""; rpt "[MON-4] History login terakhir:"
    last 2>/dev/null | head -20 | tee -a "${REPORT_FILE}" || true

    # Log Apache jika ada
    if $HAS_APACHE && [[ -f /var/log/apache2/access.log ]]; then
        rpt ""; rpt "[MON-5] Top IP request ke Apache:"
        awk '{print $1}' /var/log/apache2/access.log 2>/dev/null | \
            sort | uniq -c | sort -rn | head -10 | tee -a "${REPORT_FILE}" || true
        rpt ""; rpt "[MON-5b] Request mencurigakan ke web:"
        grep -E '\.\.\/|cmd=|shell|wget|curl|base64' /var/log/apache2/access.log 2>/dev/null | \
            tail -10 | tee -a "${REPORT_FILE}" || rpt "  (tidak ada)"
    fi
}

# ============================================================
# FUNGSI: BACKUP KONFIGURASI
# ============================================================
backup_configs() {
    section "BACKUP KONFIGURASI"
    info "Target backup: ${BACKUP_DIR}"

    local BACKUP_OK=0; local BACKUP_FAIL=0

    backup_file() {
        local SRC="$1"
        if [[ -f "${SRC}" ]]; then
            cp -p "${SRC}" "${BACKUP_DIR}/" 2>/dev/null && {
                ok "Backup: ${SRC}"
                rpt "  [BACKUP OK] ${SRC}"
                BACKUP_OK=$((BACKUP_OK + 1))
            } || {
                warn "Backup gagal: ${SRC}"
                rpt "  [BACKUP FAIL] ${SRC}"
                BACKUP_FAIL=$((BACKUP_FAIL + 1))
            }
        else
            info "Skip (tidak ada): ${SRC}"
            rpt "  [SKIP] ${SRC} tidak ditemukan"
        fi
    }

    backup_dir_content() {
        local SRC="$1"; local DEST_NAME="$2"
        if [[ -d "${SRC}" ]]; then
            mkdir -p "${BACKUP_DIR}/${DEST_NAME}"
            cp -rp "${SRC}/." "${BACKUP_DIR}/${DEST_NAME}/" 2>/dev/null && {
                ok "Backup dir: ${SRC}"
                rpt "  [BACKUP OK] ${SRC}/"
                BACKUP_OK=$((BACKUP_OK + 1))
            } || {
                warn "Backup dir gagal: ${SRC}"
                BACKUP_FAIL=$((BACKUP_FAIL + 1))
            }
        fi
    }

    # SSH
    backup_file "/etc/ssh/sshd_config"
    backup_file "/etc/ssh/banner.txt"

    # UFW
    backup_dir_content "/etc/ufw" "ufw_etc"
    if [[ -d /lib/ufw ]]; then
        backup_dir_content "/lib/ufw" "ufw_lib"
    fi

    # Fail2ban
    backup_file "/etc/fail2ban/jail.local"
    backup_file "/etc/fail2ban/jail.conf"

    # Wazuh
    backup_file "/var/ossec/etc/ossec.conf"
    backup_file "/var/ossec/etc/rules/local_rules.xml"

    # Crontabs
    [[ -f /etc/crontab ]] && backup_file "/etc/crontab"
    if [[ -d /etc/cron.d ]]; then
        backup_dir_content "/etc/cron.d" "cron_d"
    fi

    # Simpan daftar user dan port saat ini sebagai referensi
    cp /etc/passwd "${BACKUP_DIR}/passwd.bak" 2>/dev/null || true
    cp /etc/shadow "${BACKUP_DIR}/shadow.bak" 2>/dev/null || true
    ss -tlnp > "${BACKUP_DIR}/ports_before.txt" 2>/dev/null || true
    ufw status verbose > "${BACKUP_DIR}/ufw_before.txt" 2>/dev/null || true

    # Catat metadata backup
    cat > "${BACKUP_DIR}/BACKUP_META.txt" <<EOF
Backup dibuat  : $(date)
Script version : ${SCRIPT_VERSION}
OS             : ${OS_ID} ${OS_VERSION}
Hostname       : ${HOSTNAME_VAL}
IP             : ${IP_ADDR}
Berhasil       : ${BACKUP_OK} file
Gagal          : ${BACKUP_FAIL} file
EOF

    ok "Backup selesai — ${BACKUP_OK} berhasil, ${BACKUP_FAIL} gagal"
    rpt ""; rpt "Backup disimpan di: ${BACKUP_DIR}"

    # Simpan path backup untuk rollback
    echo "${BACKUP_DIR}" > "${BASE_DIR}/.last_backup_path"
}

# ============================================================
# FUNGSI: HARDENING SSH
# ============================================================
harden_ssh() {
    section "HARDENING SSH"
    local SSHD_CFG="/etc/ssh/sshd_config"

    if [[ ! -f "${SSHD_CFG}" ]]; then
        bad "sshd_config tidak ditemukan — skip SSH hardening"
        return 1
    fi

    # Fungsi helper: set atau update parameter SSH
    set_ssh_param() {
        local PARAM="$1"; local VALUE="$2"
        if grep -qiE "^#?\s*${PARAM}\s" "${SSHD_CFG}" 2>/dev/null; then
            # Sudah ada (mungkin dikomentari) — uncomment dan set nilai
            sed -i -E "s|^#?\s*(${PARAM})\s.*|${PARAM} ${VALUE}|I" "${SSHD_CFG}"
        else
            # Tambahkan di akhir file
            echo "${PARAM} ${VALUE}" >> "${SSHD_CFG}"
        fi
        info "  Set ${PARAM} = ${VALUE}"
        rpt "  [HARDENING SSH] ${PARAM} = ${VALUE}"
    }

    info "Menerapkan hardening SSH..."

    set_ssh_param "PermitRootLogin"  "no"
    set_ssh_param "MaxAuthTries"     "3"
    set_ssh_param "LoginGraceTime"   "20"
    set_ssh_param "X11Forwarding"   "no"
    set_ssh_param "UseDNS"          "no"

    # JANGAN ubah PasswordAuthentication secara otomatis
    warn "PasswordAuthentication TIDAK diubah — verifikasi SSH key dulu secara manual"
    rpt "  [SKIP] PasswordAuthentication tidak diubah (aman)"

    # Tambahkan Banner jika belum ada
    BANNER_FILE="/etc/ssh/banner.txt"
    if [[ ! -f "${BANNER_FILE}" ]]; then
        cat > "${BANNER_FILE}" <<'BANNER'
============================================================
  SISTEM INI DIPANTAU — AKSES TIDAK SAH DILARANG
  Semua aktivitas dicatat dan dilaporkan
  Unauthorized access is prohibited and will be reported
============================================================
BANNER
        ok "Banner SSH dibuat: ${BANNER_FILE}"
        rpt "  [OK] SSH Banner dibuat"
    fi
    set_ssh_param "Banner" "${BANNER_FILE}"

    # Validasi konfigurasi SSH sebelum restart
    info "Memvalidasi konfigurasi SSH (sshd -t)..."
    if sshd -t 2>/dev/null; then
        ok "Validasi sshd_config: PASSED"
        rpt "  [OK] sshd -t: valid"

        # Restart SSH
        if systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null; then
            ok "SSH berhasil direstart"
            rpt "  [OK] SSH direstart"
        else
            bad "Restart SSH gagal — cek manual"
            rpt "  [ERR] Restart SSH gagal"
        fi
    else
        bad "Validasi sshd_config GAGAL — rollback otomatis!"
        rpt "  [ERR] sshd -t gagal — rollback sshd_config"

        # Rollback dari backup
        LAST_BACKUP=$(cat "${BASE_DIR}/.last_backup_path" 2>/dev/null || echo "")
        if [[ -n "${LAST_BACKUP}" && -f "${LAST_BACKUP}/sshd_config" ]]; then
            cp "${LAST_BACKUP}/sshd_config" "${SSHD_CFG}"
            ok "Rollback sshd_config berhasil"
            rpt "  [ROLLBACK] sshd_config dikembalikan dari backup"
        else
            bad "Backup sshd_config tidak ditemukan — perbaiki manual!"
        fi
        return 1
    fi
}

# ============================================================
# FUNGSI: KONFIGURASI UFW
# ============================================================
harden_ufw() {
    section "KONFIGURASI UFW"

    # Install UFW jika belum ada
    if ! command -v ufw &>/dev/null; then
        info "UFW belum terinstal — mencoba install..."
        if [[ "${PKG_MGR}" == "apt" ]]; then
            DEBIAN_FRONTEND=noninteractive apt-get install -y ufw 2>/dev/null && {
                ok "UFW berhasil diinstal"; HAS_UFW=true
            } || { bad "Install UFW gagal"; return 1; }
        else
            warn "UFW tidak bisa diinstall otomatis (bukan apt) — skip"
            return 1
        fi
    fi

    # Catat rule UFW lama
    info "Mencatat rule UFW yang ada..."
    ufw status numbered 2>/dev/null > "${BACKUP_DIR}/ufw_rules_before.txt" || true
    rpt "  [INFO] Rule UFW lama disimpan ke backup"

    # Set default policy
    info "Set UFW default: deny incoming, allow outgoing"
    ufw --force default deny incoming  2>/dev/null
    ufw --force default allow outgoing 2>/dev/null
    rpt "  [UFW] default deny incoming, allow outgoing"

    # Allow SSH port (WAJIB — jangan sampai terkunci)
    info "Allow SSH port: ${SSH_PORT}"
    ufw allow "${SSH_PORT}/tcp" comment "SSH" 2>/dev/null
    rpt "  [UFW] Allow ${SSH_PORT}/tcp (SSH)"

    # Rate limit SSH
    ufw limit "${SSH_PORT}/tcp" comment "SSH rate limit" 2>/dev/null
    rpt "  [UFW] Rate limit SSH port ${SSH_PORT}"

    # Allow HTTP/HTTPS hanya jika web server terdeteksi
    if $HAS_APACHE || $HAS_NGINX; then
        ufw allow 80/tcp  comment "HTTP"  2>/dev/null
        ufw allow 443/tcp comment "HTTPS" 2>/dev/null
        ok "Allow HTTP/HTTPS (web server terdeteksi)"
        rpt "  [UFW] Allow 80/tcp (HTTP) dan 443/tcp (HTTPS)"
    else
        info "Web server tidak terdeteksi — HTTP/HTTPS tidak dibuka"
        rpt "  [UFW] HTTP/HTTPS tidak dibuka (web server tidak terdeteksi)"
    fi

    # Allow Wazuh hanya jika terdeteksi
    if $HAS_WAZUH_AGENT || $HAS_WAZUH_MGR; then
        ufw allow 55000/tcp comment "Wazuh" 2>/dev/null
        ufw allow 1514/udp  comment "Wazuh syslog" 2>/dev/null
        ok "Allow port Wazuh (terdeteksi)"
        rpt "  [UFW] Allow 55000/tcp dan 1514/udp (Wazuh)"
    fi

    # Blokir port berbahaya
    DANGER_PORTS=("21/tcp:FTP" "23/tcp:Telnet" "3306/tcp:MySQL-external" \
                  "4444/tcp:RevShell" "9999/tcp:Exfil" "31337/tcp:Elite-backdoor" \
                  "5555/tcp:RevShell" "6666/tcp:RevShell" "8080/tcp:AltHTTP")

    rpt ""; rpt "  [UFW] Memblokir port berbahaya:"
    for ENTRY in "${DANGER_PORTS[@]}"; do
        PORT=$(echo "${ENTRY}" | cut -d: -f1)
        LABEL=$(echo "${ENTRY}" | cut -d: -f2)
        # Hanya blokir kalau bukan SSH port
        if [[ "${PORT}" != "${SSH_PORT}/tcp" ]]; then
            ufw deny "${PORT}" comment "${LABEL}" 2>/dev/null || true
            rpt "    deny ${PORT} (${LABEL})"
        fi
    done

    # Aktifkan UFW
    info "Mengaktifkan UFW..."
    echo "y" | ufw enable 2>/dev/null && {
        ok "UFW aktif"
        rpt "  [UFW] UFW diaktifkan"
    } || {
        bad "Gagal mengaktifkan UFW"
        rpt "  [ERR] Gagal aktifkan UFW"
    }

    ufw status verbose 2>/dev/null | tee -a "${REPORT_FILE}"
}

# ============================================================
# FUNGSI: INSTALL & KONFIGURASI FAIL2BAN
# ============================================================
harden_fail2ban() {
    section "FAIL2BAN SETUP"

    # Install jika belum ada
    if ! command -v fail2ban-server &>/dev/null; then
        info "Fail2ban belum terinstal — mencoba install..."
        if [[ "${PKG_MGR}" == "apt" ]]; then
            DEBIAN_FRONTEND=noninteractive apt-get install -y fail2ban 2>/dev/null && {
                ok "Fail2ban berhasil diinstal"; HAS_FAIL2BAN=true
            } || { bad "Install Fail2ban gagal"; return 1; }
        else
            warn "Tidak bisa install Fail2ban otomatis — skip"
            return 1
        fi
    fi

    # Buat jail.local (JANGAN edit jail.conf langsung)
    JAIL_LOCAL="/etc/fail2ban/jail.local"
    info "Membuat/memperbarui ${JAIL_LOCAL}..."

    # Backup jail.local lama jika ada
    [[ -f "${JAIL_LOCAL}" ]] && cp "${JAIL_LOCAL}" "${BACKUP_DIR}/jail.local.bak" 2>/dev/null || true

    # Tulis jail.local
    cat > "${JAIL_LOCAL}" <<EOF
# jail.local — dibuat oleh linux_hardening_v${SCRIPT_VERSION}.sh
# $(date)
# JANGAN edit jail.conf — override dilakukan di file ini

[DEFAULT]
bantime  = 3600
findtime = 300
maxretry = 3
ignoreip = 127.0.0.1 ::1

[sshd]
enabled  = true
port     = ${SSH_PORT}
logpath  = /var/log/auth.log
maxretry = 3
bantime  = 7200

[vsftpd]
enabled  = false
port     = ftp
logpath  = /var/log/vsftpd.log
maxretry = 3

[apache-auth]
enabled  = $(if $HAS_APACHE; then echo true; else echo false; fi)
port     = http,https
logpath  = /var/log/apache2/error.log
maxretry = 5

[nginx-http-auth]
enabled  = $(if $HAS_NGINX; then echo true; else echo false; fi)
port     = http,https
logpath  = /var/log/nginx/error.log
maxretry = 5
EOF

    ok "jail.local ditulis"
    rpt "  [FAIL2BAN] jail.local dikonfigurasi"
    rpt "  [FAIL2BAN] sshd jail: port=${SSH_PORT} maxretry=3 bantime=7200"

    # Enable & restart
    systemctl enable fail2ban 2>/dev/null
    systemctl restart fail2ban 2>/dev/null && {
        ok "Fail2ban diaktifkan & direstart"
        rpt "  [FAIL2BAN] Aktif dan berjalan"
    } || {
        bad "Fail2ban gagal restart — cek manual"
        rpt "  [ERR] Fail2ban restart gagal"
    }
}

# ============================================================
# FUNGSI: WAZUH ACTIVE RESPONSE
# ============================================================
harden_wazuh() {
    section "WAZUH ACTIVE RESPONSE"

    if ! $HAS_WAZUH_MGR; then
        info "Wazuh Manager tidak terdeteksi — skip Active Response"
        rpt "  [SKIP] Wazuh Manager tidak terdeteksi"
        return
    fi

    OSSEC_CFG="/var/ossec/etc/ossec.conf"
    if [[ ! -f "${OSSEC_CFG}" ]]; then
        warn "ossec.conf tidak ditemukan — skip"
        return
    fi

    # Cek apakah active-response sudah dikonfigurasi
    if grep -q "firewall-drop" "${OSSEC_CFG}" 2>/dev/null; then
        ok "Wazuh Active Response sudah dikonfigurasi"
        rpt "  [WAZUH] Active Response sudah ada — tidak diubah"
        return
    fi

    info "Menambahkan Active Response ke ossec.conf..."
    rpt "  [WAZUH] Menambahkan Active Response block"

    # Tambahkan sebelum </ossec_config>
    ACTIVE_RESPONSE_BLOCK='
  <active-response>
    <command>firewall-drop</command>
    <location>local</location>
    <rules_id>5712,5710,31151,40101</rules_id>
    <timeout>600</timeout>
  </active-response>'

    sed -i "s|</ossec_config>|${ACTIVE_RESPONSE_BLOCK}\n</ossec_config>|" "${OSSEC_CFG}" 2>/dev/null && {
        ok "Active Response ditambahkan ke ossec.conf"
        rpt "  [WAZUH] Active Response: rules 5712,5710,31151,40101 timeout=600s"

        # Tambahkan rule custom untuk nmap scan jika belum ada
        LOCAL_RULES="/var/ossec/etc/rules/local_rules.xml"
        if [[ -f "${LOCAL_RULES}" ]] && ! grep -q "100001" "${LOCAL_RULES}" 2>/dev/null; then
            cat >> "${LOCAL_RULES}" <<'XML'

<!-- Rule custom: Nmap scan detection — ditambahkan oleh linux_hardening -->
<group name="nmap,scan">
  <rule id="100001" level="10">
    <if_sid>1002</if_sid>
    <match>nmap</match>
    <description>Nmap scan detected</description>
  </rule>
</group>
XML
            ok "Custom rule Nmap detection ditambahkan"
            rpt "  [WAZUH] Custom rule 100001 (nmap detection) ditambahkan"
        fi

        systemctl restart wazuh-manager 2>/dev/null && {
            ok "Wazuh Manager direstart"
            rpt "  [WAZUH] Manager direstart"
        } || bad "Restart Wazuh Manager gagal"
    } || {
        bad "Gagal edit ossec.conf — cek manual"
        rpt "  [ERR] Gagal tambah Active Response"
    }
}

# ============================================================
# FUNGSI: HITUNG SECURITY RATING
# ============================================================
calculate_rating() {
    section "SECURITY RATING"
    local SCORE=0
    local IOC_COUNT=${1:-0}

    rpt ""; rpt "=== SECURITY RATING ==="; rpt ""

    # Poin 1: OS teridentifikasi (10 poin)
    if [[ "${OS_ID}" != "unknown" ]]; then
        SCORE=$((SCORE + 10))
        rpt "  [+10] OS berhasil diidentifikasi: ${OS_ID} ${OS_VERSION}"
    else
        rpt "  [+0]  OS tidak teridentifikasi"
    fi

    # Poin 2: Backup dibuat (10 poin)
    if [[ -f "${BASE_DIR}/.last_backup_path" ]]; then
        SCORE=$((SCORE + 10))
        rpt "  [+10] Backup berhasil dibuat"
    else
        rpt "  [+0]  Backup belum dibuat (jalankan --enforce)"
    fi

    # Poin 3: SSH aman (20 poin) — cek 4 parameter
    local SSH_SCORE=0
    get_ssh_val2() { grep -iE "^${1}\s" /etc/ssh/sshd_config 2>/dev/null | tail -1 | awk '{print $2}'; }
    [[ "$(get_ssh_val2 PermitRootLogin)" == "no" ]]   && SSH_SCORE=$((SSH_SCORE + 5))
    [[ "$(get_ssh_val2 MaxAuthTries)"    == "3" ]]    && SSH_SCORE=$((SSH_SCORE + 5))
    [[ "$(get_ssh_val2 X11Forwarding)"  == "no" ]]   && SSH_SCORE=$((SSH_SCORE + 5))
    [[ "$(get_ssh_val2 UseDNS)"         == "no" ]]   && SSH_SCORE=$((SSH_SCORE + 5))
    SCORE=$((SCORE + SSH_SCORE))
    rpt "  [+${SSH_SCORE}] SSH hardening (maks 20 poin)"

    # Poin 4: Firewall aktif (15 poin)
    if $HAS_UFW && ufw status 2>/dev/null | grep -q "active"; then
        SCORE=$((SCORE + 15))
        rpt "  [+15] UFW aktif"
    elif iptables -L INPUT 2>/dev/null | grep -qv "policy ACCEPT"; then
        SCORE=$((SCORE + 10))
        rpt "  [+10] iptables aktif (UFW tidak ada)"
    else
        rpt "  [+0]  Firewall tidak aktif"
    fi

    # Poin 5: Fail2ban aktif (15 poin)
    if $HAS_FAIL2BAN && systemctl is-active --quiet fail2ban 2>/dev/null; then
        SCORE=$((SCORE + 15))
        rpt "  [+15] Fail2ban aktif"
    else
        rpt "  [+0]  Fail2ban tidak aktif"
    fi

    # Poin 6: Wazuh aktif (10 poin — jika tersedia)
    if $HAS_WAZUH_AGENT || $HAS_WAZUH_MGR; then
        if systemctl is-active --quiet wazuh-agent 2>/dev/null || \
           systemctl is-active --quiet wazuh-manager 2>/dev/null; then
            SCORE=$((SCORE + 10))
            rpt "  [+10] Wazuh aktif"
        else
            rpt "  [+0]  Wazuh terinstal tapi tidak aktif"
        fi
    else
        SCORE=$((SCORE + 5)) # Bonus 5 kalau wazuh memang tidak relevan di sistem ini
        rpt "  [+5]  Wazuh tidak relevan di sistem ini"
    fi

    # Poin 7: Tidak ada user UID 0 selain root (10 poin)
    UID0_EXTRA=$(awk -F: '($3 == 0 && $1 != "root") {print $1}' /etc/passwd 2>/dev/null)
    if [[ -z "${UID0_EXTRA}" ]]; then
        SCORE=$((SCORE + 10))
        rpt "  [+10] Tidak ada user UID 0 selain root"
    else
        rpt "  [+0]  PERINGATAN: Ada user UID 0 selain root: ${UID0_EXTRA}"
    fi

    # Poin 8: Tidak ada koneksi mencurigakan (5 poin)
    SUSP_CONN=$(ss -tnp 2>/dev/null | grep "ESTAB" | \
        grep -cE ":(4444|9999|1234|5555|6666|31337)" || true)
    if [[ "${SUSP_CONN}" -eq 0 ]]; then
        SCORE=$((SCORE + 5))
        rpt "  [+5]  Tidak ada koneksi ke port reverse shell"
    else
        rpt "  [+0]  Ada koneksi ke port mencurigakan!"
    fi

    # Poin 9: Tidak ada IOC kritikal (5 poin)
    if [[ "${IOC_COUNT}" -le 1 ]]; then
        SCORE=$((SCORE + 5))
        rpt "  [+5]  IOC rendah (${IOC_COUNT} kategori)"
    else
        rpt "  [+0]  IOC ditemukan (${IOC_COUNT} kategori)"
    fi

    # Hitung rating
    rpt ""
    rpt "  TOTAL SKOR: ${SCORE}/100"
    rpt ""

    if [[ $SCORE -ge 85 ]]; then
        GRADE="A — Sangat Baik 🟢"
    elif [[ $SCORE -ge 70 ]]; then
        GRADE="B — Baik 🟡"
    elif [[ $SCORE -ge 55 ]]; then
        GRADE="C — Cukup 🟠"
    elif [[ $SCORE -ge 40 ]]; then
        GRADE="D — Lemah 🔴"
    else
        GRADE="E — Berisiko Tinggi ⛔"
    fi

    rpt "  GRADE: ${GRADE}"
    echo -e "\n${BOLD}  Security Rating: ${SCORE}/100 — ${GRADE}${NC}\n"
    log_debug "Security Rating: ${SCORE}/100 Grade: ${GRADE}"
}

# ============================================================
# FUNGSI: GENERATE HEADER LAPORAN
# ============================================================
init_report() {
    cat > "${REPORT_FILE}" <<EOF
================================================================
  LAPORAN BLUE TEAM HARDENING AUTOMATION
  Script   : linux_hardening_v${SCRIPT_VERSION}.sh
  Mode     : ${MODE}
  Tanggal  : $(date)
================================================================

=== RINGKASAN SISTEM ===

  OS        : ${OS_ID} ${OS_VERSION}
  Kernel    : ${KERNEL}
  Hostname  : ${HOSTNAME_VAL}
  IP        : ${IP_ADDR}
  Virt      : ${VIRT_TYPE}
  PkgMgr   : ${PKG_MGR}
  systemd   : ${HAS_SYSTEMD}

================================================================
EOF
}

# ============================================================
# FUNGSI: GENERATE FOOTER LAPORAN
# ============================================================
finish_report() {
    rpt ""
    rpt "================================================================"
    rpt "  REKOMENDASI MANUAL BERIKUTNYA"
    rpt "================================================================"
    rpt ""
    rpt "  1. Verifikasi SSH key sebelum menonaktifkan PasswordAuthentication"
    rpt "  2. Tinjau semua authorized_keys yang ditemukan"
    rpt "  3. Review cronjob user yang mencurigakan"
    rpt "  4. Investigasi manual setiap IOC yang ditemukan di laporan"
    rpt "  5. Buka Wazuh Dashboard dan verifikasi agent terhubung"
    rpt "  6. Tambahkan rule GeoIP block di OPNsense jika tersedia"
    rpt "  7. Screenshot log untuk dokumentasi write-up kompetisi"
    rpt "  8. Snapshot VM setelah hardening selesai dan terverifikasi"
    rpt ""
    rpt "  File Backup : $(cat "${BASE_DIR}/.last_backup_path" 2>/dev/null || echo 'Belum ada backup')"
    rpt "  File Laporan: ${REPORT_FILE}"
    rpt "  File Debug  : ${DEBUG_FILE}"
    rpt ""
    rpt "================================================================"
    rpt "  Gunakan ilmu untuk melindungi, bukan merusak."
    rpt "  Blue Team Automation — v${SCRIPT_VERSION}"
    rpt "================================================================"

    ok "Laporan disimpan ke: ${REPORT_FILE}"
}

# ============================================================
# FUNGSI: ROLLBACK
# ============================================================
do_rollback() {
    section "MODE ROLLBACK"

    # Temukan backup terakhir
    LAST_BACKUP=$(cat "${BASE_DIR}/.last_backup_path" 2>/dev/null || echo "")

    if [[ -z "${LAST_BACKUP}" || ! -d "${LAST_BACKUP}" ]]; then
        # Coba temukan backup terbaru dari direktori
        LAST_BACKUP=$(ls -td "${BASE_DIR}/backup/"*/ 2>/dev/null | head -1 || echo "")
    fi

    if [[ -z "${LAST_BACKUP}" || ! -d "${LAST_BACKUP}" ]]; then
        bad "Tidak ada backup yang ditemukan di ${BASE_DIR}/backup/"
        bad "Rollback tidak bisa dilakukan."
        exit 1
    fi

    info "Backup yang akan di-restore: ${LAST_BACKUP}"
    echo ""

    # Konfirmasi
    read -r -p "  ⚠️  Rollback dari: ${LAST_BACKUP} ? (ketik 'ya' untuk konfirmasi): " CONFIRM
    [[ "${CONFIRM}" != "ya" ]] && { info "Rollback dibatalkan."; exit 0; }

    cat > "${ROLLBACK_LOG}" <<EOF
================================================================
  ROLLBACK LOG
  Tanggal : $(date)
  Sumber  : ${LAST_BACKUP}
================================================================
EOF

    # Restore sshd_config
    if [[ -f "${LAST_BACKUP}/sshd_config" ]]; then
        cp "${LAST_BACKUP}/sshd_config" /etc/ssh/sshd_config
        if sshd -t 2>/dev/null; then
            systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null
            ok "sshd_config di-restore dan SSH direstart"
            echo "  [OK] sshd_config restored" >> "${ROLLBACK_LOG}"
        else
            bad "sshd_config dari backup tidak valid — TIDAK direstart"
            echo "  [ERR] sshd_config backup tidak valid" >> "${ROLLBACK_LOG}"
        fi
    fi

    # Restore UFW config
    if [[ -d "${LAST_BACKUP}/ufw_etc" ]]; then
        cp -rp "${LAST_BACKUP}/ufw_etc/." /etc/ufw/ 2>/dev/null && {
            ufw reload 2>/dev/null
            ok "UFW config di-restore dan direload"
            echo "  [OK] UFW restored" >> "${ROLLBACK_LOG}"
        } || {
            warn "Restore UFW config sebagian gagal"
            echo "  [WARN] UFW restore partial" >> "${ROLLBACK_LOG}"
        }
    fi

    # Restore jail.local
    if [[ -f "${LAST_BACKUP}/jail.local.bak" ]]; then
        cp "${LAST_BACKUP}/jail.local.bak" /etc/fail2ban/jail.local
        systemctl restart fail2ban 2>/dev/null
        ok "jail.local di-restore dan Fail2ban direstart"
        echo "  [OK] jail.local restored" >> "${ROLLBACK_LOG}"
    fi

    echo "" >> "${ROLLBACK_LOG}"
    echo "Rollback selesai: $(date)" >> "${ROLLBACK_LOG}"

    ok "Rollback selesai. Log: ${ROLLBACK_LOG}"
}

# ============================================================
# MAIN — PARSE ARGUMEN
# ============================================================
MODE="${1:-}"

# Tampilkan header
echo ""
echo -e "${BOLD}${CYAN}  linux_hardening_v${SCRIPT_VERSION}.sh — Blue Team Automation${NC}"
echo -e "${CYAN}  $(date)${NC}"
echo ""

case "${MODE}" in
    -h|--help)
        show_help
        exit 0
        ;;
    -c|--check)
        info "Mode: CHECK (read-only audit)"
        preflight_check
        init_report
        inventory_services
        audit_defense
        IOC_RESULT=$(detect_ioc)
        run_monitoring
        calculate_rating "${IOC_RESULT}"
        finish_report
        ;;
    -e|--enforce)
        warn "Mode: ENFORCE — akan melakukan perubahan sistem"
        echo ""
        read -r -p "  ⚠️  Pastikan VM sudah di-snapshot! Lanjutkan? (ketik 'ya'): " CONFIRM
        [[ "${CONFIRM}" != "ya" ]] && { info "Dibatalkan."; exit 0; }

        preflight_check
        init_report
        inventory_services
        audit_defense
        IOC_RESULT=$(detect_ioc)
        backup_configs
        harden_ssh
        harden_ufw
        harden_fail2ban
        harden_wazuh
        run_monitoring
        calculate_rating "${IOC_RESULT}"
        finish_report
        ;;
    -r|--rollback)
        info "Mode: ROLLBACK"
        preflight_check
        do_rollback
        ;;
    "")
        bad "Mode tidak ditentukan."
        echo "  Gunakan: sudo $0 --help"
        exit 1
        ;;
    *)
        bad "Mode tidak dikenali: ${MODE}"
        echo "  Gunakan: sudo $0 --help"
        exit 1
        ;;
esac

exit 0
