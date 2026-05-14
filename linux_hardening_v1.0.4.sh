#!/usr/bin/env bash
# =============================================================================
#
#   ██████╗ ███████╗███████╗███████╗███╗   ██╗██████╗ ███████╗██████╗
#   ██╔══██╗██╔════╝██╔════╝██╔════╝████╗  ██║██╔══██╗██╔════╝██╔══██╗
#   ██║  ██║█████╗  █████╗  █████╗  ██╔██╗ ██║██║  ██║█████╗  ██████╔╝
#   ██║  ██║██╔══╝  ██╔══╝  ██╔══╝  ██║╚██╗██║██║  ██║██╔══╝  ██╔══██╗
#   ██████╔╝███████╗██║     ███████╗██║ ╚████║██████╔╝███████╗██║  ██║
#   ╚═════╝ ╚══════╝╚═╝     ╚══════╝╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═╝  ╚═╝
#
#   linux_hardening_v1.0.4.sh — Linux Blue Team Defensive Automation
#   Versi   : 1.0.4
#   Target  : Debian / Ubuntu (systemd-based)
#   Tujuan  : Audit, hardening, monitoring, dan respons insiden defensif
#
# =============================================================================
#   STRUKTUR OUTPUT:
#     ./report/laporan_[waktu].txt   — laporan lengkap
#     ./debug/debug_[waktu].log      — log debug internal
#     ./backup/[waktu]/              — backup konfigurasi (mode enforce)
#     ./rollback/rollback_[waktu].txt — catatan rollback
#
#   CARA PAKAI:
#     chmod +x linux_hardening_v1.0.4.sh
#     sudo ./linux_hardening_v1.0.4.sh --check     # audit tanpa ubah apapun
#     sudo ./linux_hardening_v1.0.4.sh --enforce   # terapkan hardening
#     sudo ./linux_hardening_v1.0.4.sh --rollback  # kembalikan dari backup
#     sudo ./linux_hardening_v1.0.4.sh --help
#
#   PRINSIP AMAN:
#     - Tidak ada aksi destruktif tanpa backup
#     - Tidak mematikan SSH secara agresif
#     - PasswordAuthentication tidak diubah otomatis
#     - Semua temuan hanya dilaporkan (tidak dihapus otomatis)
#     - Rollback otomatis jika validasi SSH gagal
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

# =============================================================================
# ── KONFIGURASI GLOBAL ────────────────────────────────────────────────────────
# =============================================================================

readonly SCRIPT_VERSION="1.0.4"
readonly SCRIPT_NAME="linux_hardening"
readonly TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# Direktori output relatif terhadap lokasi script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly BASE_DIR="${SCRIPT_DIR}"
readonly REPORT_DIR="${BASE_DIR}/report"
readonly DEBUG_DIR="${BASE_DIR}/debug"
readonly BACKUP_DIR="${BASE_DIR}/backup/${TIMESTAMP}"
readonly ROLLBACK_DIR="${BASE_DIR}/rollback"

readonly REPORT_FILE="${REPORT_DIR}/laporan_${TIMESTAMP}.txt"
readonly DEBUG_FILE="${DEBUG_DIR}/debug_${TIMESTAMP}.log"
readonly ROLLBACK_FILE="${ROLLBACK_DIR}/rollback_${TIMESTAMP}.txt"

# Port berbahaya yang diblokir di mode enforce
readonly DANGEROUS_PORTS="21 23 4444 9999 1234 5555 6666 8888 31337"

# Port Wazuh
readonly WAZUH_AGENT_PORT="1514"
readonly WAZUH_MANAGER_PORT="55000"

# Warna terminal
readonly RED='\033[0;31m'
readonly YELLOW='\033[1;33m'
readonly GREEN='\033[0;32m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly MAGENTA='\033[0;35m'
readonly BOLD='\033[1m'
readonly DIM='\033[2m'
readonly RESET='\033[0m'

# Mode operasi (diisi dari argumen)
MODE=""

# Variabel state global
CURRENT_SSH_PORT="22"
WAZUH_AGENT_ACTIVE="false"
WAZUH_MANAGER_ACTIVE="false"
WEB_SERVICE_ACTIVE="false"
UFW_ACTIVE="false"

# Variabel scoring
SCORE=0
declare -A SCORE_ITEMS=()

# Array tracking
declare -a SUSPICIOUS_FINDINGS=()
declare -a CHANGES_MADE=()
declare -a BACKUP_FILES=()
declare -a RECOMMENDATIONS=()
declare -a INCIDENT_ACTIONS=()

# =============================================================================
# ── FUNGSI UTILITAS ───────────────────────────────────────────────────────────
# =============================================================================

# ── Logging ──────────────────────────────────────────────────────────────────

_log() {
    local level="$1"; shift
    local msg="$*"
    local ts
    ts=$(date +"%H:%M:%S")
    printf "[%s] [%-6s] %s\n" "${ts}" "${level}" "${msg}" >> "${DEBUG_FILE}" 2>/dev/null || true
}

# ── Print ke terminal ─────────────────────────────────────────────────────────

print_header() {
    local title="$1"
    local width=66
    local line
    line=$(printf '═%.0s' $(seq 1 $width))
    echo ""
    echo -e "${BOLD}${BLUE}╔${line}╗${RESET}"
    printf "${BOLD}${BLUE}║  %-${width}s║${RESET}\n" "${title}"
    echo -e "${BOLD}${BLUE}╚${line}╝${RESET}"
    _log "INFO" "=== ${title} ==="
}

print_sub() {
    echo -e "\n  ${BOLD}${CYAN}── $1 ──${RESET}"
    _log "INFO" "-- $1 --"
}

print_ok()     { echo -e "  ${GREEN}[✓]${RESET} $*"; _log "OK"   "$*"; }
print_warn()   { echo -e "  ${YELLOW}[!]${RESET} $*"; _log "WARN" "$*"; }
print_bad()    { echo -e "  ${RED}[✗]${RESET} $*"; _log "BAD"  "$*"; SUSPICIOUS_FINDINGS+=("$*"); }
print_info()   { echo -e "  ${DIM}[·]${RESET} $*"; _log "INFO" "$*"; }
print_change() { echo -e "  ${YELLOW}[→]${RESET} $*"; _log "CHG"  "$*"; CHANGES_MADE+=("$*"); }
print_action() { echo -e "  ${MAGENTA}[★]${RESET} $*"; _log "ACT"  "$*"; INCIDENT_ACTIONS+=("$*"); }

# ── Laporan ──────────────────────────────────────────────────────────────────

R() { printf "%s\n" "$*" >> "${REPORT_FILE}"; }

R_section() {
    R ""
    R "╔══════════════════════════════════════════════════════════════════╗"
    printf "║  %-64s║\n" "$1" >> "${REPORT_FILE}"
    R "╚══════════════════════════════════════════════════════════════════╝"
}

R_line() { R "  $*"; }
R_blank() { R ""; }

# ── Rekomendasi ───────────────────────────────────────────────────────────────

add_rec() { RECOMMENDATIONS+=("$*"); }

# ── Helper ────────────────────────────────────────────────────────────────────

cmd_exists() { command -v "$1" &>/dev/null; }

service_active() {
    systemctl is-active "$1" &>/dev/null 2>&1
}

port_listening() {
    local port="$1"
    if cmd_exists ss; then
        ss -tlnp 2>/dev/null | grep -q ":${port}[[:space:]]"
    elif cmd_exists netstat; then
        netstat -tlnp 2>/dev/null | grep -q ":${port}[[:space:]]"
    else
        return 1
    fi
}

get_established_conns() {
    if cmd_exists ss; then
        ss -tnp 2>/dev/null | grep -i estab || true
    elif cmd_exists netstat; then
        netstat -antp 2>/dev/null | grep -i established || true
    fi
}

# =============================================================================
# ── PRE-FLIGHT ────────────────────────────────────────────────────────────────
# =============================================================================

preflight_check() {
    # ── Cek root ─────────────────────────────────────────────────────────────
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[ERROR] Script harus dijalankan sebagai root.${RESET}"
        echo "        Gunakan: sudo ./$(basename "$0") --${MODE}"
        exit 1
    fi

    # ── Buat direktori output ─────────────────────────────────────────────────
    mkdir -p "${REPORT_DIR}" "${DEBUG_DIR}" "${ROLLBACK_DIR}"
    [[ "$MODE" == "enforce" ]] && mkdir -p "${BACKUP_DIR}"

    # ── Init file output ──────────────────────────────────────────────────────
    : > "${REPORT_FILE}"
    : > "${DEBUG_FILE}"

    # ── Header laporan ────────────────────────────────────────────────────────
    R "╔══════════════════════════════════════════════════════════════════╗"
    R "║         LAPORAN KEAMANAN — linux_hardening v${SCRIPT_VERSION}            ║"
    R "╠══════════════════════════════════════════════════════════════════╣"
    R_line "Tanggal   : $(date '+%A, %d %B %Y %H:%M:%S %Z')"
    R_line "Mode      : ${MODE^^}"
    R_line "Hostname  : $(hostname -f 2>/dev/null || hostname)"
    R_line "Script    : $(realpath "$0")"
    R "╚══════════════════════════════════════════════════════════════════╝"

    _log "INFO" "Script dimulai. Mode=${MODE} PID=$$"
}

# =============================================================================
# ── FASE 1: IDENTIFIKASI SISTEM ───────────────────────────────────────────────
# =============================================================================

phase_identify() {
    print_header "FASE 1 — IDENTIFIKASI SISTEM"
    R_section "IDENTIFIKASI SISTEM"

    # ── OS ────────────────────────────────────────────────────────────────────
    local os_name="Unknown" os_version="Unknown" os_id="unknown"
    if [[ -f /etc/os-release ]]; then
        os_name=$(    . /etc/os-release && echo "${NAME:-Unknown}")
        os_version=$( . /etc/os-release && echo "${VERSION_ID:-Unknown}")
        os_id=$(      . /etc/os-release && echo "${ID:-unknown}")
    fi

    print_info "OS          : ${os_name} ${os_version}"
    R_line "OS          : ${os_name} ${os_version}"

    if echo "${os_id}" | grep -qiE "^(debian|ubuntu|kali|linuxmint|pop)$"; then
        print_ok "Platform Debian/Ubuntu — didukung penuh"
        R_line "Platform    : Debian/Ubuntu [SUPPORTED]"
        add_score "os_detected" 10
    else
        print_warn "Platform bukan Debian/Ubuntu — beberapa fungsi mungkin tidak optimal"
        R_line "Platform    : ${os_id} [PARTIAL SUPPORT]"
        add_score "os_detected" 5
        add_rec "Verifikasi kompatibilitas script secara manual untuk OS: ${os_id}"
    fi

    # ── Kernel ────────────────────────────────────────────────────────────────
    local kernel arch
    kernel=$(uname -r)
    arch=$(uname -m)
    print_info "Kernel      : ${kernel} (${arch})"
    R_line "Kernel      : ${kernel} (${arch})"

    # ── Hostname & IP ─────────────────────────────────────────────────────────
    local hostname_val ip_list
    hostname_val=$(hostname -f 2>/dev/null || hostname)
    ip_list=$(ip -4 addr show 2>/dev/null \
        | grep -oP '(?<=inet\s)\d+(\.\d+){3}' \
        | grep -v '^127\.' \
        | tr '\n' '  ' || echo "N/A")
    print_info "Hostname    : ${hostname_val}"
    print_info "IP Address  : ${ip_list}"
    R_line "Hostname    : ${hostname_val}"
    R_line "IP Address  : ${ip_list}"

    # ── Virtualisasi ─────────────────────────────────────────────────────────
    local virt="Physical/Unknown"
    if cmd_exists systemd-detect-virt; then
        virt=$(systemd-detect-virt 2>/dev/null || echo "none")
        [[ "$virt" == "none" ]] && virt="Physical/Bare-metal"
    fi
    if cmd_exists dmidecode; then
        local dmi
        dmi=$(dmidecode -s system-product-name 2>/dev/null || true)
        echo "${dmi}" | grep -qiE "vmware|virtualbox|kvm|qemu|xen|hyper-v" \
            && virt="VM: ${dmi}"
    fi
    print_info "Virtualisasi: ${virt}"
    R_line "Virtualisasi: ${virt}"

    # ── Package Manager ──────────────────────────────────────────────────────
    local pkgmgr="Unknown"
    cmd_exists apt    && pkgmgr="apt (Debian/Ubuntu)"
    cmd_exists dnf    && pkgmgr="dnf (Fedora/RHEL)"
    cmd_exists yum    && pkgmgr="yum (RHEL/CentOS)"
    cmd_exists pacman && pkgmgr="pacman (Arch)"
    print_info "Pkg Manager : ${pkgmgr}"
    R_line "Pkg Manager : ${pkgmgr}"

    # ── Systemd ───────────────────────────────────────────────────────────────
    local init_sys="unknown"
    if [[ "$(ps -p 1 -o comm= 2>/dev/null)" == "systemd" ]] || pidof systemd &>/dev/null; then
        init_sys="systemd"
        print_ok "Init system : systemd"
    else
        init_sys="non-systemd"
        print_warn "Init system : non-systemd — periksa kompatibilitas"
        add_rec "Sistem non-systemd: verifikasi perintah service/start/stop secara manual."
    fi
    R_line "Init System : ${init_sys}"

    # ── Uptime & Load ─────────────────────────────────────────────────────────
    local uptime_str load_avg
    uptime_str=$(uptime -p 2>/dev/null || uptime)
    load_avg=$(cut -d' ' -f1-3 /proc/loadavg 2>/dev/null || echo "N/A")
    print_info "Uptime      : ${uptime_str}"
    print_info "Load Avg    : ${load_avg}"
    R_line "Uptime      : ${uptime_str}"
    R_line "Load Avg    : ${load_avg}"

    # ── Disk Usage ───────────────────────────────────────────────────────────
    local disk_usage
    disk_usage=$(df -h / 2>/dev/null | awk 'NR==2{print $3"/"$2" ("$5" used)"}' || echo "N/A")
    print_info "Disk (/)    : ${disk_usage}"
    R_line "Disk (/)    : ${disk_usage}"

    # ── RAM ──────────────────────────────────────────────────────────────────
    local ram_info
    ram_info=$(free -h 2>/dev/null | awk '/^Mem:/{print $3"/"$2" used"}' || echo "N/A")
    print_info "RAM         : ${ram_info}"
    R_line "RAM         : ${ram_info}"
}

# =============================================================================
# ── FASE 2: INVENTARIS SERVICE DAN PORT ───────────────────────────────────────
# =============================================================================

phase_inventory() {
    print_header "FASE 2 — INVENTARIS SERVICE DAN PORT"
    R_section "INVENTARIS SERVICE DAN PORT"

    # ── Service aktif ─────────────────────────────────────────────────────────
    print_sub "Service Aktif (Running)"
    R_blank; R_line "[Service Aktif]"

    local svc_list=""
    if cmd_exists systemctl; then
        svc_list=$(systemctl list-units --type=service --state=running \
            --no-pager --no-legend 2>/dev/null \
            | awk '{print $1}' | head -60)
    fi

    if [[ -n "$svc_list" ]]; then
        local count=0
        while IFS= read -r svc; do
            print_info "${svc}"
            R_line "  ${svc}"
            ((count++))
        done <<< "$svc_list"
        print_info "Total: ${count} service running"
        R_line "  Total: ${count} service running"
    else
        print_warn "Tidak dapat membaca daftar service"
        R_line "  Tidak dapat membaca daftar service"
    fi

    # ── Port Listening ────────────────────────────────────────────────────────
    print_sub "Port Listening"
    R_blank; R_line "[Port Listening]"

    local port_list=""
    if cmd_exists ss; then
        port_list=$(ss -tlnp 2>/dev/null)
    elif cmd_exists netstat; then
        port_list=$(netstat -tlnp 2>/dev/null)
    fi

    if [[ -n "$port_list" ]]; then
        echo "$port_list" | tail -n +2 | while IFS= read -r line; do
            print_info "${line}"
            R_line "  ${line}"
        done
    else
        print_warn "ss/netstat tidak tersedia"
        R_line "  ss/netstat tidak tersedia"
    fi

    # ── Deteksi Service Penting ───────────────────────────────────────────────
    print_sub "Deteksi Service Penting"
    R_blank; R_line "[Deteksi Service Penting]"

    # SSH
    _detect_important_service "SSH"       "22"   "sshd ssh openssh"
    # HTTP
    _detect_important_service "HTTP"      "80"   "apache2 nginx httpd lighttpd"
    # HTTPS
    _detect_important_service "HTTPS"     "443"  "apache2 nginx httpd"
    # MySQL/MariaDB
    _detect_important_service "MySQL"     "3306" "mysql mysqld mariadb"
    # PostgreSQL
    _detect_important_service "PostgreSQL" "5432" "postgresql"
    # FTP
    _detect_important_service "FTP"       "21"   "vsftpd proftpd pure-ftpd"
    # Wazuh
    _detect_wazuh_full
    # Firewall
    _detect_firewall_full

    # Simpan state global web service
    if port_listening "80" || port_listening "443" \
        || service_active "apache2" || service_active "nginx"; then
        WEB_SERVICE_ACTIVE="true"
    fi
}

_detect_important_service() {
    local label="$1" port="$2" svc_names="$3"
    local port_up=false svc_up=false found_svc=""

    port_listening "$port" && port_up=true

    for svc in $svc_names; do
        if service_active "$svc" 2>/dev/null; then
            svc_up=true
            found_svc="$svc"
            break
        fi
    done

    if $port_up || $svc_up; then
        local detail=""
        $svc_up && detail=" (${found_svc})"
        $port_up && detail="${detail} [port ${port}]"
        print_ok "${label} terdeteksi${detail}"
        R_line "  [AKTIF] ${label}${detail}"
    else
        print_info "${label} tidak terdeteksi"
        R_line "  [TIDAK AKTIF] ${label}"
    fi
}

_detect_wazuh_full() {
    R_blank; R_line "  [Wazuh]"

    if service_active "wazuh-agent"; then
        WAZUH_AGENT_ACTIVE="true"
        print_ok "Wazuh Agent  : AKTIF"
        R_line "  [AKTIF] Wazuh Agent"

        # Cek koneksi ke manager
        local connected
        connected=$(grep -i "connected to manager" /var/ossec/logs/ossec.log 2>/dev/null | tail -1 || true)
        [[ -n "$connected" ]] && print_ok "  Terhubung ke Wazuh Manager" \
                              || print_warn "  Status koneksi ke manager tidak terbaca"
    else
        print_info "Wazuh Agent  : tidak aktif"
        R_line "  [TIDAK AKTIF] Wazuh Agent"
    fi

    if service_active "wazuh-manager"; then
        WAZUH_MANAGER_ACTIVE="true"
        print_ok "Wazuh Manager: AKTIF"
        R_line "  [AKTIF] Wazuh Manager"

        # Cek error log
        local errs
        errs=$(tail -30 /var/ossec/logs/ossec.log 2>/dev/null \
            | grep -ic "error" || true)
        [[ "$errs" -gt 0 ]] \
            && print_warn "  ${errs} error di ossec.log (periksa manual)" \
            || print_ok  "  Log Wazuh Manager bersih"
    else
        print_info "Wazuh Manager: tidak aktif"
        R_line "  [TIDAK AKTIF] Wazuh Manager"
    fi

    if [[ "$WAZUH_AGENT_ACTIVE" == "false" && "$WAZUH_MANAGER_ACTIVE" == "false" ]]; then
        add_rec "Pertimbangkan install Wazuh Agent untuk centralized monitoring."
    fi
}

_detect_firewall_full() {
    R_blank; R_line "  [Firewall]"

    if cmd_exists ufw; then
        local ufw_st
        ufw_st=$(ufw status 2>/dev/null | head -1 | awk '{print $2}')
        if [[ "${ufw_st,,}" == "active" ]]; then
            UFW_ACTIVE="true"
            print_ok "UFW: AKTIF"
            R_line "  [AKTIF] UFW"
        else
            print_warn "UFW terinstall tapi TIDAK AKTIF"
            R_line "  [TIDAK AKTIF] UFW (terinstall)"
            add_rec "Aktifkan UFW: ufw enable"
        fi
    elif cmd_exists firewall-cmd; then
        print_info "firewalld terdeteksi"
        R_line "  [INFO] firewalld"
    elif cmd_exists iptables; then
        local rules
        rules=$(iptables -L INPUT --line-numbers 2>/dev/null | grep -c "^[0-9]" || echo 0)
        print_info "iptables tersedia (${rules} rules di INPUT chain)"
        R_line "  [INFO] iptables — ${rules} rules"
    else
        print_bad "Tidak ada firewall yang terdeteksi"
        R_line "  [TIDAK ADA] Firewall"
        add_rec "Install dan aktifkan UFW: apt install ufw && ufw enable"
    fi
}

# =============================================================================
# ── FASE 3: BACKUP KONFIGURASI ────────────────────────────────────────────────
# =============================================================================

phase_backup() {
    if [[ "$MODE" != "enforce" ]]; then
        _log "INFO" "Backup dilewati (mode: ${MODE})"
        return 0
    fi

    print_header "FASE 3 — BACKUP KONFIGURASI"
    R_section "BACKUP KONFIGURASI"
    R_line "Direktori: ${BACKUP_DIR}"
    R_line "Waktu    : $(date)"
    R_blank

    mkdir -p "${BACKUP_DIR}"

    # ── Daftar target backup ─────────────────────────────────────────────────
    declare -A TARGETS=(
        ["sshd_config"]="/etc/ssh/sshd_config"
        ["ssh_banner"]="/etc/ssh/banner.txt"
        ["ufw_dir"]="/etc/ufw"
        ["fail2ban_dir"]="/etc/fail2ban"
        ["wazuh_ossec_conf"]="/var/ossec/etc/ossec.conf"
        ["wazuh_local_rules"]="/var/ossec/etc/rules/local_rules.xml"
        ["wazuh_agent_conf"]="/var/ossec/etc/ossec.conf"
        ["etc_crontab"]="/etc/crontab"
        ["cron_daily"]="/etc/cron.d"
        ["passwd"]="/etc/passwd"
        ["shadow"]="/etc/shadow"
        ["group"]="/etc/group"
        ["sudoers"]="/etc/sudoers"
    )

    local ok_count=0 fail_count=0 skip_count=0

    for key in "${!TARGETS[@]}"; do
        local src="${TARGETS[$key]}"
        local dst="${BACKUP_DIR}/${key}"
        if [[ -e "$src" ]]; then
            if cp -rp "$src" "$dst" 2>/dev/null; then
                print_ok "Backup: ${src}"
                R_line "[OK]   ${src} → ${dst}"
                BACKUP_FILES+=("${src}")
                ((ok_count++))
            else
                print_warn "Gagal backup: ${src}"
                R_line "[FAIL] ${src}"
                ((fail_count++))
            fi
        else
            print_info "Skip (tidak ada): ${src}"
            R_line "[SKIP] ${src}"
            ((skip_count++))
        fi
    done

    # ── Backup crontab per-user ───────────────────────────────────────────────
    local cron_user_dir="${BACKUP_DIR}/crontabs_users"
    mkdir -p "$cron_user_dir"
    while IFS=: read -r uname _ uid _ _ _ _; do
        local ct
        ct=$(crontab -u "$uname" -l 2>/dev/null || true)
        if [[ -n "$ct" ]]; then
            echo "$ct" > "${cron_user_dir}/${uname}.cron"
            R_line "[OK]   crontab user ${uname}"
            ((ok_count++))
        fi
    done < /etc/passwd

    # ── Backup UFW status verbose ─────────────────────────────────────────────
    if cmd_exists ufw; then
        ufw status verbose > "${BACKUP_DIR}/ufw_status_verbose.txt" 2>/dev/null || true
        ufw status numbered > "${BACKUP_DIR}/ufw_status_numbered.txt" 2>/dev/null || true
        R_line "[OK]   UFW status verbose & numbered"
    fi

    # ── Metadata ──────────────────────────────────────────────────────────────
    {
        echo "Backup Timestamp : ${TIMESTAMP}"
        echo "Backup Dir       : ${BACKUP_DIR}"
        echo "Script Version   : ${SCRIPT_VERSION}"
        echo "Mode             : ${MODE}"
        echo "Created At       : $(date)"
        echo "OK/Fail/Skip     : ${ok_count}/${fail_count}/${skip_count}"
    } > "${BACKUP_DIR}/metadata.txt"

    R_blank
    R_line "Hasil: ${ok_count} OK, ${fail_count} GAGAL, ${skip_count} SKIP"
    print_ok "Backup selesai — ${ok_count} file, direktori: ${BACKUP_DIR}"

    add_score "backup" 10
}

# =============================================================================
# ── FASE 4: AUDIT DEFENSE ────────────────────────────────────────────────────
# =============================================================================

phase_audit() {
    print_header "FASE 4 — AUDIT DEFENSE YANG ADA"
    R_section "AUDIT DEFENSE"

    _audit_ufw
    _audit_fail2ban
    _audit_wazuh_status
    _audit_ssh_config
}

# ── Audit UFW ─────────────────────────────────────────────────────────────────

_audit_ufw() {
    print_sub "UFW Firewall"
    R_blank; R_line "[UFW]"

    if ! cmd_exists ufw; then
        print_warn "UFW tidak terinstall"
        R_line "  Status: tidak terinstall"
        add_rec "Install UFW: apt install ufw -y"
        return
    fi

    local ufw_verbose
    ufw_verbose=$(ufw status verbose 2>/dev/null)
    local ufw_state
    ufw_state=$(echo "$ufw_verbose" | awk '/^Status:/{print $2}')

    if [[ "${ufw_state,,}" == "active" ]]; then
        print_ok "Status: AKTIF"
        R_line "  Status: AKTIF"
        add_score "firewall" 15

        # Default policies
        local def_in def_out
        def_in=$(echo "$ufw_verbose"  | grep "Default:" | grep -oP 'deny\s+\(incoming\)' || echo "unknown")
        def_out=$(echo "$ufw_verbose" | grep "Default:" | grep -oP 'allow\s+\(outgoing\)' || echo "unknown")
        [[ -n "$def_in"  ]] && print_ok "Default deny incoming"  || print_warn "Default incoming belum deny"
        [[ -n "$def_out" ]] && print_ok "Default allow outgoing" || print_warn "Default outgoing belum allow"

        # Tampilkan rules
        ufw status numbered 2>/dev/null | grep -E "^\[" | while IFS= read -r line; do
            print_info "${line}"
            R_line "  ${line}"
        done
    else
        print_bad "UFW TIDAK AKTIF — sistem tidak terlindungi firewall"
        R_line "  Status: TIDAK AKTIF"
        add_rec "Aktifkan UFW dengan konfigurasi aman: jalankan mode --enforce"
    fi
}

# ── Audit Fail2ban ────────────────────────────────────────────────────────────

_audit_fail2ban() {
    print_sub "Fail2ban"
    R_blank; R_line "[Fail2ban]"

    if ! cmd_exists fail2ban-client; then
        print_warn "Fail2ban tidak terinstall"
        R_line "  Status: tidak terinstall"
        add_rec "Install Fail2ban: apt install fail2ban -y"
        return
    fi

    if service_active "fail2ban"; then
        print_ok "Status: AKTIF"
        R_line "  Status: AKTIF"
        add_score "fail2ban" 10

        # Jail summary
        local jail_summary
        jail_summary=$(fail2ban-client status 2>/dev/null || true)
        if [[ -n "$jail_summary" ]]; then
            echo "$jail_summary" | while IFS= read -r line; do
                print_info "  ${line}"
                R_line "  ${line}"
            done
        fi

        # Status sshd jail
        local sshd_st
        sshd_st=$(fail2ban-client status sshd 2>/dev/null || echo "jail sshd belum aktif")
        echo "$sshd_st" | while IFS= read -r line; do
            [[ -n "$line" ]] && { print_info "  ${line}"; R_line "  ${line}"; }
        done

        # IP yang sedang di-ban
        local banned
        banned=$(fail2ban-client status sshd 2>/dev/null \
            | grep "Banned IP" | awk -F: '{print $2}' | xargs || true)
        if [[ -n "$banned" ]]; then
            print_warn "IP yang sedang di-ban: ${banned}"
            R_line "  IP Banned: ${banned}"
        fi
    else
        print_bad "Fail2ban TIDAK AKTIF"
        R_line "  Status: TIDAK AKTIF"
        add_rec "Aktifkan Fail2ban: systemctl enable --now fail2ban"
    fi
}

# ── Audit Wazuh ───────────────────────────────────────────────────────────────

_audit_wazuh_status() {
    print_sub "Wazuh"
    R_blank; R_line "[Wazuh]"

    local wazuh_score=false

    if service_active "wazuh-agent"; then
        print_ok "Wazuh Agent  : AKTIF"
        R_line "  Wazuh Agent: AKTIF"
        wazuh_score=true

        if [[ -f /var/ossec/logs/ossec.log ]]; then
            local errs
            errs=$(grep -ic "error" /var/ossec/logs/ossec.log 2>/dev/null || true)
            [[ "$errs" -gt 0 ]] \
                && print_warn "${errs} baris error di ossec.log" \
                || print_ok  "Log Wazuh Agent bersih"
            R_line "  Error di log: ${errs}"
        fi
    else
        print_info "Wazuh Agent  : tidak aktif / tidak terinstall"
        R_line "  Wazuh Agent: tidak aktif"
    fi

    if service_active "wazuh-manager"; then
        print_ok "Wazuh Manager: AKTIF"
        R_line "  Wazuh Manager: AKTIF"
        wazuh_score=true

        # Cek active response log
        if [[ -f /var/ossec/logs/active-responses.log ]]; then
            local ar_count
            ar_count=$(wc -l < /var/ossec/logs/active-responses.log 2>/dev/null || echo 0)
            print_info "Active Response log: ${ar_count} entri"
            R_line "  Active Response log: ${ar_count} entri"
        fi
    else
        print_info "Wazuh Manager: tidak aktif / tidak terinstall"
        R_line "  Wazuh Manager: tidak aktif"
    fi

    $wazuh_score && add_score "wazuh" 10
}

# ── Audit SSH Config ──────────────────────────────────────────────────────────

_audit_ssh_config() {
    print_sub "Konfigurasi SSH"
    R_blank; R_line "[SSH Konfigurasi]"

    local cfg="/etc/ssh/sshd_config"
    if [[ ! -f "$cfg" ]]; then
        print_warn "sshd_config tidak ditemukan"
        R_line "  sshd_config tidak ditemukan"
        return
    fi

    # Helper ambil nilai parameter (case-insensitive, abaikan komentar)
    _ssh_val() {
        grep -iE "^[[:space:]]*${1}[[:space:]]" "$cfg" 2>/dev/null \
            | grep -v "^[[:space:]]*#" \
            | awk '{print $2}' | tail -1
    }

    # Port SSH
    local ssh_port
    ssh_port=$(_ssh_val "Port"); ssh_port="${ssh_port:-22}"
    CURRENT_SSH_PORT="$ssh_port"
    print_info "Port SSH          : ${ssh_port}"
    R_line "  Port SSH          : ${ssh_port}"

    # PermitRootLogin
    local root_login
    root_login=$(_ssh_val "PermitRootLogin"); root_login="${root_login:-yes}"
    if [[ "${root_login,,}" == "no" ]]; then
        print_ok "PermitRootLogin   : no (aman)"
        R_line "  PermitRootLogin   : no [OK]"
    else
        print_bad "PermitRootLogin   : ${root_login} — harus 'no'"
        R_line "  PermitRootLogin   : ${root_login} [BERISIKO]"
        add_rec "Set PermitRootLogin no di /etc/ssh/sshd_config"
    fi

    # MaxAuthTries
    local max_auth
    max_auth=$(_ssh_val "MaxAuthTries"); max_auth="${max_auth:-6}"
    if [[ "$max_auth" -le 3 ]]; then
        print_ok "MaxAuthTries      : ${max_auth} (aman)"
        R_line "  MaxAuthTries      : ${max_auth} [OK]"
    else
        print_warn "MaxAuthTries      : ${max_auth} — sebaiknya ≤ 3"
        R_line "  MaxAuthTries      : ${max_auth} [PERLU DIPERKECIL]"
        add_rec "Set MaxAuthTries 3 di /etc/ssh/sshd_config"
    fi

    # LoginGraceTime
    local grace
    grace=$(_ssh_val "LoginGraceTime"); grace="${grace:-120}"
    if [[ "$grace" -le 30 ]]; then
        print_ok "LoginGraceTime    : ${grace}s (aman)"
        R_line "  LoginGraceTime    : ${grace}s [OK]"
    else
        print_warn "LoginGraceTime    : ${grace}s — sebaiknya ≤ 30"
        R_line "  LoginGraceTime    : ${grace}s [PERLU DIPERKECIL]"
    fi

    # X11Forwarding
    local x11
    x11=$(_ssh_val "X11Forwarding"); x11="${x11:-yes}"
    if [[ "${x11,,}" == "no" ]]; then
        print_ok "X11Forwarding     : no (aman)"
        R_line "  X11Forwarding     : no [OK]"
    else
        print_warn "X11Forwarding     : ${x11} — tidak diperlukan, matikan"
        R_line "  X11Forwarding     : ${x11} [PERLU DIMATIKAN]"
        add_rec "Set X11Forwarding no di /etc/ssh/sshd_config"
    fi

    # PasswordAuthentication
    local passauth
    passauth=$(_ssh_val "PasswordAuthentication"); passauth="${passauth:-yes}"
    if [[ "${passauth,,}" == "no" ]]; then
        print_ok "PasswordAuth      : no (SSH key enforced)"
        R_line "  PasswordAuth      : no [OK]"
    else
        print_warn "PasswordAuth      : ${passauth} — pertimbangkan key-only setelah konfigurasi SSH key"
        R_line "  PasswordAuth      : ${passauth} [INFORMASI]"
        add_rec "Pertimbangkan PasswordAuthentication no setelah SSH key tim dikonfigurasi."
    fi

    # UseDNS
    local usedns
    usedns=$(_ssh_val "UseDNS"); usedns="${usedns:-yes}"
    if [[ "${usedns,,}" == "no" ]]; then
        print_ok "UseDNS            : no (lebih cepat)"
        R_line "  UseDNS            : no [OK]"
    else
        print_info "UseDNS            : ${usedns} — sebaiknya no"
        R_line "  UseDNS            : ${usedns} [INFO]"
    fi

    # Banner
    local banner
    banner=$(_ssh_val "Banner"); banner="${banner:-none}"
    if [[ "$banner" != "none" && -f "$banner" ]]; then
        print_ok "Banner            : ${banner} (ada)"
        R_line "  Banner            : ${banner} [OK]"
    else
        print_info "Banner            : tidak dikonfigurasi"
        R_line "  Banner            : tidak dikonfigurasi"
        add_rec "Tambahkan SSH banner peringatan di /etc/ssh/banner.txt"
    fi

    # SSH sudah aman → tambah skor di mode check
    if [[ "$MODE" == "check" ]] \
        && [[ "${root_login,,}" == "no" ]] \
        && [[ "$max_auth" -le 3 ]]; then
        add_score "ssh_hardened" 15
    fi
}

# =============================================================================
# ── FASE 5: HARDENING AMAN ────────────────────────────────────────────────────
# =============================================================================

phase_hardening() {
    if [[ "$MODE" != "enforce" ]]; then
        _log "INFO" "Hardening dilewati (mode: ${MODE})"
        return 0
    fi

    print_header "FASE 5 — HARDENING AMAN"
    R_section "HARDENING YANG DITERAPKAN"

    _harden_ssh
    _harden_ufw
    _harden_fail2ban
    _harden_wazuh_ar
    _harden_ssh_banner
}

# ── SSH Hardening ─────────────────────────────────────────────────────────────

_harden_ssh() {
    print_sub "SSH Hardening"
    R_blank; R_line "[SSH Hardening]"

    local cfg="/etc/ssh/sshd_config"
    [[ ! -f "$cfg" ]] && { print_warn "sshd_config tidak ditemukan"; return; }

    # Fungsi helper: set / update parameter SSH
    # - hapus semua baris (aktif dan komentar) yang match parameter
    # - tambahkan baris bersih di akhir
    _ssh_set() {
        local param="$1" value="$2"
        # hapus baris yang ada (aktif/komentar dengan parameter ini)
        sed -i -E "/^[[:space:]]*#?[[:space:]]*${param}[[:space:]]+/d" "$cfg" 2>/dev/null || true
        # tambahkan setting baru
        echo "${param} ${value}" >> "$cfg"
    }

    # Terapkan hardening
    # CATATAN: PasswordAuthentication tidak diubah otomatis (butuh verifikasi SSH key)
    _ssh_set "PermitRootLogin"  "no"
    _ssh_set "MaxAuthTries"     "3"
    _ssh_set "LoginGraceTime"   "20"
    _ssh_set "X11Forwarding"    "no"
    _ssh_set "UseDNS"           "no"
    _ssh_set "Banner"           "/etc/ssh/banner.txt"
    _ssh_set "PrintLastLog"     "yes"
    _ssh_set "TCPKeepAlive"     "yes"
    _ssh_set "ClientAliveInterval" "300"
    _ssh_set "ClientAliveCountMax" "2"

    print_change "SSH: PermitRootLogin no"
    print_change "SSH: MaxAuthTries 3"
    print_change "SSH: LoginGraceTime 20s"
    print_change "SSH: X11Forwarding no"
    print_change "SSH: UseDNS no"
    print_change "SSH: Banner /etc/ssh/banner.txt"
    print_change "SSH: ClientAliveInterval 300, CountMax 2"

    R_line "  Parameter yang diterapkan:"
    R_line "    PermitRootLogin  no"
    R_line "    MaxAuthTries     3"
    R_line "    LoginGraceTime   20"
    R_line "    X11Forwarding    no"
    R_line "    UseDNS           no"
    R_line "    Banner           /etc/ssh/banner.txt"
    R_line "    ClientAliveInterval 300 / CountMax 2"
    R_line "  [CATATAN] PasswordAuthentication tidak diubah otomatis"

    # Validasi dengan sshd -t
    print_info "Validasi konfigurasi SSH (sshd -t)..."
    local sshd_err="/tmp/.sshd_validate_$$.err"
    if sshd -t 2>"$sshd_err"; then
        print_ok "Validasi SSH: PASS — restart sshd"
        R_line "  Validasi SSH: PASS"
        systemctl restart sshd 2>/dev/null \
            || service ssh restart 2>/dev/null \
            || true
        print_change "sshd di-restart"
        R_line "  sshd di-restart"
        add_score "ssh_hardened" 15
    else
        local err_msg
        err_msg=$(cat "$sshd_err" 2>/dev/null || echo "unknown")
        print_bad "Validasi SSH: GAGAL — rollback otomatis"
        print_bad "Error: ${err_msg}"
        R_line "  Validasi SSH: GAGAL"
        R_line "  Error: ${err_msg}"

        if [[ -f "${BACKUP_DIR}/sshd_config" ]]; then
            cp "${BACKUP_DIR}/sshd_config" "$cfg"
            print_warn "sshd_config dikembalikan dari backup"
            R_line "  ROLLBACK: sshd_config dikembalikan"
            systemctl restart sshd 2>/dev/null || service ssh restart 2>/dev/null || true
        else
            print_bad "Backup sshd_config tidak tersedia — periksa manual"
        fi
    fi
    rm -f "$sshd_err"
}

# ── UFW Hardening ─────────────────────────────────────────────────────────────

_harden_ufw() {
    print_sub "UFW Hardening"
    R_blank; R_line "[UFW Hardening]"

    # Install jika belum ada
    if ! cmd_exists ufw; then
        print_info "UFW belum terinstall — install sekarang"
        apt-get install -y ufw 2>/dev/null \
            && { print_change "UFW terinstall"; R_line "  UFW diinstall"; } \
            || { print_warn "Gagal install UFW"; R_line "  Gagal install UFW"; return; }
    fi

    # Simpan rules lama ke file backup
    ufw status numbered > "${BACKUP_DIR}/ufw_rules_sebelum_enforce.txt" 2>/dev/null || true
    R_line "  Rules lama disimpan: ${BACKUP_DIR}/ufw_rules_sebelum_enforce.txt"

    # Default policy
    ufw default deny incoming 2>/dev/null || true
    ufw default allow outgoing 2>/dev/null || true
    print_change "UFW: default deny incoming / allow outgoing"
    R_line "  default deny incoming"
    R_line "  default allow outgoing"

    # ── Port SSH — WAJIB dibuka ───────────────────────────────────────────────
    local ssh_port="${CURRENT_SSH_PORT:-22}"
    ufw allow "${ssh_port}/tcp" 2>/dev/null || true
    ufw limit "${ssh_port}/tcp" 2>/dev/null || true
    print_change "UFW: allow + limit SSH port ${ssh_port}/tcp"
    R_line "  allow + limit ${ssh_port}/tcp (SSH)"

    # ── Web (hanya jika terdeteksi) ───────────────────────────────────────────
    if [[ "$WEB_SERVICE_ACTIVE" == "true" ]]; then
        ufw allow 80/tcp  2>/dev/null || true
        ufw allow 443/tcp 2>/dev/null || true
        print_change "UFW: allow 80/tcp (HTTP) dan 443/tcp (HTTPS)"
        R_line "  allow 80/tcp (HTTP)"
        R_line "  allow 443/tcp (HTTPS)"
    else
        print_info "Web service tidak terdeteksi — 80/443 tidak dibuka"
        R_line "  80/443 tidak dibuka (web tidak terdeteksi)"
    fi

    # ── Wazuh (hanya jika terdeteksi) ─────────────────────────────────────────
    if [[ "$WAZUH_AGENT_ACTIVE" == "true" || "$WAZUH_MANAGER_ACTIVE" == "true" ]]; then
        ufw allow "${WAZUH_AGENT_PORT}/tcp"   2>/dev/null || true
        ufw allow "${WAZUH_MANAGER_PORT}/tcp" 2>/dev/null || true
        print_change "UFW: allow port Wazuh ${WAZUH_AGENT_PORT} dan ${WAZUH_MANAGER_PORT}"
        R_line "  allow ${WAZUH_AGENT_PORT}/tcp (Wazuh Agent)"
        R_line "  allow ${WAZUH_MANAGER_PORT}/tcp (Wazuh Manager)"
    fi

    # ── Blokir port berbahaya ─────────────────────────────────────────────────
    for dport in $DANGEROUS_PORTS; do
        ufw deny "${dport}/tcp" 2>/dev/null || true
        print_change "UFW: deny ${dport}/tcp"
        R_line "  deny ${dport}/tcp [berbahaya]"
    done

    # ── Aktifkan UFW ──────────────────────────────────────────────────────────
    ufw --force enable 2>/dev/null || true
    print_change "UFW diaktifkan"
    R_line "  UFW diaktifkan"

    # Status akhir
    R_blank; R_line "  [UFW Status Akhir]"
    ufw status numbered 2>/dev/null | while IFS= read -r line; do
        R_line "    ${line}"
    done

    add_score "firewall" 15
}

# ── Fail2ban Hardening ────────────────────────────────────────────────────────

_harden_fail2ban() {
    print_sub "Fail2ban — Install & Konfigurasi"
    R_blank; R_line "[Fail2ban Hardening]"

    # Install jika belum ada
    if ! cmd_exists fail2ban-client; then
        print_info "Install Fail2ban..."
        if apt-get install -y fail2ban 2>/dev/null; then
            print_change "Fail2ban terinstall"
            R_line "  Fail2ban diinstall"
        else
            print_warn "Gagal install Fail2ban"
            R_line "  Gagal install Fail2ban"
            return
        fi
    fi

    # ── Buat jail.local ───────────────────────────────────────────────────────
    # PRINSIP: JANGAN edit jail.conf langsung — selalu gunakan jail.local
    local jail_local="/etc/fail2ban/jail.local"

    if [[ -f "$jail_local" ]]; then
        print_info "jail.local sudah ada — tidak ditimpa (backup tersedia)"
        R_line "  jail.local sudah ada — tidak ditimpa"
    else
        # Deteksi apakah apache/nginx ada
        local apache_enabled="false"
        local nginx_enabled="false"
        service_active "apache2" && [[ -f /var/log/apache2/error.log ]] && apache_enabled="true"
        service_active "nginx"   && [[ -f /var/log/nginx/error.log   ]] && nginx_enabled="true"

        cat > "$jail_local" << JAILLOCAL
# /etc/fail2ban/jail.local
# Dibuat otomatis oleh linux_hardening_v${SCRIPT_VERSION}
# JANGAN edit jail.conf — edit file ini saja
# Dibuat: $(date)

[DEFAULT]
# Ban selama 1 jam (3600 detik)
bantime  = 3600
# Jendela pantau: 5 menit
findtime = 300
# Blokir setelah 3 kali gagal
maxretry = 3
# Jangan ban loopback
ignoreip = 127.0.0.1/8 ::1

# ── SSH ────────────────────────────────────────────────────────────────────
[sshd]
enabled  = true
port     = ssh
logpath  = %(sshd_log)s
backend  = %(sshd_backend)s
maxretry = 3
# Ban SSH lebih lama: 2 jam
bantime  = 7200

# ── FTP (vsftpd) ───────────────────────────────────────────────────────────
[vsftpd]
enabled  = false
port     = ftp,ftp-data,ftps,ftps-data
logpath  = /var/log/vsftpd.log
maxretry = 3

# ── Apache ─────────────────────────────────────────────────────────────────
[apache-auth]
enabled  = ${apache_enabled}
port     = http,https
logpath  = /var/log/apache2/error.log
maxretry = 5

[apache-badbots]
enabled  = ${apache_enabled}
port     = http,https
logpath  = /var/log/apache2/access.log
maxretry = 2

# ── Nginx ──────────────────────────────────────────────────────────────────
[nginx-http-auth]
enabled  = ${nginx_enabled}
port     = http,https
logpath  = /var/log/nginx/error.log
maxretry = 5
JAILLOCAL

        print_change "Fail2ban jail.local dibuat (sshd enabled)"
        [[ "$apache_enabled" == "true" ]] && print_change "Fail2ban apache-auth diaktifkan"
        [[ "$nginx_enabled"  == "true" ]] && print_change "Fail2ban nginx-http-auth diaktifkan"
        R_line "  jail.local dibuat"
        R_line "  sshd jail: enabled | bantime 7200s | maxretry 3"
        R_line "  apache-auth: ${apache_enabled} | nginx: ${nginx_enabled}"
    fi

    # Enable dan restart
    systemctl enable fail2ban 2>/dev/null || true
    systemctl restart fail2ban 2>/dev/null || true

    if service_active "fail2ban"; then
        print_ok "Fail2ban berjalan"
        R_line "  Fail2ban: aktif dan berjalan"
        add_score "fail2ban" 10
    else
        print_warn "Fail2ban gagal distart — periksa: journalctl -u fail2ban"
        R_line "  Fail2ban: gagal start"
        add_rec "Periksa Fail2ban: journalctl -u fail2ban --no-pager | tail -20"
    fi
}

# ── Wazuh Active Response ─────────────────────────────────────────────────────

_harden_wazuh_ar() {
    print_sub "Wazuh Active Response"
    R_blank; R_line "[Wazuh Active Response]"

    if [[ "$WAZUH_MANAGER_ACTIVE" != "true" ]]; then
        print_info "Wazuh Manager tidak aktif — Active Response dilewati"
        R_line "  Dilewati (Wazuh Manager tidak aktif)"
        return
    fi

    local ossec_conf="/var/ossec/etc/ossec.conf"
    [[ ! -f "$ossec_conf" ]] && { print_warn "ossec.conf tidak ditemukan"; return; }

    # Cek apakah sudah dikonfigurasi
    if grep -q "firewall-drop" "$ossec_conf" 2>/dev/null; then
        print_ok "Active Response sudah ada di ossec.conf"
        R_line "  Active Response sudah terkonfigurasi — tidak ditimpa"
        return
    fi

    # Tambahkan active response sebelum </ossec_config>
    local ar_block
    ar_block=$(cat << 'ARBLOCK'

  <!-- Active Response: auto-block attacker IP via iptables -->
  <!-- Ditambahkan oleh linux_hardening.sh -->
  <active-response>
    <command>firewall-drop</command>
    <location>local</location>
    <!-- 5712/5710: SSH brute force | 31151: web attack | 40101: suspicious process -->
    <rules_id>5712,5710,31151,40101</rules_id>
    <!-- Timeout: 600 detik = 10 menit ban -->
    <timeout>600</timeout>
  </active-response>

ARBLOCK
)

    if sed -i "s|</ossec_config>|${ar_block}</ossec_config>|" "$ossec_conf" 2>/dev/null; then
        print_change "Wazuh Active Response ditambahkan (rules: 5712, 5710, 31151, 40101)"
        R_line "  Active Response ditambahkan"
        R_line "  Rules: 5712 (SSH BF), 5710 (SSH BF), 31151 (Web), 40101 (Proses)"
        R_line "  Timeout: 600 detik"
    else
        print_warn "Gagal menambahkan Active Response ke ossec.conf"
        R_line "  GAGAL menambahkan Active Response"
        return
    fi

    # Tambahkan custom rule nmap detection
    local local_rules="/var/ossec/etc/rules/local_rules.xml"
    if [[ -f "$local_rules" ]] && ! grep -q "100001" "$local_rules" 2>/dev/null; then
        cat >> "$local_rules" << 'WAZUHRULE'

<!-- Custom rule: Nmap scan detection — dibuat oleh linux_hardening.sh -->
<group name="nmap,scan,local">
  <rule id="100001" level="10">
    <if_sid>1002</if_sid>
    <match>nmap</match>
    <description>Nmap scan terdeteksi dari log sistem</description>
  </rule>
</group>
WAZUHRULE
        print_change "Custom rule Wazuh 100001 (nmap detection) ditambahkan"
        R_line "  Custom rule 100001 (nmap detection) ditambahkan"
    fi

    # Restart Wazuh Manager
    systemctl restart wazuh-manager 2>/dev/null || true
    print_change "Wazuh Manager di-restart"
    R_line "  Wazuh Manager di-restart"
}

# ── SSH Banner ────────────────────────────────────────────────────────────────

_harden_ssh_banner() {
    print_sub "SSH Login Banner"
    R_blank; R_line "[SSH Banner]"

    local banner_file="/etc/ssh/banner.txt"

    if [[ -f "$banner_file" ]]; then
        print_info "Banner sudah ada — tidak ditimpa"
        R_line "  Banner sudah ada — tidak ditimpa"
        return
    fi

    cat > "$banner_file" << 'BANNER'
╔══════════════════════════════════════════════════════════╗
║        SISTEM INI DIPANTAU — AKSES TIDAK SAH DILARANG       ║
║   Unauthorized access is strictly prohibited and logged.    ║
║     All activities are monitored and will be reported.      ║
╚══════════════════════════════════════════════════════════╝
BANNER

    print_change "SSH banner dibuat: ${banner_file}"
    R_line "  Banner dibuat: ${banner_file}"
}

# =============================================================================
# ── FASE 6: DETEKSI ANCAMAN ───────────────────────────────────────────────────
# =============================================================================

phase_threat_detection() {
    print_header "FASE 6 — DETEKSI INDIKATOR ANCAMAN"
    R_section "DETEKSI ANCAMAN"

    _detect_uid0
    _detect_new_users
    _detect_authorized_keys
    _detect_suspicious_cron
    _detect_suspicious_connections
    _detect_suspicious_processes
    _detect_webshells
    _detect_auth_log
    _detect_recently_modified
}

# ── UID 0 selain root ─────────────────────────────────────────────────────────

_detect_uid0() {
    print_sub "User UID 0"
    R_blank; R_line "[User UID 0]"

    local bad_uid0=0
    while IFS=: read -r uname _ uid _; do
        if [[ "$uid" -eq 0 ]]; then
            if [[ "$uname" == "root" ]]; then
                print_ok "root (UID 0) — normal"
                R_line "  root — normal"
            else
                print_bad "UID 0 BUKAN ROOT: ${uname} — SANGAT MENCURIGAKAN"
                R_line "  [ALERT] ${uname} UID=0 — bukan root!"
                add_rec "SEGERA audit user ${uname} (UID 0 bukan root): getent passwd ${uname}"
                ((bad_uid0++))
            fi
        fi
    done < /etc/passwd

    [[ $bad_uid0 -eq 0 ]] && add_score "no_extra_uid0" 10
}

# ── User baru (UID ≥ 1000) ────────────────────────────────────────────────────

_detect_new_users() {
    print_sub "User dengan UID ≥ 1000"
    R_blank; R_line "[User UID >= 1000]"

    local count=0
    while IFS=: read -r uname _ uid _ _ home shell; do
        if [[ "$uid" -ge 1000 ]] && [[ "$uname" != "nobody" ]]; then
            print_info "User: ${uname} | UID: ${uid} | Home: ${home} | Shell: ${shell}"
            R_line "  ${uname} | UID=${uid} | ${home} | ${shell}"

            # Peringatan jika shell login dan user tidak dikenal
            if echo "${shell}" | grep -qvE "(nologin|false|sync)"; then
                print_warn "  → ${uname} memiliki shell login aktif: ${shell}"
                R_line "    [WARN] Shell login aktif: ${shell}"
            fi
            ((count++))
        fi
    done < /etc/passwd

    [[ $count -eq 0 ]] && print_info "Tidak ada user UID ≥ 1000 (selain nobody)"
    R_line "  Total user UID >= 1000: ${count}"
}

# ── Authorized Keys ───────────────────────────────────────────────────────────

_detect_authorized_keys() {
    print_sub "SSH Authorized Keys"
    R_blank; R_line "[Authorized Keys]"

    local total_keys=0
    while IFS=: read -r uname _ uid _ _ home _; do
        local keyfile="${home}/.ssh/authorized_keys"
        if [[ -f "$keyfile" ]]; then
            local key_count
            key_count=$(grep -cE "^(ssh-|ecdsa-|sk-)" "$keyfile" 2>/dev/null || echo 0)
            print_info "${uname}: ${key_count} key di ${keyfile}"
            R_line "  ${uname}: ${key_count} key"
            ((total_keys += key_count))

            # Tampilkan fingerprint untuk audit
            if cmd_exists ssh-keygen && [[ "$key_count" -gt 0 ]]; then
                ssh-keygen -l -f "$keyfile" 2>/dev/null | while IFS= read -r fp; do
                    print_info "    ${fp}"
                    R_line "    FP: ${fp}"
                done
            fi

            # Peringatan jika file bisa dibaca oleh semua orang
            local perms
            perms=$(stat -c "%a" "$keyfile" 2>/dev/null || echo "???")
            if [[ "$perms" != "600" && "$perms" != "400" ]]; then
                print_warn "  Izin file ${keyfile}: ${perms} — seharusnya 600"
                R_line "    [WARN] Izin: ${perms} (seharusnya 600)"
            fi
        fi
    done < /etc/passwd

    R_line "  Total SSH key di semua user: ${total_keys}"
}

# ── Suspicious Cron ───────────────────────────────────────────────────────────

_detect_suspicious_cron() {
    print_sub "Audit Cronjob"
    R_blank; R_line "[Cronjob]"

    local suspicious=false
    # Pattern mencurigakan
    local susp_pattern="wget|curl -|base64|nc [^a-z]|ncat|bash -i|sh -i|python.*-c|perl -e|ruby -e|/dev/tcp|/dev/udp|mkfifo|eval\b"

    # Crontab per-user
    while IFS=: read -r uname _ _ _ _ _ _; do
        local cron_out
        cron_out=$(crontab -u "$uname" -l 2>/dev/null \
            | grep -v "^[[:space:]]*#" \
            | grep -v "^[[:space:]]*$" || true)
        if [[ -n "$cron_out" ]]; then
            R_line "  [User: ${uname}]"
            echo "$cron_out" | while IFS= read -r line; do
                if echo "$line" | grep -qiE "${susp_pattern}"; then
                    print_bad "CRON MENCURIGAKAN (${uname}): ${line}"
                    R_line "    [ALERT] ${line}"
                    suspicious=true
                else
                    print_info "  cron(${uname}): ${line}"
                    R_line "    ${line}"
                fi
            done
        fi
    done < /etc/passwd

    # /etc/crontab
    if [[ -f /etc/crontab ]]; then
        R_line "  [/etc/crontab]"
        grep -v "^[[:space:]]*#" /etc/crontab | grep -v "^[[:space:]]*$" | while IFS= read -r line; do
            if echo "$line" | grep -qiE "${susp_pattern}"; then
                print_bad "CRON MENCURIGAKAN (/etc/crontab): ${line}"
                R_line "    [ALERT] ${line}"
                suspicious=true
            else
                print_info "  crontab: ${line}"
                R_line "    ${line}"
            fi
        done
    fi

    # /etc/cron.d/
    if [[ -d /etc/cron.d ]]; then
        local cronfiles
        cronfiles=$(ls /etc/cron.d/ 2>/dev/null | tr '\n' ' ')
        [[ -n "$cronfiles" ]] && {
            print_info "/etc/cron.d/: ${cronfiles}"
            R_line "  /etc/cron.d/: ${cronfiles}"
        }
    fi

    [[ "$suspicious" == "false" ]] && {
        print_ok "Tidak ada cronjob mencurigakan"
        R_line "  Tidak ada cronjob mencurigakan"
        add_score "clean_cron" 5
    }
}

# ── Koneksi Mencurigakan ──────────────────────────────────────────────────────

_detect_suspicious_connections() {
    print_sub "Koneksi Aktif Mencurigakan"
    R_blank; R_line "[Koneksi Aktif]"

    local suspicious=false
    local revshell_ports=":4444|:9999|:1234|:5555|:6666|:8888|:31337|:7777|:2222"
    local normal_ports=":22|:80|:443|:55000|:1514|:53"

    local conns
    conns=$(get_established_conns)

    if [[ -z "$conns" ]]; then
        print_info "Tidak ada koneksi established"
        R_line "  Tidak ada koneksi established"
    else
        echo "$conns" | while IFS= read -r line; do
            # Skip loopback
            echo "$line" | grep -q "127\.0\.0\." && continue
            echo "$line" | grep -q "::1" && continue

            if echo "$line" | grep -qE "${revshell_ports}"; then
                print_bad "KONEKSI MENCURIGAKAN (port reverse shell): ${line}"
                R_line "  [ALERT] ${line}"
                suspicious=true
            elif echo "$line" | grep -qvE "${normal_ports}"; then
                print_warn "Koneksi non-standar: ${line}"
                R_line "  [WARN] ${line}"
            else
                print_info "${line}"
                R_line "  ${line}"
            fi
        done
    fi

    [[ "$suspicious" == "false" ]] && {
        print_ok "Tidak ada koneksi ke port reverse shell"
        R_line "  Tidak ada koneksi mencurigakan"
        add_score "clean_connections" 10
    }
}

# ── Proses Mencurigakan ───────────────────────────────────────────────────────

_detect_suspicious_processes() {
    print_sub "Proses Mencurigakan"
    R_blank; R_line "[Proses Mencurigakan]"

    local suspicious=false
    local all_procs
    all_procs=$(ps aux 2>/dev/null)

    # Pattern proses berbahaya (reverse shell, recon, pivoting)
    declare -a PROC_PATTERNS=(
        "nc -[lep]"
        "ncat"
        "bash -i"
        "sh -i"
        "/dev/tcp"
        "python[23]? -c"
        "perl -e"
        "ruby -e"
        "mkfifo"
        "socat"
        "chisel"
        "ligolo"
    )

    for pattern in "${PROC_PATTERNS[@]}"; do
        local matches
        matches=$(echo "$all_procs" | grep -iE "${pattern}" | grep -v "grep" || true)
        if [[ -n "$matches" ]]; then
            print_bad "PROSES MENCURIGAKAN (${pattern}):"
            echo "$matches" | while IFS= read -r m; do
                print_bad "  → ${m}"
                R_line "  [ALERT] ${m}"
            done
            suspicious=true
        fi
    done

    [[ "$suspicious" == "false" ]] && {
        print_ok "Tidak ada proses mencurigakan"
        R_line "  Tidak ada proses mencurigakan"
        add_score "clean_processes" 5
    }
}

# ── Webshell Detection ────────────────────────────────────────────────────────

_detect_webshells() {
    print_sub "Deteksi Webshell"
    R_blank; R_line "[Deteksi Webshell]"

    if [[ ! -d /var/www ]]; then
        print_info "/var/www tidak ada — tidak ada web server, dilewati"
        R_line "  /var/www tidak ada — dilewati"
        add_score "clean_webshell" 10
        return
    fi

    local suspicious=false
    # Fungsi PHP berbahaya yang umum di webshell
    local php_funcs="system\(|exec\(|passthru\(|shell_exec\(|eval\(|base64_decode\(|popen\(|proc_open\(|assert\(|preg_replace.*\/e"

    # Cari file PHP dengan fungsi berbahaya
    local sus_files
    sus_files=$(grep -rlE "${php_funcs}" /var/www/ --include="*.php" 2>/dev/null || true)

    if [[ -n "$sus_files" ]]; then
        print_bad "File PHP mencurigakan (kemungkinan webshell):"
        R_line "  [ALERT] File PHP mencurigakan:"
        echo "$sus_files" | while IFS= read -r f; do
            local snippet
            snippet=$(grep -nE "${php_funcs}" "$f" 2>/dev/null | head -3 | tr '\n' ' ')
            print_bad "  File  : ${f}"
            print_bad "  Isi   : ${snippet}"
            R_line "    File   : ${f}"
            R_line "    Snippet: ${snippet}"
            suspicious=true
        done
        add_rec "Periksa file PHP mencurigakan di atas — jangan hapus sebelum diverifikasi manual."
    fi

    # PHP baru (< 2 jam)
    local new_php
    new_php=$(find /var/www -name "*.php" -mmin -120 -type f 2>/dev/null | head -20 || true)
    if [[ -n "$new_php" ]]; then
        print_warn "File PHP baru (dibuat < 2 jam):"
        R_line "  [WARN] PHP baru (< 2 jam):"
        echo "$new_php" | while IFS= read -r f; do
            print_warn "  ${f}"
            R_line "    ${f}"
        done
    fi

    # Cek isi .htaccess yang mencurigakan
    local sus_htaccess
    sus_htaccess=$(find /var/www -name ".htaccess" 2>/dev/null | xargs grep -lE "php_value|auto_append_file|base64" 2>/dev/null || true)
    if [[ -n "$sus_htaccess" ]]; then
        print_warn ".htaccess mencurigakan ditemukan: ${sus_htaccess}"
        R_line "  [WARN] .htaccess mencurigakan: ${sus_htaccess}"
    fi

    [[ "$suspicious" == "false" ]] && {
        print_ok "Tidak ada indikasi webshell"
        R_line "  Tidak ada webshell terdeteksi"
        add_score "clean_webshell" 10
    }
}

# ── Auth Log Analysis ──────────────────────────────────────────────────────────

_detect_auth_log() {
    print_sub "Analisis Auth Log"
    R_blank; R_line "[Auth Log]"

    local auth_log="/var/log/auth.log"
    [[ ! -f "$auth_log" ]] && auth_log="/var/log/secure"
    [[ ! -f "$auth_log" ]] && {
        print_warn "auth.log / secure tidak ditemukan"
        R_line "  auth.log tidak ditemukan"
        return
    }

    # Top IP yang gagal login
    print_info "Top 10 IP gagal login SSH:"
    R_line "  [Top 10 IP Gagal Login]"
    local top_fail
    top_fail=$(grep "Failed password" "$auth_log" 2>/dev/null \
        | grep -oP '(?<=from )\d+(\.\d+){3}' \
        | sort | uniq -c | sort -rn | head -10 || true)
    if [[ -n "$top_fail" ]]; then
        echo "$top_fail" | while IFS= read -r line; do
            print_warn "  ${line}"
            R_line "    ${line}"
        done
    else
        print_info "  Tidak ada login gagal"
        R_line "    Tidak ada login gagal"
    fi

    # Username yang dicoba
    print_info "Username yang dicoba penyerang:"
    R_line "  [Username Dicoba]"
    local top_user
    top_user=$(grep "Failed password" "$auth_log" 2>/dev/null \
        | grep -oP '(?<=for )\S+(?= from)' \
        | sort | uniq -c | sort -rn | head -10 || true)
    if [[ -n "$top_user" ]]; then
        echo "$top_user" | while IFS= read -r line; do
            print_warn "  ${line}"
            R_line "    ${line}"
        done
    fi

    # Login berhasil — KRITIS untuk diaudit
    print_info "Login SSH berhasil:"
    R_line "  [Login Berhasil]"
    local success
    success=$(grep -E "Accepted (password|publickey)" "$auth_log" 2>/dev/null | tail -15 || true)
    if [[ -n "$success" ]]; then
        echo "$success" | while IFS= read -r line; do
            print_info "  ${line}"
            R_line "    ${line}"
        done
    else
        print_info "  Tidak ada login berhasil di log"
        R_line "    Tidak ada login berhasil"
    fi

    # Cek root login
    local root_logins
    root_logins=$(grep "Accepted.*root" "$auth_log" 2>/dev/null | tail -5 || true)
    if [[ -n "$root_logins" ]]; then
        print_bad "ROOT LOGIN TERDETEKSI:"
        echo "$root_logins" | while IFS= read -r line; do
            print_bad "  ${line}"
            R_line "  [ALERT] Root login: ${line}"
        done
        add_rec "Root login terdeteksi — verifikasi apakah itu aktivitas tim sendiri."
    fi
}

# ── File yang Baru Dimodifikasi ────────────────────────────────────────────────

_detect_recently_modified() {
    print_sub "File Baru Dimodifikasi (< 1 jam)"
    R_blank; R_line "[File Baru Dimodifikasi]"

    local recent
    recent=$(find / -mmin -60 -type f 2>/dev/null \
        | grep -vE "^/proc|^/sys|^/run|^/dev|/var/log|/var/ossec/logs|/tmp" \
        | head -40 || true)

    if [[ -n "$recent" ]]; then
        echo "$recent" | while IFS= read -r f; do
            if echo "$f" | grep -qE "^/etc|^/usr/bin|^/usr/sbin|^/bin|^/sbin|^/root"; then
                print_warn "[SENSITIF] ${f}"
                R_line "  [SENSITIF] ${f}"
            else
                print_info "${f}"
                R_line "  ${f}"
            fi
        done
    else
        print_ok "Tidak ada file penting yang baru dimodifikasi"
        R_line "  Tidak ada file sensitif yang baru dimodifikasi"
    fi
}

# =============================================================================
# ── FASE 7: MONITORING ────────────────────────────────────────────────────────
# =============================================================================

phase_monitoring() {
    if [[ "$MODE" != "check" ]]; then
        _log "INFO" "Monitoring snapshot dilewati (mode: ${MODE})"
        return 0
    fi

    print_header "FASE 7 — MONITORING SNAPSHOT"
    R_section "MONITORING SNAPSHOT"

    # ── Siapa yang sedang login ────────────────────────────────────────────────
    print_sub "User yang Sedang Login"
    R_blank; R_line "[Who is Logged In]"
    local who_out
    who_out=$(who 2>/dev/null || true)
    if [[ -n "$who_out" ]]; then
        echo "$who_out" | while IFS= read -r line; do
            print_info "${line}"; R_line "  ${line}"
        done
    else
        print_info "Tidak ada user yang login saat ini"
        R_line "  Tidak ada user login"
    fi

    # ── Riwayat login terakhir ────────────────────────────────────────────────
    print_sub "Riwayat Login Terakhir"
    R_blank; R_line "[Last Login]"
    last 2>/dev/null | head -15 | while IFS= read -r line; do
        print_info "${line}"; R_line "  ${line}"
    done

    # ── Top proses by CPU ─────────────────────────────────────────────────────
    print_sub "Top Proses by CPU"
    R_blank; R_line "[Top Proses CPU]"
    ps aux --sort=-%cpu 2>/dev/null | head -11 | while IFS= read -r line; do
        print_info "${line}"; R_line "  ${line}"
    done

    # ── Koneksi established ───────────────────────────────────────────────────
    print_sub "Semua Koneksi Established"
    R_blank; R_line "[Koneksi Established]"
    local estab
    estab=$(get_established_conns)
    if [[ -n "$estab" ]]; then
        echo "$estab" | while IFS= read -r line; do
            print_info "${line}"; R_line "  ${line}"
        done
    else
        print_info "Tidak ada koneksi established"
        R_line "  Tidak ada koneksi established"
    fi

    # ── Apache/Nginx log snippet ──────────────────────────────────────────────
    if [[ "$WEB_SERVICE_ACTIVE" == "true" ]]; then
        print_sub "Web Access Log (Mencurigakan)"
        R_blank; R_line "[Web Log Mencurigakan]"

        for logfile in /var/log/apache2/access.log /var/log/nginx/access.log; do
            if [[ -f "$logfile" ]]; then
                # Cari request mencurigakan
                local sus_req
                sus_req=$(grep -iE "\.\./|cmd=|shell|wget|curl|base64|union.*select|<script" \
                    "$logfile" 2>/dev/null | tail -10 || true)
                if [[ -n "$sus_req" ]]; then
                    print_warn "Request mencurigakan di ${logfile}:"
                    echo "$sus_req" | while IFS= read -r line; do
                        print_warn "  ${line}"
                        R_line "  [WARN] ${line}"
                    done
                else
                    print_ok "Tidak ada request mencurigakan di ${logfile}"
                    R_line "  Log bersih: ${logfile}"
                fi
            fi
        done
    fi

    # ── Journal error terbaru ─────────────────────────────────────────────────
    print_sub "Journal Error Terbaru"
    R_blank; R_line "[Journal Errors]"
    local journal_errs
    journal_errs=$(journalctl -p err --no-pager -n 20 2>/dev/null || true)
    if [[ -n "$journal_errs" ]]; then
        echo "$journal_errs" | while IFS= read -r line; do
            print_info "${line}"; R_line "  ${line}"
        done
    else
        print_info "Tidak ada error di journal"
        R_line "  Journal bersih"
    fi

    print_info ""
    print_info "Tips Monitoring Real-Time:"
    print_info "  Terminal 1: sudo tail -f /var/log/auth.log | grep -E 'Failed|Invalid|Accepted'"
    print_info "  Terminal 2: watch -n 5 \"sudo ss -tnp | grep ESTABLISHED\""
    print_info "  Terminal 3: watch -n 30 \"find /var/www /tmp /dev/shm -mmin -10 -type f 2>/dev/null\""
}

# =============================================================================
# ── RESPONS INSIDEN CEPAT (MODE ENFORCE) ─────────────────────────────────────
# =============================================================================

phase_incident_response() {
    if [[ "$MODE" != "enforce" ]]; then
        return 0
    fi

    print_header "RESPONS INSIDEN CEPAT"
    R_section "RESPONS INSIDEN CEPAT"

    # ── Block top attacker IP (dari auth.log) ─────────────────────────────────
    print_sub "Auto-block IP Penyerang Teratas"
    R_blank; R_line "[Auto-block IP]"

    local auth_log="/var/log/auth.log"
    [[ ! -f "$auth_log" ]] && auth_log="/var/log/secure"

    if [[ -f "$auth_log" ]] && cmd_exists ufw && [[ "$UFW_ACTIVE" == "true" || "$MODE" == "enforce" ]]; then
        # Ambil IP dengan > 20 kali gagal login
        local attack_ips
        attack_ips=$(grep "Failed password" "$auth_log" 2>/dev/null \
            | grep -oP '(?<=from )\d+(\.\d+){3}' \
            | sort | uniq -c | sort -rn \
            | awk '$1 > 20 {print $2}' | head -10 || true)

        if [[ -n "$attack_ips" ]]; then
            echo "$attack_ips" | while IFS= read -r ip; do
                # Jangan blokir IP sendiri
                local own_ips
                own_ips=$(ip -4 addr show 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
                if echo "$own_ips" | grep -q "^${ip}$"; then
                    print_warn "Skip ${ip} — itu IP sendiri"
                    R_line "  [SKIP] ${ip} — IP lokal"
                else
                    ufw deny from "$ip" to any 2>/dev/null || true
                    print_action "UFW: block attacker IP ${ip} (>20 login gagal)"
                    R_line "  [BLOCKED] ${ip}"
                fi
            done
        else
            print_info "Tidak ada IP dengan >20 login gagal"
            R_line "  Tidak ada IP yang perlu di-block otomatis"
        fi
    else
        print_info "Auto-block dilewati (UFW tidak aktif atau auth.log tidak ada)"
        R_line "  Auto-block dilewati"
    fi

    # ── Cek dan kill koneksi reverse shell aktif ───────────────────────────────
    print_sub "Terminasi Koneksi Reverse Shell"
    R_blank; R_line "[Kill Reverse Shell]"

    local revshell_pattern=":4444|:9999|:1234|:5555|:6666|:8888|:31337"
    local revshell_conns
    revshell_conns=$(get_established_conns \
        | grep -E "${revshell_pattern}" \
        | grep -v "127\.0\.0\." || true)

    if [[ -n "$revshell_conns" ]]; then
        print_bad "Koneksi reverse shell terdeteksi:"
        echo "$revshell_conns" | while IFS= read -r line; do
            print_bad "  ${line}"
            R_line "  [ALERT] ${line}"

            # Ekstrak PID jika ada
            local pid
            pid=$(echo "$line" | grep -oP '(?<=pid=)\d+' | head -1 || true)
            if [[ -n "$pid" ]]; then
                print_action "KILL PID ${pid} (reverse shell)"
                R_line "  [ACTION] kill -9 ${pid}"
                # Uncomment baris berikut untuk auto-kill (hati-hati):
                # kill -9 "$pid" 2>/dev/null || true
                print_warn "  → Auto-kill TIDAK dilakukan. Jalankan manual: kill -9 ${pid}"
            fi
        done
    else
        print_ok "Tidak ada koneksi reverse shell aktif"
        R_line "  Tidak ada reverse shell aktif"
    fi

    # ── Restart service yang mungkin dikompromis ──────────────────────────────
    print_sub "Restart Service Penting"
    R_blank; R_line "[Restart Service]"

    for svc in sshd apache2 nginx; do
        if service_active "$svc"; then
            systemctl restart "$svc" 2>/dev/null || true
            print_action "Service ${svc} di-restart"
            R_line "  [RESTARTED] ${svc}"
        fi
    done

    # ── Wazuh Fail2ban status ─────────────────────────────────────────────────
    print_sub "Verifikasi Defense Setelah Enforce"
    R_blank; R_line "[Verifikasi Akhir]"

    service_active "fail2ban" \
        && { print_ok "Fail2ban: AKTIF"; R_line "  Fail2ban: OK"; } \
        || { print_warn "Fail2ban: tidak aktif"; R_line "  Fail2ban: tidak aktif"; }

    service_active "sshd" \
        && { print_ok "sshd: AKTIF"; R_line "  sshd: OK"; } \
        || { print_bad "sshd: TIDAK AKTIF — PERIKSA SEGERA"; R_line "  sshd: TIDAK AKTIF!"; }

    ufw status 2>/dev/null | grep -q "active" \
        && { print_ok "UFW: AKTIF"; R_line "  UFW: OK"; } \
        || { print_warn "UFW: tidak aktif"; R_line "  UFW: tidak aktif"; }
}

# =============================================================================
# ── FASE 8: ROLLBACK ─────────────────────────────────────────────────────────
# =============================================================================

phase_rollback() {
    print_header "ROLLBACK KONFIGURASI"

    # Init rollback log
    : > "${ROLLBACK_FILE}"
    {
        echo "╔══════════════════════════════════════════════════════════════════╗"
        echo "  ROLLBACK LOG — linux_hardening v${SCRIPT_VERSION}"
        echo "  Waktu: $(date)"
        echo "╚══════════════════════════════════════════════════════════════════╝"
        echo ""
    } >> "${ROLLBACK_FILE}"

    # Cari backup terbaru
    local latest_backup
    latest_backup=$(ls -td "${BASE_DIR}/backup"/*/ 2>/dev/null | head -1 || echo "")

    if [[ -z "$latest_backup" ]]; then
        print_bad "Tidak ada backup ditemukan di ${BASE_DIR}/backup/"
        echo "Tidak ada backup ditemukan — rollback gagal" >> "${ROLLBACK_FILE}"
        exit 1
    fi

    print_info "Backup terbaru: ${latest_backup}"
    echo "Backup sumber: ${latest_backup}" >> "${ROLLBACK_FILE}"

    # ── Rollback sshd_config ──────────────────────────────────────────────────
    print_sub "Restore sshd_config"
    if [[ -f "${latest_backup}/sshd_config" ]]; then
        cp "${latest_backup}/sshd_config" /etc/ssh/sshd_config
        print_change "sshd_config dikembalikan"
        echo "[OK] sshd_config dikembalikan" >> "${ROLLBACK_FILE}"

        # Validasi sebelum restart
        if sshd -t 2>/dev/null; then
            systemctl restart sshd 2>/dev/null \
                || service ssh restart 2>/dev/null \
                || true
            print_ok "sshd di-restart setelah rollback"
            echo "[OK] sshd di-restart" >> "${ROLLBACK_FILE}"
        else
            print_bad "sshd_config dari backup tidak valid — PERIKSA MANUAL"
            echo "[FAIL] sshd_config dari backup tidak valid" >> "${ROLLBACK_FILE}"
        fi
    else
        print_warn "Tidak ada backup sshd_config di: ${latest_backup}"
        echo "[SKIP] sshd_config — tidak ada backup" >> "${ROLLBACK_FILE}"
    fi

    # ── Rollback UFW ──────────────────────────────────────────────────────────
    print_sub "Restore UFW"
    if [[ -d "${latest_backup}/ufw_dir" ]]; then
        cp -rp "${latest_backup}/ufw_dir/." /etc/ufw/ 2>/dev/null || true
        ufw reload 2>/dev/null || true
        print_change "UFW dikembalikan dan di-reload"
        echo "[OK] UFW dikembalikan" >> "${ROLLBACK_FILE}"
    elif [[ -f "${latest_backup}/ufw_rules_sebelum_enforce.txt" ]]; then
        print_warn "UFW dir backup tidak ada — referensi manual tersedia:"
        print_warn "  ${latest_backup}/ufw_rules_sebelum_enforce.txt"
        echo "[WARN] UFW — referensi manual: ${latest_backup}/ufw_rules_sebelum_enforce.txt" >> "${ROLLBACK_FILE}"
        add_rec "Rollback UFW manual — lihat ${latest_backup}/ufw_rules_sebelum_enforce.txt"
    else
        print_warn "Tidak ada backup UFW"
        echo "[SKIP] UFW — tidak ada backup" >> "${ROLLBACK_FILE}"
    fi

    # ── Rollback Fail2ban ─────────────────────────────────────────────────────
    print_sub "Restore Fail2ban"
    if [[ -d "${latest_backup}/fail2ban_dir" ]]; then
        cp -rp "${latest_backup}/fail2ban_dir/." /etc/fail2ban/ 2>/dev/null || true
        systemctl restart fail2ban 2>/dev/null || true
        print_change "Fail2ban dikembalikan"
        echo "[OK] Fail2ban dikembalikan" >> "${ROLLBACK_FILE}"
    else
        print_info "Tidak ada backup Fail2ban (mungkin belum diinstall sebelumnya)"
        echo "[SKIP] Fail2ban — tidak ada backup" >> "${ROLLBACK_FILE}"
    fi

    # ── Rollback Wazuh ────────────────────────────────────────────────────────
    print_sub "Restore Wazuh ossec.conf"
    if [[ -f "${latest_backup}/wazuh_ossec_conf" ]]; then
        cp "${latest_backup}/wazuh_ossec_conf" /var/ossec/etc/ossec.conf 2>/dev/null || true
        systemctl restart wazuh-manager 2>/dev/null || true
        print_change "Wazuh ossec.conf dikembalikan"
        echo "[OK] Wazuh ossec.conf dikembalikan" >> "${ROLLBACK_FILE}"
    else
        print_info "Tidak ada backup Wazuh"
        echo "[SKIP] Wazuh — tidak ada backup" >> "${ROLLBACK_FILE}"
    fi

    echo "" >> "${ROLLBACK_FILE}"
    echo "Rollback selesai: $(date)" >> "${ROLLBACK_FILE}"

    print_ok "Rollback selesai"
    print_info "Log rollback: ${ROLLBACK_FILE}"
    R_section "ROLLBACK"
    cat "${ROLLBACK_FILE}" >> "${REPORT_FILE}" 2>/dev/null || true
}

# =============================================================================
# ── SCORING ───────────────────────────────────────────────────────────────────
# =============================================================================

add_score() {
    local key="$1" val="$2"
    # Jangan tambah dua kali untuk key yang sama
    [[ -v SCORE_ITEMS["$key"] ]] && return
    SCORE_ITEMS["$key"]="$val"
    SCORE=$((SCORE + val))
    [[ $SCORE -gt 100 ]] && SCORE=100
    _log "SCORE" "+${val} untuk ${key} → total ${SCORE}"
}

_finalize_score() {
    # Validasi kondisi real-time di akhir

    # UFW aktif di akhir eksekusi
    ufw status 2>/dev/null | grep -q "active" && add_score "firewall" 15

    # SSH hardened (pengecekan langsung)
    local cfg="/etc/ssh/sshd_config"
    if [[ -f "$cfg" ]]; then
        local rl ma
        rl=$(grep -iE "^PermitRootLogin" "$cfg" 2>/dev/null | awk '{print $2}' | tail -1 || true)
        ma=$(grep -iE "^MaxAuthTries" "$cfg" 2>/dev/null | awk '{print $2}' | tail -1 || true)
        [[ "${rl,,}" == "no" && "${ma:-6}" -le 3 ]] && add_score "ssh_hardened" 15
    fi

    # Fail2ban aktif
    service_active "fail2ban" && add_score "fail2ban" 10

    # Wazuh
    { service_active "wazuh-agent" || service_active "wazuh-manager"; } && add_score "wazuh" 10

    # Cap
    [[ $SCORE -gt 100 ]] && SCORE=100
}

_get_rating() {
    local s=$1
    if [[ $s -ge 85 ]]; then echo "A — Sangat Baik  🛡️"
    elif [[ $s -ge 70 ]]; then echo "B — Baik          ✅"
    elif [[ $s -ge 55 ]]; then echo "C — Cukup         ⚠️"
    elif [[ $s -ge 40 ]]; then echo "D — Lemah         🔶"
    else                        echo "E — Berisiko Tinggi ⛔"
    fi
}

# =============================================================================
# ── LAPORAN AKHIR ─────────────────────────────────────────────────────────────
# =============================================================================

phase_final_report() {
    _finalize_score

    local rating
    rating=$(_get_rating "$SCORE")

    print_header "LAPORAN AKHIR"

    # ── Terminal summary ──────────────────────────────────────────────────────
    echo ""
    echo -e "  ${BOLD}╔═══════════════════════════════════════╗${RESET}"
    echo -e "  ${BOLD}║        SECURITY RATING AKHIR          ║${RESET}"
    echo -e "  ${BOLD}╠═══════════════════════════════════════╣${RESET}"
    printf  "  ${BOLD}║  Score : %-3s / 100                    ║${RESET}\n" "$SCORE"
    printf  "  ${BOLD}║  Rating: %-30s║${RESET}\n" "$rating"
    echo -e "  ${BOLD}╚═══════════════════════════════════════╝${RESET}"

    echo ""
    echo -e "  ${CYAN}Komponen Skor:${RESET}"
    for key in "${!SCORE_ITEMS[@]}"; do
        printf "    ${GREEN}✓${RESET} %-25s +%s\n" "${key}" "${SCORE_ITEMS[$key]}"
    done

    echo ""
    if [[ ${#SUSPICIOUS_FINDINGS[@]} -gt 0 ]]; then
        echo -e "  ${RED}${BOLD}Temuan Mencurigakan (${#SUSPICIOUS_FINDINGS[@]}):${RESET}"
        for f in "${SUSPICIOUS_FINDINGS[@]}"; do
            echo -e "    ${RED}⚠${RESET} ${f}"
        done
    else
        echo -e "  ${GREEN}✓ Tidak ada temuan mencurigakan.${RESET}"
    fi

    echo ""
    if [[ ${#RECOMMENDATIONS[@]} -gt 0 ]]; then
        echo -e "  ${YELLOW}Rekomendasi Manual (${#RECOMMENDATIONS[@]}):${RESET}"
        for rec in "${RECOMMENDATIONS[@]}"; do
            echo -e "    → ${rec}"
        done
    fi

    echo ""
    if [[ ${#CHANGES_MADE[@]} -gt 0 ]]; then
        echo -e "  ${YELLOW}Perubahan Diterapkan (${#CHANGES_MADE[@]}):${RESET}"
        for c in "${CHANGES_MADE[@]}"; do
            echo -e "    • ${c}"
        done
    fi

    if [[ ${#INCIDENT_ACTIONS[@]} -gt 0 ]]; then
        echo ""
        echo -e "  ${MAGENTA}Aksi Insiden (${#INCIDENT_ACTIONS[@]}):${RESET}"
        for a in "${INCIDENT_ACTIONS[@]}"; do
            echo -e "    ★ ${a}"
        done
    fi

    # ── Tulis ke file laporan ─────────────────────────────────────────────────
    R_section "SECURITY RATING"
    R_line "Score       : ${SCORE}/100"
    R_line "Rating      : $(_get_rating "$SCORE")"
    R_blank
    R_line "Komponen Skor:"
    for key in "${!SCORE_ITEMS[@]}"; do
        R_line "  [+${SCORE_ITEMS[$key]}] ${key}"
    done

    R_section "TEMUAN MENCURIGAKAN"
    if [[ ${#SUSPICIOUS_FINDINGS[@]} -eq 0 ]]; then
        R_line "  Tidak ada temuan mencurigakan."
    else
        for f in "${SUSPICIOUS_FINDINGS[@]}"; do
            R_line "  [ALERT] ${f}"
        done
    fi

    R_section "PERUBAHAN YANG DIBUAT"
    if [[ ${#CHANGES_MADE[@]} -eq 0 ]]; then
        R_line "  Tidak ada perubahan (mode: ${MODE})"
    else
        for c in "${CHANGES_MADE[@]}"; do
            R_line "  • ${c}"
        done
    fi

    R_section "AKSI INSIDEN"
    if [[ ${#INCIDENT_ACTIONS[@]} -eq 0 ]]; then
        R_line "  Tidak ada aksi insiden"
    else
        for a in "${INCIDENT_ACTIONS[@]}"; do
            R_line "  ★ ${a}"
        done
    fi

    R_section "REKOMENDASI MANUAL"
    if [[ ${#RECOMMENDATIONS[@]} -eq 0 ]]; then
        R_line "  Tidak ada rekomendasi tambahan — sistem sudah baik"
    else
        local i=1
        for rec in "${RECOMMENDATIONS[@]}"; do
            R_line "  ${i}. ${rec}"
            ((i++))
        done
    fi

    R_section "FILE BACKUP"
    if [[ "$MODE" == "enforce" ]]; then
        R_line "  Direktori backup: ${BACKUP_DIR}"
        for bf in "${BACKUP_FILES[@]}"; do
            R_line "    • ${bf}"
        done
    else
        R_line "  Backup tidak dibuat (mode: ${MODE})"
    fi

    R_section "FILE OUTPUT"
    R_line "  Laporan : ${REPORT_FILE}"
    R_line "  Debug   : ${DEBUG_FILE}"
    [[ "$MODE" == "enforce" ]] && R_line "  Backup  : ${BACKUP_DIR}"
    [[ "$MODE" == "rollback" ]] && R_line "  Rollback: ${ROLLBACK_FILE}"

    R_section "PANDUAN MONITORING LANJUTAN"
    R_line "  # Pantau SSH login real-time:"
    R_line "  tail -f /var/log/auth.log | grep -E 'Failed|Invalid|Accepted'"
    R_line ""
    R_line "  # Pantau koneksi aktif setiap 5 detik:"
    R_line "  watch -n 5 \"ss -tnp | grep ESTABLISHED\""
    R_line ""
    R_line "  # Pantau file baru di direktori sensitif:"
    R_line "  watch -n 30 \"find /var/www /tmp /dev/shm -mmin -10 -type f 2>/dev/null\""
    R_line ""
    R_line "  # Cek IP yang di-ban Fail2ban:"
    R_line "  fail2ban-client status sshd"
    R_line ""
    R_line "  # Hitung IP penyerang teratas:"
    R_line "  grep 'Failed password' /var/log/auth.log | awk '{print \$11}' | sort | uniq -c | sort -rn | head -10"
    R_line ""
    R_line "  # Cek Wazuh Active Response:"
    R_line "  tail -f /var/ossec/logs/active-responses.log"

    R_blank
    R_line "════════════════════════════════════════════════════════════════════"
    R_line "  Laporan selesai: $(date)"
    R_line "  Script: linux_hardening_v${SCRIPT_VERSION}"
    R_line "  D4 Rekayasa Keamanan Siber — 2026"
    R_line "════════════════════════════════════════════════════════════════════"

    echo ""
    echo -e "  ${GREEN}${BOLD}Output disimpan:${RESET}"
    echo -e "    Laporan : ${REPORT_FILE}"
    echo -e "    Debug   : ${DEBUG_FILE}"
    [[ "$MODE" == "enforce"  ]] && echo -e "    Backup  : ${BACKUP_DIR}"
    [[ "$MODE" == "rollback" ]] && echo -e "    Rollback: ${ROLLBACK_FILE}"
    echo ""
}

# =============================================================================
# ── HELP ──────────────────────────────────────────────────────────────────────
# =============================================================================

show_help() {
    cat << HELP

${BOLD}╔══════════════════════════════════════════════════════════════════╗
║      linux_hardening_v${SCRIPT_VERSION} — Blue Team Defensive Automation      ║
╚══════════════════════════════════════════════════════════════════╝${RESET}

${BOLD}PENGGUNAAN:${RESET}
  sudo ./$(basename "$0") [MODE]

${BOLD}MODE:${RESET}
  ${CYAN}-c, --check${RESET}     Audit sistem tanpa mengubah apapun.
                  Menghasilkan laporan + security rating.

  ${CYAN}-e, --enforce${RESET}   Backup konfigurasi, lalu terapkan hardening aman:
                  SSH hardening, UFW, Fail2ban, Wazuh AR, banner,
                  auto-block IP penyerang teratas.

  ${CYAN}-r, --rollback${RESET}  Kembalikan konfigurasi dari backup terbaru.
                  Restore: sshd_config, UFW, Fail2ban, Wazuh.

  ${CYAN}-h, --help${RESET}      Tampilkan bantuan ini.

${BOLD}STRUKTUR OUTPUT:${RESET}
  ./report/laporan_[waktu].txt   — laporan lengkap
  ./debug/debug_[waktu].log      — log debug internal
  ./backup/[waktu]/              — backup konfigurasi (mode enforce)
  ./rollback/rollback_[waktu].txt — catatan rollback

${BOLD}CONTOH:${RESET}
  sudo ./$(basename "$0") --check
  sudo ./$(basename "$0") --enforce
  sudo ./$(basename "$0") --rollback

${BOLD}KEAMANAN:${RESET}
  - Tidak ada aksi destruktif tanpa backup
  - Tidak mematikan SSH secara agresif
  - PasswordAuthentication tidak diubah otomatis
  - Semua temuan hanya dilaporkan (tidak dihapus otomatis)
  - Rollback otomatis jika validasi SSH gagal
  - Tidak ada teknik ofensif, eksploitasi, atau bypass

${DIM}D4 Rekayasa Keamanan Siber 2026 — Gunakan ilmu untuk melindungi.${RESET}
HELP
}

# =============================================================================
# ── MAIN ──────────────────────────────────────────────────────────────────────
# =============================================================================

main() {
    # Parse argumen
    case "${1:-}" in
        -c|--check)    MODE="check"    ;;
        -e|--enforce)  MODE="enforce"  ;;
        -r|--rollback) MODE="rollback" ;;
        -h|--help)     show_help; exit 0 ;;
        *)
            echo -e "${RED}[ERROR] Mode tidak dikenal: '${1:-unset}'${RESET}"
            echo "Gunakan: sudo ./$(basename "$0") --help"
            exit 1
            ;;
    esac

    # Pre-flight (cek root + buat direktori + init laporan)
    preflight_check

    # Banner startup
    echo ""
    echo -e "${BOLD}${BLUE}╔══════════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${BOLD}${BLUE}║         linux_hardening_v${SCRIPT_VERSION} — Blue Team Automation           ║${RESET}"
    echo -e "${BOLD}${BLUE}╠══════════════════════════════════════════════════════════════════╣${RESET}"
    printf  "${BOLD}${BLUE}║  Mode    : %-54s║${RESET}\n" "${MODE^^}"
    printf  "${BOLD}${BLUE}║  Waktu   : %-54s║${RESET}\n" "$(date '+%Y-%m-%d %H:%M:%S')"
    printf  "${BOLD}${BLUE}║  Laporan : %-54s║${RESET}\n" "${REPORT_FILE}"
    echo -e "${BOLD}${BLUE}╚══════════════════════════════════════════════════════════════════╝${RESET}"

    if [[ "$MODE" == "rollback" ]]; then
        phase_rollback
        phase_final_report
        exit 0
    fi

    # ── Urutan eksekusi ────────────────────────────────────────────────────────
    phase_identify            # Fase 1: Identifikasi sistem
    phase_inventory           # Fase 2: Inventaris service & port
    phase_backup              # Fase 3: Backup (hanya enforce)
    phase_audit               # Fase 4: Audit defense
    phase_hardening           # Fase 5: Hardening (hanya enforce)
    phase_threat_detection    # Fase 6: Deteksi ancaman
    phase_monitoring          # Fase 7: Monitoring snapshot (hanya check)
    phase_incident_response   # Fase 8: Respons insiden (hanya enforce)
    phase_final_report        # Fase 9: Laporan akhir + scoring
}

# Jalankan
main "$@"
