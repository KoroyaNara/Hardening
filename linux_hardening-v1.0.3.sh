#!/usr/bin/env bash
# =============================================================================
#  linux_defender.sh — Linux Blue Team Defensive Automation
#  Versi  : 1.0
#  Target : Debian / Ubuntu (systemd-based)
#  Tujuan : Audit, hardening, dan monitoring defensif untuk kompetisi Blue Team
#  Penulis: Blue Team Automation Engineer
# =============================================================================
#
#  CARA PAKAI:
#    chmod +x linux_defender.sh
#    sudo ./linux_defender.sh --check     # audit tanpa ubah apapun
#    sudo ./linux_defender.sh --enforce   # terapkan hardening (buat backup dulu)
#    sudo ./linux_defender.sh --rollback  # kembalikan konfigurasi dari backup
#    sudo ./linux_defender.sh --help      # tampilkan bantuan
#
#  PERINGATAN: Jalankan sebagai root. Semua perubahan dicatat di laporan.
# =============================================================================

set -euo pipefail

# =============================================================================
# KONFIGURASI GLOBAL
# =============================================================================

SCRIPT_VERSION="1.0"
SCRIPT_NAME="linux_defender"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_DIR="/root/defender_backup/${TIMESTAMP}"
REPORT_DIR="/root/defender_reports"
REPORT_FILE="${REPORT_DIR}/report_${TIMESTAMP}.txt"
LOG_FILE="${REPORT_DIR}/debug_${TIMESTAMP}.log"

# Port berbahaya yang akan diblokir di mode enforce
DANGEROUS_PORTS="21 23 4444 9999 1234 5555 6666 8888"

# Port Wazuh
WAZUH_AGENT_PORT="1514"
WAZUH_MANAGER_PORT="55000"

# Warna output terminal
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

# Variabel scoring (diisi selama eksekusi)
SCORE=0
SCORE_MAX=100
declare -A SCORE_COMPONENTS

# Variabel untuk tracking temuan
SUSPICIOUS_FINDINGS=()
CHANGES_MADE=()
BACKUP_FILES=()
RECOMMENDATIONS=()

# Mode operasi
MODE=""

# =============================================================================
# FUNGSI UTILITAS
# =============================================================================

log() {
    # Tulis ke log file DAN terminal
    local level="$1"
    local msg="$2"
    local ts
    ts=$(date +"%H:%M:%S")
    echo "[${ts}] [${level}] ${msg}" >> "${LOG_FILE}" 2>/dev/null || true
}

print_header() {
    echo -e "\n${BOLD}${BLUE}================================================================${RESET}"
    echo -e "${BOLD}${BLUE}  $1${RESET}"
    echo -e "${BOLD}${BLUE}================================================================${RESET}"
}

print_ok() {
    echo -e "  ${GREEN}[OK]${RESET} $1"
    log "OK" "$1"
}

print_warn() {
    echo -e "  ${YELLOW}[WARN]${RESET} $1"
    log "WARN" "$1"
}

print_bad() {
    echo -e "  ${RED}[BAD]${RESET} $1"
    log "BAD" "$1"
    SUSPICIOUS_FINDINGS+=("$1")
}

print_info() {
    echo -e "  ${CYAN}[INFO]${RESET} $1"
    log "INFO" "$1"
}

print_change() {
    echo -e "  ${YELLOW}[CHANGE]${RESET} $1"
    log "CHANGE" "$1"
    CHANGES_MADE+=("$1")
}

report() {
    # Tulis ke file laporan
    echo "$1" >> "${REPORT_FILE}"
}

report_section() {
    report ""
    report "================================================================"
    report "  $1"
    report "================================================================"
}

add_recommendation() {
    RECOMMENDATIONS+=("$1")
}

confirm_action() {
    # Hanya digunakan untuk tindakan berisiko tinggi
    local prompt="$1"
    echo -e "${YELLOW}  [?] ${prompt} [y/N]: ${RESET}"
    read -r answer
    [[ "$answer" =~ ^[Yy]$ ]]
}

# =============================================================================
# PRE-CHECK: ROOT DAN PERSIAPAN DIREKTORI
# =============================================================================

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[ERROR] Script harus dijalankan sebagai root (sudo).${RESET}"
        exit 1
    fi
}

prepare_directories() {
    mkdir -p "${REPORT_DIR}" || { echo "Gagal membuat direktori laporan"; exit 1; }
    touch "${REPORT_FILE}" || { echo "Gagal membuat file laporan"; exit 1; }
    touch "${LOG_FILE}" || true

    report "================================================================"
    report "  LAPORAN KEAMANAN — linux_defender.sh v${SCRIPT_VERSION}"
    report "  Tanggal : $(date '+%Y-%m-%d %H:%M:%S')"
    report "  Mode    : ${MODE}"
    report "================================================================"
}

# =============================================================================
# FASE 1: IDENTIFIKASI SISTEM
# =============================================================================

phase_system_identification() {
    print_header "FASE 1 — IDENTIFIKASI SISTEM"
    report_section "IDENTIFIKASI SISTEM"

    # --- Hostname ---
    local hostname_val
    hostname_val=$(hostname -f 2>/dev/null || hostname)
    print_info "Hostname    : ${hostname_val}"
    report "Hostname    : ${hostname_val}"

    # --- OS & Versi ---
    local os_name="Unknown"
    local os_version="Unknown"
    if [[ -f /etc/os-release ]]; then
        os_name=$(grep -oP '(?<=^NAME=").*(?=")' /etc/os-release 2>/dev/null || grep '^NAME=' /etc/os-release | cut -d= -f2 | tr -d '"')
        os_version=$(grep -oP '(?<=^VERSION_ID=").*(?=")' /etc/os-release 2>/dev/null || grep '^VERSION_ID=' /etc/os-release | cut -d= -f2 | tr -d '"')
    fi
    print_info "OS          : ${os_name} ${os_version}"
    report "OS          : ${os_name} ${os_version}"

    # Cek Debian/Ubuntu
    if echo "${os_name}" | grep -qiE "debian|ubuntu|kali|mint"; then
        print_ok "OS berbasis Debian — didukung penuh"
        SCORE_COMPONENTS["os_detected"]=10
        SCORE=$((SCORE + 10))
    else
        print_warn "OS bukan Debian/Ubuntu — beberapa fungsi mungkin tidak optimal"
        SCORE_COMPONENTS["os_detected"]=5
        SCORE=$((SCORE + 5))
        add_recommendation "Verifikasi kompatibilitas script dengan OS ini secara manual."
    fi

    # --- Kernel ---
    local kernel
    kernel=$(uname -r)
    print_info "Kernel      : ${kernel}"
    report "Kernel      : ${kernel}"

    # --- Arsitektur ---
    local arch
    arch=$(uname -m)
    print_info "Arsitektur  : ${arch}"
    report "Arsitektur  : ${arch}"

    # --- IP Address ---
    local ip_addrs
    ip_addrs=$(ip -4 addr show 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v '^127\.' | tr '\n' ' ' || echo "N/A")
    print_info "IP Address  : ${ip_addrs}"
    report "IP Address  : ${ip_addrs}"

    # --- Virtualisasi ---
    local virt_type="Physical/Unknown"
    if command -v systemd-detect-virt &>/dev/null; then
        virt_type=$(systemd-detect-virt 2>/dev/null || echo "none")
        [[ "$virt_type" == "none" ]] && virt_type="Physical/Bare-metal"
    elif [[ -f /proc/cpuinfo ]]; then
        if grep -qi "hypervisor" /proc/cpuinfo; then
            virt_type="VM (hypervisor flag detected)"
        fi
    fi
    # Fallback: cek DMI
    if command -v dmidecode &>/dev/null 2>&1; then
        local dmi
        dmi=$(dmidecode -s system-product-name 2>/dev/null || echo "")
        if echo "$dmi" | grep -qiE "vmware|virtualbox|kvm|qemu|xen|hyper-v"; then
            virt_type="VM: ${dmi}"
        fi
    fi
    print_info "Virtualisasi: ${virt_type}"
    report "Virtualisasi: ${virt_type}"

    # --- Package Manager ---
    local pkg_manager="Unknown"
    if command -v apt &>/dev/null; then
        pkg_manager="apt (Debian/Ubuntu)"
    elif command -v dnf &>/dev/null; then
        pkg_manager="dnf (Fedora/RHEL)"
    elif command -v yum &>/dev/null; then
        pkg_manager="yum (RHEL/CentOS)"
    elif command -v pacman &>/dev/null; then
        pkg_manager="pacman (Arch)"
    fi
    print_info "Pkg Manager : ${pkg_manager}"
    report "Pkg Manager : ${pkg_manager}"

    # --- Systemd ---
    if pidof systemd &>/dev/null || [[ "$(ps -p 1 -o comm=)" == "systemd" ]]; then
        print_ok "Systemd terdeteksi"
        report "Init System : systemd"
    else
        print_warn "Systemd tidak terdeteksi — gunakan init/service secara manual"
        report "Init System : non-systemd"
        add_recommendation "Verifikasi perintah service management karena bukan systemd."
    fi

    # --- Uptime ---
    local uptime_info
    uptime_info=$(uptime -p 2>/dev/null || uptime)
    print_info "Uptime      : ${uptime_info}"
    report "Uptime      : ${uptime_info}"

    echo ""
}

# =============================================================================
# FASE 2: INVENTARIS SERVICE DAN PORT
# =============================================================================

phase_service_inventory() {
    print_header "FASE 2 — INVENTARIS SERVICE DAN PORT"
    report_section "INVENTARIS SERVICE DAN PORT"

    # --- Service aktif ---
    print_info "Service yang sedang berjalan (active):"
    report ""
    report "[Service Aktif]"

    local active_services
    if command -v systemctl &>/dev/null; then
        active_services=$(systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null | awk '{print $1}' | head -50)
        echo "${active_services}" | while read -r svc; do
            print_info "  ${svc}"
            report "  ${svc}"
        done
    else
        print_warn "systemctl tidak tersedia, gunakan service --status-all"
        service --status-all 2>/dev/null | grep '\[ + \]' | awk '{print $4}' | while read -r svc; do
            print_info "  ${svc}"
            report "  ${svc}"
        done
    fi

    # --- Port listening ---
    print_info ""
    print_info "Port yang sedang listening:"
    report ""
    report "[Port Listening]"

    local ports_output
    if command -v ss &>/dev/null; then
        ports_output=$(ss -tlnp 2>/dev/null | tail -n +2)
    elif command -v netstat &>/dev/null; then
        ports_output=$(netstat -tlnp 2>/dev/null | tail -n +3)
    else
        ports_output="N/A — ss/netstat tidak tersedia"
    fi
    echo "${ports_output}" | while IFS= read -r line; do
        print_info "  ${line}"
        report "  ${line}"
    done

    # --- Deteksi service penting ---
    print_info ""
    print_info "Deteksi service penting:"
    report ""
    report "[Deteksi Service Penting]"

    # SSH
    detect_service_port "SSH" "22" "sshd ssh"
    # HTTP
    detect_service_port "HTTP" "80" "apache2 nginx httpd"
    # HTTPS
    detect_service_port "HTTPS" "443" "apache2 nginx httpd"
    # MySQL
    detect_service_port "MySQL" "3306" "mysql mysqld mariadb"
    # PostgreSQL
    detect_service_port "PostgreSQL" "5432" "postgresql"
    # Wazuh Agent
    detect_wazuh_service
    # Firewall
    detect_firewall_service

    echo ""
}

detect_service_port() {
    local service_name="$1"
    local port="$2"
    local service_names="$3"

    local port_active=false
    local service_active=false

    # Cek port
    if ss -tlnp 2>/dev/null | grep -q ":${port} " || \
       netstat -tlnp 2>/dev/null | grep -q ":${port} "; then
        port_active=true
    fi

    # Cek service name
    for svc in $service_names; do
        if systemctl is-active "$svc" &>/dev/null 2>&1; then
            service_active=true
            break
        fi
    done

    if $port_active || $service_active; then
        print_ok "${service_name} terdeteksi (port ${port})"
        report "  [AKTIF] ${service_name} — port ${port}"
        # Tandai port untuk tidak diblokir
        eval "PORT_${service_name//-/_}_ACTIVE=true"
    else
        print_info "${service_name} tidak terdeteksi (port ${port})"
        report "  [TIDAK AKTIF] ${service_name} — port ${port}"
        eval "PORT_${service_name//-/_}_ACTIVE=false"
    fi
}

detect_wazuh_service() {
    local wazuh_agent=false
    local wazuh_manager=false

    if systemctl is-active wazuh-agent &>/dev/null 2>&1; then
        wazuh_agent=true
        print_ok "Wazuh Agent terdeteksi (aktif)"
        report "  [AKTIF] Wazuh Agent"
    fi

    if systemctl is-active wazuh-manager &>/dev/null 2>&1; then
        wazuh_manager=true
        print_ok "Wazuh Manager terdeteksi (aktif)"
        report "  [AKTIF] Wazuh Manager"
    fi

    if ! $wazuh_agent && ! $wazuh_manager; then
        print_info "Wazuh tidak terdeteksi"
        report "  [TIDAK AKTIF] Wazuh"
    fi

    export WAZUH_AGENT_ACTIVE=$wazuh_agent
    export WAZUH_MANAGER_ACTIVE=$wazuh_manager
}

detect_firewall_service() {
    if command -v ufw &>/dev/null; then
        local ufw_status
        ufw_status=$(ufw status 2>/dev/null | head -1)
        if echo "${ufw_status}" | grep -qi "active"; then
            print_ok "UFW aktif: ${ufw_status}"
            report "  [AKTIF] UFW — ${ufw_status}"
        else
            print_warn "UFW terinstall tapi tidak aktif"
            report "  [TIDAK AKTIF] UFW"
        fi
    elif command -v firewalld &>/dev/null; then
        print_info "firewalld terdeteksi (bukan UFW)"
        report "  [INFO] firewalld terdeteksi"
    elif command -v iptables &>/dev/null; then
        local ipt_rules
        ipt_rules=$(iptables -L INPUT --line-numbers 2>/dev/null | wc -l)
        print_info "iptables tersedia (${ipt_rules} rules)"
        report "  [INFO] iptables dengan ${ipt_rules} rules"
    else
        print_warn "Tidak ada firewall yang terdeteksi"
        report "  [TIDAK ADA] Firewall"
    fi
}

# =============================================================================
# FASE 3: BACKUP KONFIGURASI
# =============================================================================

phase_backup() {
    print_header "FASE 3 — BACKUP KONFIGURASI"
    report_section "BACKUP KONFIGURASI"

    if [[ "$MODE" == "check" ]]; then
        print_info "Mode check — backup dilewati"
        report "Mode check — backup tidak dibuat"
        return 0
    fi

    mkdir -p "${BACKUP_DIR}"
    print_info "Direktori backup: ${BACKUP_DIR}"
    report "Direktori backup: ${BACKUP_DIR}"

    # Daftar file/direktori yang akan dibackup
    declare -A BACKUP_TARGETS=(
        ["sshd_config"]="/etc/ssh/sshd_config"
        ["ufw_rules"]="/etc/ufw"
        ["fail2ban"]="/etc/fail2ban"
        ["wazuh_ossec"]="/var/ossec/etc/ossec.conf"
        ["wazuh_rules"]="/var/ossec/etc/rules/local_rules.xml"
        ["crontab_root"]="/var/spool/cron/crontabs/root"
        ["etc_crontab"]="/etc/crontab"
        ["passwd"]="/etc/passwd"
        ["shadow"]="/etc/shadow"
        ["group"]="/etc/group"
    )

    for key in "${!BACKUP_TARGETS[@]}"; do
        local src="${BACKUP_TARGETS[$key]}"
        local dst="${BACKUP_DIR}/${key}"

        if [[ -e "${src}" ]]; then
            if cp -rp "${src}" "${dst}" 2>/dev/null; then
                print_ok "Backup: ${src} → ${dst}"
                report "  [OK] ${src}"
                BACKUP_FILES+=("${src} → ${dst}")
            else
                print_warn "Gagal backup: ${src}"
                report "  [GAGAL] ${src}"
            fi
        else
            print_info "Tidak ada: ${src} (dilewati)"
            report "  [SKIP] ${src} — tidak ditemukan"
        fi
    done

    # Backup crontab semua user
    local cron_backup_dir="${BACKUP_DIR}/crontabs_users"
    mkdir -p "${cron_backup_dir}"
    while IFS=: read -r user _ uid _ _ home _; do
        if [[ "$uid" -ge 0 ]]; then
            local cron_content
            cron_content=$(crontab -u "$user" -l 2>/dev/null || true)
            if [[ -n "$cron_content" ]]; then
                echo "$cron_content" > "${cron_backup_dir}/${user}.cron"
                print_info "Backup crontab: ${user}"
                report "  [OK] crontab user ${user}"
            fi
        fi
    done < /etc/passwd

    # Backup UFW rules (exported)
    if command -v ufw &>/dev/null; then
        ufw status verbose > "${BACKUP_DIR}/ufw_status_verbose.txt" 2>/dev/null || true
        report "  [OK] UFW status verbose"
    fi

    # Catat timestamp backup di file metadata
    {
        echo "Backup dibuat: $(date)"
        echo "Mode saat backup: ${MODE}"
        echo "Script versi: ${SCRIPT_VERSION}"
    } > "${BACKUP_DIR}/backup_metadata.txt"

    print_ok "Backup selesai di: ${BACKUP_DIR}"
    report ""
    report "Backup selesai: ${BACKUP_DIR}"

    SCORE_COMPONENTS["backup"]=10
    SCORE=$((SCORE + 10))
    echo ""
}

# =============================================================================
# FASE 4: AUDIT DEFENSE YANG SUDAH ADA
# =============================================================================

phase_audit_defense() {
    print_header "FASE 4 — AUDIT DEFENSE YANG ADA"
    report_section "AUDIT DEFENSE"

    # --- UFW ---
    audit_ufw
    # --- Fail2ban ---
    audit_fail2ban
    # --- Wazuh ---
    audit_wazuh
    # --- SSH Konfigurasi ---
    audit_ssh_config

    echo ""
}

audit_ufw() {
    print_info "--- UFW ---"
    report ""
    report "[UFW]"

    if ! command -v ufw &>/dev/null; then
        print_warn "UFW tidak terinstall"
        report "  UFW tidak terinstall"
        add_recommendation "Install UFW: apt install ufw"
        return
    fi

    local ufw_status
    ufw_status=$(ufw status verbose 2>/dev/null)
    local ufw_state
    ufw_state=$(echo "${ufw_status}" | grep -i "^Status:" | awk '{print $2}')

    if [[ "${ufw_state,,}" == "active" ]]; then
        print_ok "UFW aktif"
        report "  Status: aktif"
        SCORE_COMPONENTS["firewall"]=15
        SCORE=$((SCORE + 15))

        # Tampilkan rules
        echo "${ufw_status}" | grep -E "^[0-9]|ALLOW|DENY|REJECT|LIMIT" | while read -r line; do
            print_info "  Rule: ${line}"
            report "  Rule: ${line}"
        done
    else
        print_bad "UFW tidak aktif — sistem tidak terlindungi firewall"
        report "  Status: TIDAK AKTIF"
        add_recommendation "Aktifkan UFW: ufw enable"
    fi
}

audit_fail2ban() {
    print_info ""
    print_info "--- Fail2ban ---"
    report ""
    report "[Fail2ban]"

    if ! command -v fail2ban-client &>/dev/null; then
        print_warn "Fail2ban tidak terinstall"
        report "  Fail2ban tidak terinstall"
        add_recommendation "Install Fail2ban: apt install fail2ban"
        return
    fi

    if systemctl is-active fail2ban &>/dev/null 2>&1; then
        print_ok "Fail2ban aktif"
        report "  Status: aktif"
        SCORE_COMPONENTS["fail2ban"]=10
        SCORE=$((SCORE + 10))

        # Status jail
        local jail_status
        jail_status=$(fail2ban-client status 2>/dev/null || echo "N/A")
        print_info "  ${jail_status}"
        report "  ${jail_status}"

        # Status sshd jail
        local sshd_jail
        sshd_jail=$(fail2ban-client status sshd 2>/dev/null || echo "sshd jail belum aktif")
        echo "${sshd_jail}" | while IFS= read -r line; do
            print_info "  ${line}"
            report "  ${line}"
        done
    else
        print_bad "Fail2ban tidak aktif"
        report "  Status: TIDAK AKTIF"
        add_recommendation "Aktifkan Fail2ban: systemctl enable --now fail2ban"
    fi
}

audit_wazuh() {
    print_info ""
    print_info "--- Wazuh ---"
    report ""
    report "[Wazuh]"

    local wazuh_found=false

    if systemctl is-active wazuh-agent &>/dev/null 2>&1; then
        print_ok "Wazuh Agent: aktif"
        report "  Wazuh Agent: aktif"
        wazuh_found=true
        SCORE_COMPONENTS["wazuh"]=10
        SCORE=$((SCORE + 10))

        # Cek log error terakhir
        if [[ -f /var/ossec/logs/ossec.log ]]; then
            local wazuh_errors
            wazuh_errors=$(tail -20 /var/ossec/logs/ossec.log 2>/dev/null | grep -i "error" | wc -l)
            if [[ "$wazuh_errors" -gt 0 ]]; then
                print_warn "Ada ${wazuh_errors} error di log Wazuh Agent (cek /var/ossec/logs/ossec.log)"
                report "  Error di log Wazuh: ${wazuh_errors} baris"
            else
                print_ok "Tidak ada error di log Wazuh Agent"
                report "  Log Wazuh: bersih"
            fi
        fi
    else
        print_info "Wazuh Agent tidak aktif/tidak terinstall"
        report "  Wazuh Agent: tidak aktif"
    fi

    if systemctl is-active wazuh-manager &>/dev/null 2>&1; then
        print_ok "Wazuh Manager: aktif"
        report "  Wazuh Manager: aktif"
        wazuh_found=true
    else
        print_info "Wazuh Manager tidak aktif/tidak terinstall"
        report "  Wazuh Manager: tidak aktif"
    fi

    if ! $wazuh_found; then
        add_recommendation "Pertimbangkan install Wazuh Agent untuk monitoring terpusat."
    fi
}

audit_ssh_config() {
    print_info ""
    print_info "--- Konfigurasi SSH ---"
    report ""
    report "[SSH Konfigurasi]"

    local sshd_config="/etc/ssh/sshd_config"

    if [[ ! -f "${sshd_config}" ]]; then
        print_warn "File sshd_config tidak ditemukan"
        report "  sshd_config tidak ditemukan"
        return
    fi

    # Helper: ambil nilai parameter SSH
    get_ssh_param() {
        local param="$1"
        grep -iE "^[[:space:]]*${param}[[:space:]]" "${sshd_config}" 2>/dev/null \
            | grep -v "^#" | awk '{print $2}' | tail -1
    }

    # PermitRootLogin
    local root_login
    root_login=$(get_ssh_param "PermitRootLogin")
    root_login="${root_login:-yes}"  # default SSH adalah yes
    if [[ "${root_login,,}" == "no" ]]; then
        print_ok "PermitRootLogin: no (aman)"
        report "  PermitRootLogin: no [OK]"
    else
        print_bad "PermitRootLogin: ${root_login} (BERISIKO — harus no)"
        report "  PermitRootLogin: ${root_login} [BERISIKO]"
        add_recommendation "Set PermitRootLogin no di /etc/ssh/sshd_config"
    fi

    # MaxAuthTries
    local max_auth
    max_auth=$(get_ssh_param "MaxAuthTries")
    max_auth="${max_auth:-6}"  # default 6
    if [[ "$max_auth" -le 3 ]]; then
        print_ok "MaxAuthTries: ${max_auth} (aman)"
        report "  MaxAuthTries: ${max_auth} [OK]"
    else
        print_warn "MaxAuthTries: ${max_auth} (sebaiknya <= 3)"
        report "  MaxAuthTries: ${max_auth} [PERLU DIPERKECIL]"
        add_recommendation "Set MaxAuthTries 3 di /etc/ssh/sshd_config"
    fi

    # X11Forwarding
    local x11
    x11=$(get_ssh_param "X11Forwarding")
    x11="${x11:-no}"
    if [[ "${x11,,}" == "no" ]]; then
        print_ok "X11Forwarding: no (aman)"
        report "  X11Forwarding: no [OK]"
    else
        print_warn "X11Forwarding: ${x11} (tidak perlu, matikan)"
        report "  X11Forwarding: ${x11} [PERLU DIMATIKAN]"
        add_recommendation "Set X11Forwarding no di /etc/ssh/sshd_config"
    fi

    # PasswordAuthentication
    local pass_auth
    pass_auth=$(get_ssh_param "PasswordAuthentication")
    pass_auth="${pass_auth:-yes}"
    if [[ "${pass_auth,,}" == "no" ]]; then
        print_ok "PasswordAuthentication: no (SSH key enforced)"
        report "  PasswordAuthentication: no [OK]"
    else
        print_warn "PasswordAuthentication: ${pass_auth} (masih aktif — pertimbangkan key-only)"
        report "  PasswordAuthentication: ${pass_auth} [INFORMASI]"
        add_recommendation "Pertimbangkan PasswordAuthentication no setelah SSH key terkonfigurasi."
    fi

    # LoginGraceTime
    local grace
    grace=$(get_ssh_param "LoginGraceTime")
    grace="${grace:-120}"
    if [[ "$grace" -le 30 ]]; then
        print_ok "LoginGraceTime: ${grace} (aman)"
        report "  LoginGraceTime: ${grace} [OK]"
    else
        print_warn "LoginGraceTime: ${grace} (sebaiknya <= 30 detik)"
        report "  LoginGraceTime: ${grace} [PERLU DIPERKECIL]"
    fi

    # UseDNS
    local usedns
    usedns=$(get_ssh_param "UseDNS")
    usedns="${usedns:-yes}"
    if [[ "${usedns,,}" == "no" ]]; then
        print_ok "UseDNS: no (performa lebih baik)"
        report "  UseDNS: no [OK]"
    else
        print_info "UseDNS: ${usedns} (sebaiknya no untuk performa)"
        report "  UseDNS: ${usedns} [INFO]"
    fi

    # Cek port SSH yang digunakan
    local ssh_port
    ssh_port=$(get_ssh_param "Port")
    ssh_port="${ssh_port:-22}"
    print_info "SSH Port: ${ssh_port}"
    report "  Port SSH: ${ssh_port}"
    export CURRENT_SSH_PORT="${ssh_port}"

    echo ""
}

# =============================================================================
# FASE 5: HARDENING AMAN
# =============================================================================

phase_hardening() {
    if [[ "$MODE" != "enforce" ]]; then
        print_info "Mode bukan enforce — hardening dilewati"
        return 0
    fi

    print_header "FASE 5 — HARDENING AMAN"
    report_section "HARDENING YANG DITERAPKAN"

    harden_ssh
    harden_ufw
    harden_fail2ban
    harden_wazuh_active_response
    create_ssh_banner

    echo ""
}

harden_ssh() {
    print_info "--- Hardening SSH ---"
    local sshd_config="/etc/ssh/sshd_config"

    if [[ ! -f "${sshd_config}" ]]; then
        print_warn "sshd_config tidak ditemukan, lewati SSH hardening"
        return
    fi

    # Fungsi helper: set atau update parameter SSH
    set_ssh_param() {
        local param="$1"
        local value="$2"
        local file="${sshd_config}"

        # Hapus baris yang ada (termasuk yang dikomentari)
        sed -i "s/^[#[:space:]]*${param}[[:space:]].*$//" "${file}" 2>/dev/null || true
        # Hapus baris kosong berlebih
        sed -i '/^[[:space:]]*$/d' "${file}" 2>/dev/null || true
        # Tambahkan setting baru
        echo "${param} ${value}" >> "${file}"
    }

    # Terapkan hardening SSH (aman)
    set_ssh_param "PermitRootLogin" "no"
    set_ssh_param "MaxAuthTries" "3"
    set_ssh_param "LoginGraceTime" "20"
    set_ssh_param "X11Forwarding" "no"
    set_ssh_param "UseDNS" "no"
    # CATATAN: PasswordAuthentication TIDAK diubah otomatis untuk keamanan
    # Banner
    set_ssh_param "Banner" "/etc/ssh/banner.txt"

    print_change "SSH: PermitRootLogin no"
    print_change "SSH: MaxAuthTries 3"
    print_change "SSH: LoginGraceTime 20"
    print_change "SSH: X11Forwarding no"
    print_change "SSH: UseDNS no"

    report "  SSH hardening diterapkan:"
    report "    PermitRootLogin no"
    report "    MaxAuthTries 3"
    report "    LoginGraceTime 20"
    report "    X11Forwarding no"
    report "    UseDNS no"

    # Validasi konfigurasi SSH
    print_info "Validasi sshd_config dengan sshd -t..."
    if sshd -t 2>/tmp/sshd_test_error; then
        print_ok "Validasi SSH berhasil — restart sshd"
        report "  Validasi SSH: OK"
        systemctl restart sshd 2>/dev/null || service ssh restart 2>/dev/null || true
        print_change "sshd di-restart"
        report "  sshd di-restart"
    else
        print_bad "Validasi SSH GAGAL — rollback otomatis dari backup"
        report "  Validasi SSH: GAGAL — rollback dilakukan"
        local error_msg
        error_msg=$(cat /tmp/sshd_test_error 2>/dev/null || echo "unknown error")
        print_bad "Error: ${error_msg}"
        report "  Error: ${error_msg}"

        # Rollback sshd_config
        if [[ -f "${BACKUP_DIR}/sshd_config" ]]; then
            cp "${BACKUP_DIR}/sshd_config" "${sshd_config}"
            print_warn "sshd_config dikembalikan dari backup"
            report "  ROLLBACK: sshd_config dikembalikan"
        fi
    fi

    SCORE_COMPONENTS["ssh"]=15
    SCORE=$((SCORE + 15))
}

harden_ufw() {
    print_info ""
    print_info "--- Hardening UFW ---"
    report ""
    report "[UFW Hardening]"

    if ! command -v ufw &>/dev/null; then
        print_info "UFW tidak terinstall — install dulu"
        apt-get install -y ufw 2>/dev/null && print_change "UFW terinstall" || {
            print_warn "Gagal install UFW"
            return
        }
    fi

    # Export rules UFW yang ada sebelum perubahan
    ufw status numbered > "${BACKUP_DIR}/ufw_rules_before_enforce.txt" 2>/dev/null || true
    report "  Rules UFW lama disimpan di: ${BACKUP_DIR}/ufw_rules_before_enforce.txt"

    # Set default policy
    ufw default deny incoming 2>/dev/null || true
    ufw default allow outgoing 2>/dev/null || true
    print_change "UFW: default deny incoming, allow outgoing"
    report "  default deny incoming"
    report "  default allow outgoing"

    # Pastikan SSH port terbuka (KRITIS — jangan sampai terkunci)
    local ssh_port="${CURRENT_SSH_PORT:-22}"
    ufw allow "${ssh_port}/tcp" 2>/dev/null || true
    print_change "UFW: allow SSH port ${ssh_port}/tcp"
    report "  allow ${ssh_port}/tcp (SSH)"

    # Rate limit SSH
    ufw limit "${ssh_port}/tcp" 2>/dev/null || true
    print_change "UFW: rate limit SSH port ${ssh_port}/tcp"
    report "  limit ${ssh_port}/tcp (SSH rate limit)"

    # HTTP — hanya jika web service terdeteksi
    if ss -tlnp 2>/dev/null | grep -q ':80 ' || systemctl is-active apache2 &>/dev/null 2>&1 || systemctl is-active nginx &>/dev/null 2>&1; then
        ufw allow 80/tcp 2>/dev/null || true
        ufw allow 443/tcp 2>/dev/null || true
        print_change "UFW: allow 80/tcp dan 443/tcp (web terdeteksi)"
        report "  allow 80/tcp (HTTP)"
        report "  allow 443/tcp (HTTPS)"
    else
        print_info "Web service tidak terdeteksi — 80/443 tidak dibuka"
        report "  80/443 tidak dibuka (web tidak terdeteksi)"
    fi

    # Wazuh ports — hanya jika Wazuh terdeteksi
    if [[ "${WAZUH_AGENT_ACTIVE:-false}" == "true" ]] || [[ "${WAZUH_MANAGER_ACTIVE:-false}" == "true" ]]; then
        ufw allow "${WAZUH_AGENT_PORT}/tcp" 2>/dev/null || true
        ufw allow "${WAZUH_MANAGER_PORT}/tcp" 2>/dev/null || true
        print_change "UFW: allow port Wazuh ${WAZUH_AGENT_PORT} dan ${WAZUH_MANAGER_PORT}"
        report "  allow ${WAZUH_AGENT_PORT}/tcp (Wazuh Agent)"
        report "  allow ${WAZUH_MANAGER_PORT}/tcp (Wazuh Manager)"
    fi

    # Blokir port berbahaya secara eksplisit
    for dport in $DANGEROUS_PORTS; do
        ufw deny "${dport}/tcp" 2>/dev/null || true
        print_change "UFW: deny port berbahaya ${dport}/tcp"
        report "  deny ${dport}/tcp"
    done

    # Aktifkan UFW
    ufw --force enable 2>/dev/null || true
    print_change "UFW diaktifkan"
    report "  UFW diaktifkan"

    # Tampilkan status akhir
    local final_status
    final_status=$(ufw status numbered 2>/dev/null || echo "N/A")
    report ""
    report "  UFW status akhir:"
    echo "${final_status}" | while IFS= read -r line; do
        report "    ${line}"
    done

    SCORE_COMPONENTS["firewall"]=15
}

harden_fail2ban() {
    print_info ""
    print_info "--- Install/Konfigurasi Fail2ban ---"
    report ""
    report "[Fail2ban Hardening]"

    # Install jika belum ada
    if ! command -v fail2ban-client &>/dev/null; then
        print_info "Install Fail2ban..."
        if apt-get install -y fail2ban 2>/dev/null; then
            print_change "Fail2ban terinstall"
            report "  Fail2ban diinstall"
        else
            print_warn "Gagal install Fail2ban"
            report "  Gagal install Fail2ban"
            return
        fi
    fi

    # Buat jail.local jika belum ada (JANGAN overwrite yang sudah ada)
    local jail_local="/etc/fail2ban/jail.local"

    if [[ -f "${jail_local}" ]]; then
        print_info "jail.local sudah ada — tidak ditimpa (backup tersedia)"
        report "  jail.local sudah ada — tidak ditimpa"
    else
        # Buat konfigurasi jail.local baru
        cat > "${jail_local}" << 'FAIL2BAN_CONFIG'
# jail.local — dibuat oleh linux_defender.sh
# JANGAN edit jail.conf langsung, edit file ini

[DEFAULT]
bantime  = 3600
findtime = 300
maxretry = 3
ignoreip = 127.0.0.1 ::1

[sshd]
enabled  = true
port     = ssh
logpath  = %(sshd_log)s
backend  = %(sshd_backend)s
maxretry = 3
bantime  = 7200

[vsftpd]
enabled  = false
port     = ftp
logpath  = /var/log/vsftpd.log
maxretry = 3

[apache-auth]
enabled  = false
port     = http,https
logpath  = /var/log/apache2/error.log
maxretry = 5
FAIL2BAN_CONFIG

        # Aktifkan apache-auth jika apache terdeteksi
        if systemctl is-active apache2 &>/dev/null 2>&1 && [[ -f /var/log/apache2/error.log ]]; then
            sed -i 's/^enabled  = false$/enabled  = true/' "${jail_local}"
            print_change "Fail2ban apache-auth jail diaktifkan"
        fi

        print_change "Fail2ban jail.local dibuat"
        report "  jail.local dibuat dengan konfigurasi default"
    fi

    # Enable dan start Fail2ban
    systemctl enable fail2ban 2>/dev/null || true
    systemctl restart fail2ban 2>/dev/null || true

    if systemctl is-active fail2ban &>/dev/null 2>&1; then
        print_ok "Fail2ban berjalan"
        report "  Fail2ban: aktif dan berjalan"
        SCORE_COMPONENTS["fail2ban"]=10
    else
        print_warn "Fail2ban gagal distart"
        report "  Fail2ban: gagal start"
    fi
}

harden_wazuh_active_response() {
    print_info ""
    print_info "--- Wazuh Active Response ---"
    report ""
    report "[Wazuh Active Response]"

    # Hanya jika Wazuh Manager aktif
    if [[ "${WAZUH_MANAGER_ACTIVE:-false}" != "true" ]]; then
        print_info "Wazuh Manager tidak aktif — active response dilewati"
        report "  Wazuh Manager tidak aktif — dilewati"
        return
    fi

    local ossec_conf="/var/ossec/etc/ossec.conf"

    if [[ ! -f "${ossec_conf}" ]]; then
        print_warn "ossec.conf tidak ditemukan"
        return
    fi

    # Cek apakah active response sudah dikonfigurasi
    if grep -q "firewall-drop" "${ossec_conf}" 2>/dev/null; then
        print_ok "Active Response sudah dikonfigurasi di ossec.conf"
        report "  Active Response sudah ada — tidak ditimpa"
        return
    fi

    # Tambahkan active response sebelum </ossec_config>
    local ar_block='  <active-response>
    <command>firewall-drop</command>
    <location>local</location>
    <rules_id>5712,5710,31151,40101</rules_id>
    <timeout>600</timeout>
  </active-response>'

    if sed -i "s|</ossec_config>|${ar_block}\n</ossec_config>|" "${ossec_conf}" 2>/dev/null; then
        print_change "Wazuh Active Response ditambahkan ke ossec.conf"
        report "  Active Response ditambahkan (rules: 5712, 5710, 31151, 40101)"

        # Tambahkan custom rule untuk nmap detection
        local local_rules="/var/ossec/etc/rules/local_rules.xml"
        if [[ -f "${local_rules}" ]] && ! grep -q "100001" "${local_rules}"; then
            # Tambahkan sebelum </group> atau di akhir
            cat >> "${local_rules}" << 'WAZUH_RULE'

<group name="nmap,scan,local">
  <rule id="100001" level="10">
    <if_sid>1002</if_sid>
    <match>nmap</match>
    <description>Nmap scan terdeteksi dari log sistem</description>
  </rule>
</group>
WAZUH_RULE
            print_change "Custom rule Wazuh (nmap detection) ditambahkan"
            report "  Custom rule nmap (ID 100001) ditambahkan"
        fi

        systemctl restart wazuh-manager 2>/dev/null || true
        print_change "Wazuh Manager di-restart"
        report "  Wazuh Manager di-restart"
    else
        print_warn "Gagal menambahkan Active Response ke ossec.conf"
        report "  Gagal menambahkan Active Response"
    fi
}

create_ssh_banner() {
    print_info ""
    print_info "--- Pasang SSH Banner ---"
    local banner_file="/etc/ssh/banner.txt"

    if [[ ! -f "${banner_file}" ]]; then
        cat > "${banner_file}" << 'BANNER'
============================================================
  SISTEM INI DIPANTAU — AKSES TIDAK SAH DILARANG
  Semua aktivitas dicatat dan dilaporkan
  Unauthorized access is prohibited and will be prosecuted
============================================================
BANNER
        print_change "SSH banner dibuat di ${banner_file}"
        report "  SSH banner dibuat"
    else
        print_info "SSH banner sudah ada — tidak ditimpa"
        report "  SSH banner sudah ada"
    fi
}

# =============================================================================
# FASE 6: DETEKSI INDIKATOR MENCURIGAKAN
# =============================================================================

phase_threat_detection() {
    print_header "FASE 6 — DETEKSI INDIKATOR MENCURIGAKAN"
    report_section "DETEKSI ANCAMAN"

    detect_uid0_users
    detect_new_users
    detect_authorized_keys
    detect_suspicious_cron
    detect_suspicious_connections
    detect_suspicious_processes
    detect_webshells
    detect_recent_auth_failures
    detect_recently_modified_files

    echo ""
}

detect_uid0_users() {
    print_info "--- User dengan UID 0 ---"
    report ""
    report "[User UID 0]"

    local uid0_users
    uid0_users=$(awk -F: '($3 == 0) {print $1}' /etc/passwd 2>/dev/null)

    while IFS= read -r u; do
        if [[ "$u" == "root" ]]; then
            print_ok "UID 0: root (normal)"
            report "  root — normal"
        else
            print_bad "UID 0 SELAIN ROOT: ${u} — SANGAT MENCURIGAKAN"
            report "  [ALERT] ${u} — UID 0 bukan root!"
        fi
    done <<< "${uid0_users}"

    local uid0_count
    uid0_count=$(echo "${uid0_users}" | grep -v "^root$" | grep -c "." || true)
    if [[ "$uid0_count" -eq 0 ]]; then
        SCORE_COMPONENTS["no_uid0"]=10
        SCORE=$((SCORE + 10))
        report "  Tidak ada user UID 0 selain root — OK"
    fi
}

detect_new_users() {
    print_info ""
    print_info "--- User dengan UID >= 1000 ---"
    report ""
    report "[User UID >= 1000]"

    awk -F: '$3 >= 1000 && $1 != "nobody" {print $1, $3, $6}' /etc/passwd 2>/dev/null | \
    while read -r uname uid home; do
        print_info "  User: ${uname} (UID: ${uid}, Home: ${home})"
        report "  User: ${uname} UID=${uid} Home=${home}"
    done
}

detect_authorized_keys() {
    print_info ""
    print_info "--- Authorized Keys ---"
    report ""
    report "[Authorized Keys]"

    while IFS=: read -r user _ _ _ _ home _; do
        local keyfile="${home}/.ssh/authorized_keys"
        if [[ -f "${keyfile}" ]]; then
            local key_count
            key_count=$(grep -c "ssh-" "${keyfile}" 2>/dev/null || echo 0)
            print_info "  ${user}: ${key_count} SSH key di ${keyfile}"
            report "  ${user}: ${key_count} key di ${keyfile}"

            # Tampilkan fingerprint (bukan kunci penuh)
            if command -v ssh-keygen &>/dev/null; then
                ssh-keygen -l -f "${keyfile}" 2>/dev/null | while IFS= read -r fp; do
                    print_info "    Fingerprint: ${fp}"
                    report "    ${fp}"
                done
            fi
        fi
    done < /etc/passwd
}

detect_suspicious_cron() {
    print_info ""
    print_info "--- Cronjob User dan System ---"
    report ""
    report "[Cronjob]"

    local suspicious_found=false

    # Cron per-user
    while IFS=: read -r user _ uid _ _ _ _; do
        local cron_content
        cron_content=$(crontab -u "${user}" -l 2>/dev/null | grep -v "^#" | grep -v "^$" || true)
        if [[ -n "${cron_content}" ]]; then
            print_info "  Crontab user ${user}:"
            echo "${cron_content}" | while IFS= read -r line; do
                # Deteksi pattern mencurigakan
                if echo "${line}" | grep -qiE "wget|curl|base64|nc |ncat|bash -i|python.*-c|/dev/tcp|/tmp/|eval|exec"; then
                    print_bad "  [ALERT] Cron mencurigakan (${user}): ${line}"
                    report "  [ALERT] Cron ${user}: ${line}"
                    suspicious_found=true
                else
                    print_info "    ${line}"
                    report "  ${user}: ${line}"
                fi
            done
        fi
    done < /etc/passwd

    # System crontab
    if [[ -f /etc/crontab ]]; then
        print_info "  /etc/crontab:"
        grep -v "^#" /etc/crontab | grep -v "^$" | while IFS= read -r line; do
            if echo "${line}" | grep -qiE "wget|curl|base64|nc |ncat|bash -i|python.*-c|/dev/tcp|/tmp/"; then
                print_bad "  [ALERT] /etc/crontab mencurigakan: ${line}"
                report "  [ALERT] /etc/crontab: ${line}"
                suspicious_found=true
            else
                print_info "    ${line}"
                report "  /etc/crontab: ${line}"
            fi
        done
    fi

    # /etc/cron.d/
    if [[ -d /etc/cron.d ]]; then
        local cronfiles
        cronfiles=$(ls /etc/cron.d/ 2>/dev/null)
        if [[ -n "$cronfiles" ]]; then
            print_info "  File di /etc/cron.d: ${cronfiles}"
            report "  /etc/cron.d/: ${cronfiles}"
        fi
    fi

    if ! $suspicious_found; then
        SCORE_COMPONENTS["clean_cron"]=5
        SCORE=$((SCORE + 5))
        report "  Tidak ada cron mencurigakan"
    fi
}

detect_suspicious_connections() {
    print_info ""
    print_info "--- Koneksi Aktif yang Mencurigakan ---"
    report ""
    report "[Koneksi Aktif]"

    local suspicious_found=false

    # Koneksi established
    local conns
    if command -v ss &>/dev/null; then
        conns=$(ss -tnp 2>/dev/null | grep ESTAB)
    elif command -v netstat &>/dev/null; then
        conns=$(netstat -antp 2>/dev/null | grep ESTABLISHED)
    else
        conns=""
    fi

    echo "${conns}" | while IFS= read -r line; do
        # Abaikan loopback dan port normal
        if echo "${line}" | grep -qv "127.0.0"; then
            # Cek port reverse shell umum
            if echo "${line}" | grep -qE ":4444|:9999|:1234|:5555|:6666|:8888|:31337"; then
                print_bad "  [ALERT] Koneksi ke port mencurigakan: ${line}"
                report "  [ALERT] ${line}"
                suspicious_found=true
            else
                print_info "  ${line}"
                report "  ${line}"
            fi
        fi
    done

    if ! $suspicious_found; then
        SCORE_COMPONENTS["clean_connections"]=10
        SCORE=$((SCORE + 10))
        print_ok "Tidak ada koneksi ke port mencurigakan"
        report "  Tidak ada koneksi ke port mencurigakan"
    fi
}

detect_suspicious_processes() {
    print_info ""
    print_info "--- Proses Mencurigakan ---"
    report ""
    report "[Proses Mencurigakan]"

    local suspicious_found=false

    # Pattern proses berbahaya
    local patterns=(
        "nc -"
        "ncat"
        "bash -i"
        "sh -i"
        "/dev/tcp"
        "python.*-c.*import"
        "perl.*-e"
        "ruby.*-e"
        "mkfifo"
        "socat"
    )

    local all_procs
    all_procs=$(ps aux 2>/dev/null)

    for pattern in "${patterns[@]}"; do
        local matches
        matches=$(echo "${all_procs}" | grep -iE "${pattern}" | grep -v "grep" || true)
        if [[ -n "${matches}" ]]; then
            print_bad "  [ALERT] Proses mencurigakan (${pattern}):"
            echo "${matches}" | while IFS= read -r m; do
                print_bad "    ${m}"
                report "  [ALERT] ${m}"
            done
            suspicious_found=true
        fi
    done

    if ! $suspicious_found; then
        print_ok "Tidak ada proses mencurigakan yang terdeteksi"
        report "  Tidak ada proses mencurigakan"
        SCORE_COMPONENTS["clean_processes"]=5
        SCORE=$((SCORE + 5))
    fi
}

detect_webshells() {
    print_info ""
    print_info "--- Deteksi Webshell ---"
    report ""
    report "[Deteksi Webshell]"

    if [[ ! -d /var/www ]]; then
        print_info "/var/www tidak ada — tidak ada web server"
        report "  /var/www tidak ditemukan — dilewati"
        SCORE_COMPONENTS["clean_webshell"]=10
        SCORE=$((SCORE + 10))
        return
    fi

    local suspicious_found=false

    # Cari file PHP yang mengandung fungsi berbahaya
    local dangerous_funcs="system|exec|passthru|shell_exec|eval\(|base64_decode|popen|proc_open|assert\("

    local suspicious_files
    suspicious_files=$(grep -rlE "${dangerous_funcs}" /var/www/ --include="*.php" 2>/dev/null || true)

    if [[ -n "${suspicious_files}" ]]; then
        print_bad "  [ALERT] File PHP mencurigakan ditemukan:"
        echo "${suspicious_files}" | while IFS= read -r f; do
            # Tampilkan cuplikan (bukan seluruh file)
            local snippet
            snippet=$(grep -nE "${dangerous_funcs}" "${f}" 2>/dev/null | head -3)
            print_bad "    File: ${f}"
            print_bad "    Cuplikan: ${snippet}"
            report "  [ALERT] Webshell: ${f}"
            report "    Cuplikan: ${snippet}"
            suspicious_found=true
        done
    fi

    # Cek file PHP yang baru dibuat dalam 2 jam terakhir
    local new_php
    new_php=$(find /var/www -name "*.php" -mmin -120 -type f 2>/dev/null || true)
    if [[ -n "${new_php}" ]]; then
        print_warn "  File PHP baru (< 2 jam):"
        echo "${new_php}" | while IFS= read -r f; do
            print_warn "    ${f}"
            report "  [INFO] PHP baru: ${f}"
        done
    fi

    if ! $suspicious_found; then
        print_ok "Tidak ada indikasi webshell"
        report "  Tidak ada webshell terdeteksi"
        SCORE_COMPONENTS["clean_webshell"]=10
        SCORE=$((SCORE + 10))
    fi
}

detect_recent_auth_failures() {
    print_info ""
    print_info "--- Login Gagal Terbaru ---"
    report ""
    report "[Auth Log]"

    local auth_log="/var/log/auth.log"
    if [[ ! -f "${auth_log}" ]]; then
        auth_log="/var/log/secure"  # RHEL/CentOS
    fi

    if [[ -f "${auth_log}" ]]; then
        # Top 10 IP yang paling banyak gagal login
        print_info "  Top IP dengan login gagal:"
        local top_ips
        top_ips=$(grep "Failed password" "${auth_log}" 2>/dev/null \
            | grep -oP '(?<=from )\d+(\.\d+){3}' \
            | sort | uniq -c | sort -rn | head -10 || true)

        if [[ -n "${top_ips}" ]]; then
            echo "${top_ips}" | while IFS= read -r line; do
                print_warn "    ${line}"
                report "    ${line}"
            done
        else
            print_info "  Tidak ada login gagal ditemukan"
            report "  Tidak ada login gagal"
        fi

        # Successful logins
        print_info "  Login berhasil:"
        local success_logins
        success_logins=$(grep -E "Accepted password|Accepted publickey" "${auth_log}" 2>/dev/null | tail -10 || true)
        if [[ -n "${success_logins}" ]]; then
            echo "${success_logins}" | while IFS= read -r line; do
                print_info "    ${line}"
                report "    ${line}"
            done
        else
            print_info "  Tidak ada login berhasil di log"
            report "  Tidak ada login berhasil di log"
        fi
    else
        print_warn "File auth.log tidak ditemukan"
        report "  auth.log tidak ditemukan"
    fi
}

detect_recently_modified_files() {
    print_info ""
    print_info "--- File yang Baru Dimodifikasi (< 1 jam) ---"
    report ""
    report "[File Baru Dimodifikasi]"

    local recent_files
    recent_files=$(find / -mmin -60 -type f 2>/dev/null \
        | grep -vE "^/proc|^/sys|^/run|^/dev|^/tmp|/var/log|/var/ossec/logs" \
        | head -30 || true)

    if [[ -n "${recent_files}" ]]; then
        echo "${recent_files}" | while IFS= read -r f; do
            # Tandai file di lokasi sensitif
            if echo "${f}" | grep -qE "^/etc|^/usr/bin|^/usr/sbin|^/bin|^/sbin|^/root"; then
                print_warn "  [SENSITIF] ${f}"
                report "  [SENSITIF] ${f}"
            else
                print_info "  ${f}"
                report "  ${f}"
            fi
        done
    else
        print_ok "Tidak ada file penting yang baru dimodifikasi"
        report "  Tidak ada file baru dimodifikasi"
    fi
}

# =============================================================================
# FASE 7: ROLLBACK
# =============================================================================

phase_rollback() {
    print_header "ROLLBACK KONFIGURASI"
    report_section "ROLLBACK"

    # Cari backup terbaru
    local latest_backup
    latest_backup=$(ls -td /root/defender_backup/*/ 2>/dev/null | head -1 || echo "")

    if [[ -z "${latest_backup}" ]]; then
        print_bad "Tidak ada backup ditemukan di /root/defender_backup/"
        report "Tidak ada backup — rollback gagal"
        exit 1
    fi

    print_info "Backup terbaru: ${latest_backup}"
    report "Rollback dari: ${latest_backup}"

    # Rollback sshd_config
    if [[ -f "${latest_backup}/sshd_config" ]]; then
        cp "${latest_backup}/sshd_config" /etc/ssh/sshd_config
        print_change "sshd_config dikembalikan"
        report "  sshd_config: dikembalikan"

        # Validasi sebelum restart
        if sshd -t 2>/dev/null; then
            systemctl restart sshd 2>/dev/null || service ssh restart 2>/dev/null || true
            print_ok "sshd di-restart setelah rollback"
            report "  sshd: di-restart"
        else
            print_bad "sshd_config dari backup tidak valid — PERIKSA MANUAL"
            report "  sshd_config dari backup: TIDAK VALID"
        fi
    fi

    # Rollback Fail2ban
    if [[ -d "${latest_backup}/fail2ban" ]]; then
        cp -rp "${latest_backup}/fail2ban" /etc/
        systemctl restart fail2ban 2>/dev/null || true
        print_change "Fail2ban dikembalikan"
        report "  fail2ban: dikembalikan"
    fi

    # Informasi UFW — tidak auto-rollback karena berisiko
    if [[ -f "${latest_backup}/ufw_rules_before_enforce.txt" ]]; then
        print_warn "Backup rules UFW ada di: ${latest_backup}/ufw_rules_before_enforce.txt"
        print_warn "Rollback UFW tidak dilakukan otomatis — verifikasi manual"
        report "  UFW: perlu rollback manual dari ${latest_backup}/ufw_rules_before_enforce.txt"
        add_recommendation "Rollback UFW manual: lihat ${latest_backup}/ufw_rules_before_enforce.txt"
    fi

    print_ok "Rollback selesai"
    report "Rollback selesai: $(date)"
    echo ""
}

# =============================================================================
# FASE 8: SCORING DAN LAPORAN AKHIR
# =============================================================================

calculate_score() {
    # Scoring sudah dihitung secara incremental
    # Pastikan tidak melebihi 100

    # Wazuh bonus jika aktif
    if [[ "${WAZUH_AGENT_ACTIVE:-false}" == "true" ]] || [[ "${WAZUH_MANAGER_ACTIVE:-false}" == "true" ]]; then
        if [[ -z "${SCORE_COMPONENTS[wazuh]:-}" ]]; then
            SCORE_COMPONENTS["wazuh"]=10
            SCORE=$((SCORE + 10))
        fi
    fi

    # SSH aman di mode check
    if [[ "$MODE" == "check" ]]; then
        local sshd_config="/etc/ssh/sshd_config"
        if [[ -f "${sshd_config}" ]]; then
            local root_login
            root_login=$(grep -iE "^PermitRootLogin" "${sshd_config}" 2>/dev/null | awk '{print $2}' | tail -1)
            if [[ "${root_login,,}" == "no" ]]; then
                if [[ -z "${SCORE_COMPONENTS[ssh]:-}" ]]; then
                    SCORE_COMPONENTS["ssh"]=15
                    SCORE=$((SCORE + 15))
                fi
            fi
        fi
    fi

    # Cap at 100
    [[ $SCORE -gt 100 ]] && SCORE=100
}

get_rating_label() {
    local score=$1
    if [[ $score -ge 85 ]]; then
        echo "A — Sangat Baik"
    elif [[ $score -ge 70 ]]; then
        echo "B — Baik"
    elif [[ $score -ge 55 ]]; then
        echo "C — Cukup"
    elif [[ $score -ge 40 ]]; then
        echo "D — Lemah"
    else
        echo "E — Berisiko Tinggi"
    fi
}

phase_final_report() {
    calculate_score

    local rating
    rating=$(get_rating_label "$SCORE")

    print_header "LAPORAN AKHIR"

    echo ""
    echo -e "  ${BOLD}Security Rating: ${SCORE}/100 — ${rating}${RESET}"
    echo ""

    # Breakdown komponen
    echo -e "  ${CYAN}Komponen Scoring:${RESET}"
    for key in "${!SCORE_COMPONENTS[@]}"; do
        echo -e "    ✓ ${key}: +${SCORE_COMPONENTS[$key]}"
    done

    echo ""
    echo -e "  ${CYAN}Temuan Mencurigakan (${#SUSPICIOUS_FINDINGS[@]} item):${RESET}"
    if [[ ${#SUSPICIOUS_FINDINGS[@]} -eq 0 ]]; then
        echo -e "  ${GREEN}  Tidak ada temuan mencurigakan.${RESET}"
    else
        for f in "${SUSPICIOUS_FINDINGS[@]}"; do
            echo -e "  ${RED}  ⚠ ${f}${RESET}"
        done
    fi

    echo ""
    echo -e "  ${CYAN}Rekomendasi Manual:${RESET}"
    for rec in "${RECOMMENDATIONS[@]}"; do
        echo -e "    → ${rec}"
    done

    echo ""
    if [[ ${#CHANGES_MADE[@]} -gt 0 ]]; then
        echo -e "  ${CYAN}Perubahan yang Dibuat (${#CHANGES_MADE[@]}):${RESET}"
        for c in "${CHANGES_MADE[@]}"; do
            echo -e "    • ${c}"
        done
    fi

    echo ""
    echo -e "  ${BOLD}File Laporan: ${REPORT_FILE}${RESET}"
    [[ "$MODE" == "enforce" ]] && echo -e "  ${BOLD}Backup: ${BACKUP_DIR}${RESET}"

    # Tulis ringkasan ke laporan
    report_section "SCORING DAN RATING"
    report "Security Score : ${SCORE}/100"
    report "Security Rating: ${rating}"
    report ""
    report "Komponen Scoring:"
    for key in "${!SCORE_COMPONENTS[@]}"; do
        report "  ${key}: +${SCORE_COMPONENTS[$key]}"
    done

    report_section "TEMUAN MENCURIGAKAN"
    if [[ ${#SUSPICIOUS_FINDINGS[@]} -eq 0 ]]; then
        report "  Tidak ada temuan mencurigakan."
    else
        for f in "${SUSPICIOUS_FINDINGS[@]}"; do
            report "  [ALERT] ${f}"
        done
    fi

    report_section "PERUBAHAN YANG DIBUAT"
    if [[ ${#CHANGES_MADE[@]} -eq 0 ]]; then
        report "  Tidak ada perubahan (mode: ${MODE})"
    else
        for c in "${CHANGES_MADE[@]}"; do
            report "  • ${c}"
        done
    fi

    report_section "REKOMENDASI MANUAL"
    for rec in "${RECOMMENDATIONS[@]}"; do
        report "  → ${rec}"
    done

    report_section "FILE BACKUP"
    if [[ ${#BACKUP_FILES[@]} -eq 0 ]]; then
        report "  Tidak ada backup (mode: ${MODE})"
    else
        for bf in "${BACKUP_FILES[@]}"; do
            report "  • ${bf}"
        done
    fi

    report ""
    report "================================================================"
    report "  Laporan dibuat: $(date)"
    report "  Script: linux_defender.sh v${SCRIPT_VERSION}"
    report "================================================================"

    echo ""
    echo -e "  ${GREEN}Laporan tersimpan di: ${REPORT_FILE}${RESET}"
    echo ""
}

# =============================================================================
# HELP
# =============================================================================

show_help() {
    cat << HELP
================================================================
  linux_defender.sh v${SCRIPT_VERSION}
  Linux Blue Team Defensive Automation
================================================================

PENGGUNAAN:
  sudo ./linux_defender.sh [MODE]

MODE:
  -c, --check     Audit tanpa mengubah sistem. Menghasilkan laporan.
  -e, --enforce   Backup lalu terapkan hardening aman.
  -r, --rollback  Kembalikan konfigurasi dari backup terakhir.
  -h, --help      Tampilkan bantuan ini.

CONTOH:
  sudo ./linux_defender.sh --check
  sudo ./linux_defender.sh --enforce
  sudo ./linux_defender.sh --rollback

OUTPUT:
  Laporan: /root/defender_reports/report_<timestamp>.txt
  Backup : /root/defender_backup/<timestamp>/

CATATAN:
  - Jalankan sebagai root.
  - Mode enforce membuat backup otomatis sebelum perubahan.
  - PasswordAuthentication SSH tidak diubah otomatis.
  - Tidak ada file, user, atau proses yang dihapus otomatis.
================================================================
HELP
}

# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

main() {
    # Parse argumen
    case "${1:-}" in
        -c|--check)   MODE="check" ;;
        -e|--enforce) MODE="enforce" ;;
        -r|--rollback) MODE="rollback" ;;
        -h|--help)    show_help; exit 0 ;;
        *)
            echo -e "${RED}[ERROR] Mode tidak dikenal: '${1:-}'${RESET}"
            echo "Gunakan: sudo ./linux_defender.sh --help"
            exit 1
            ;;
    esac

    check_root
    prepare_directories

    echo ""
    echo -e "${BOLD}${CYAN}================================================================${RESET}"
    echo -e "${BOLD}${CYAN}  linux_defender.sh v${SCRIPT_VERSION} — Mode: ${MODE^^}${RESET}"
    echo -e "${BOLD}${CYAN}  $(date '+%Y-%m-%d %H:%M:%S')${RESET}"
    echo -e "${BOLD}${CYAN}================================================================${RESET}"

    if [[ "$MODE" == "rollback" ]]; then
        phase_rollback
        phase_final_report
        exit 0
    fi

    # Urutan eksekusi utama
    phase_system_identification
    phase_service_inventory
    phase_backup           # hanya di mode enforce
    phase_audit_defense
    phase_hardening        # hanya di mode enforce
    phase_threat_detection
    phase_final_report
}

# Jalankan
main "$@"
