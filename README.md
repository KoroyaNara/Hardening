# Linux Blue Team Defender / Hardening Script

Script Bash untuk audit keamanan, hardening dasar, dan deteksi indikasi kompromi (IOC) pada server Linux. Cocok dipakai saat sesi Blue Team, latihan CTF defense, atau pengecekan cepat kondisi keamanan server production.

## Fitur

- **Identifikasi sistem** — OS, IP, port SSH aktif, keberadaan web server (port 80/443), dan status Wazuh (manager/agent).
- **Backup otomatis** sebelum melakukan perubahan (`sshd_config`, konfigurasi UFW, konfigurasi Wazuh) saat mode `--apply`.
- **Audit & deteksi** (Fase 9 & 10):
  - User dengan UID 0 selain `root` (indikasi backdoor account)
  - Koneksi ke port umum reverse shell (4444, 9999, 1234, 5555, 6666)
  - Indikasi webshell di `/var/www` (`eval()`, `system()`, `shell_exec()`, `passthru()`)
  - Cronjob mencurigakan di semua user
  - Isi `authorized_keys` semua user
  - Top 5 IP dengan percobaan login gagal terbanyak
- **Hardening** (Fase 3 & 8):
  - Nonaktifkan `PermitRootLogin` di SSH
  - Inject **Active Response** (firewall-drop) dan rule deteksi Nmap ke Wazuh, jika terdeteksi
  - Setup firewall UFW (deny incoming by default, rate limit SSH, allow web & Wazuh jika relevan)
- **Rollback** — mengembalikan konfigurasi dari backup terakhir jika terjadi masalah.
- **Laporan otomatis** tersimpan di `/var/log/report_<timestamp>.txt`, lengkap dengan **security score (0–100)** dan rekomendasi Incident Response.

## Requirement

- Linux dengan Bash
- Dijalankan sebagai **root**
- Opsional: `ufw`, Wazuh (`wazuh-manager`/`wazuh-agent`) untuk fitur firewall & active response

## Instalasi

```bash
chmod +x linux-hardening-v1.0.2.sh
```

## Cara Pakai

```bash
sudo ./linux-hardening-v1.0.2.sh [MODE]
```

| Mode | Keterangan |
|---|---|
| `--audit-only` | Hanya mengecek sistem dan membuat laporan. **Tidak ada perubahan** ke sistem. |
| `--apply` | Melakukan backup, lalu menerapkan hardening dasar (SSH, firewall, Wazuh Active Response). |
| `--rollback` | Mengembalikan konfigurasi dari direktori backup terakhir (`/root/blueteam_backup_*`). |
| `--help` | Menampilkan bantuan penggunaan. |

### Contoh

```bash
# Cek kondisi keamanan server tanpa mengubah apa pun
sudo ./linux-hardening-v1.0.2.sh --audit-only

# Terapkan hardening penuh
sudo ./linux-hardening-v1.0.2.sh --apply

# Batalkan perubahan, kembalikan ke kondisi sebelumnya
sudo ./linux-hardening-v1.0.2.sh --rollback
```

## Output

- **Laporan teks**: `/var/log/report_<YYYYMMDD_HHMMSS>.txt`
- **Backup konfigurasi** (mode `--apply`): `/root/blueteam_backup_<YYYYMMDD_HHMMSS>/`

## Security Score

Skor dihitung dari 10 indikator (masing-masing bernilai 10 poin):

| Skor | Grade |
|---|---|
| ≥ 85 | A (Sangat Baik) |
| ≥ 70 | B (Baik) |
| < 70 | C / D / E (Butuh Perhatian) |

## Peringatan

- Selalu jalankan `--audit-only` terlebih dahulu sebelum `--apply` untuk melihat kondisi awal sistem.
- Script ini melakukan perubahan langsung ke konfigurasi SSH dan firewall — pastikan Anda punya akses out-of-band (console/KVM) sebelum menjalankan `--apply` di server remote, untuk berjaga-jaga jika akses SSH terputus.
- Gunakan `--rollback` segera jika terjadi masalah konektivitas setelah `--apply`.

## Lisensi

##
