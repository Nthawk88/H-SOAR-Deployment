# H-SOAR Security Deployment Tutorial

Panduan ini menjelaskan langkah demi langkah untuk mengubah H-SOAR menjadi security tool yang berjalan real-time di Linux (Ubuntu Server 22.04+). Ikuti urutan setiap fase, lakukan verifikasi sebelum melanjutkan ke fase berikutnya.

> **📌 Untuk tutorial lengkap dari Windows ke Linux (termasuk transfer file), lihat: [WINDOWS_TO_LINUX_DEPLOYMENT.md](WINDOWS_TO_LINUX_DEPLOYMENT.md)**

---

## Fase 0 – Persiapan Lingkungan

**Tujuan:** Menyediakan server Linux dan memenuhi semua prasyarat dasar.

1. **Siapkan server Linux (disarankan Ubuntu Server 22.04 LTS).**
   - Minimal RAM 4 GB, CPU 2 core, storage 50 GB.
   - Akses SSH dengan hak `sudo`.
2. **Install dependensi sistem.**
   ```bash
   sudo apt update && sudo apt install -y git python3 python3-venv python3-pip auditd git-lfs fail2ban
   ```
3. **Aktifkan dan periksa auditd.**
   ```bash
   sudo systemctl enable auditd --now
   sudo systemctl status auditd
   ```
4. **Clone repository H-SOAR.**
   ```bash
   git clone <repo-url> hsoar
   cd hsoar
   ```
5. **Buat virtual environment dan install requirement.**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install --upgrade pip
   pip install -r requirements.txt
   ```
6. **Verifikasi struktur project.**
   - Pastikan direktori `config/`, `src/`, `docs/`, `data/` tersedia.

> ✅ **Checklist Fase 0:** Server siap, auditd aktif, env & dependency terpasang.

---

## Fase 1 – Konfigurasi Auditd & Git Baseline

**Tujuan:** Mengamankan file/direktori kritikal dan menyiapkan rollback.

1. **Salin rules auditd.**
   ```bash
   sudo cp config/auditd.rules /etc/audit/rules.d/hids.rules
   sudo augenrules --load
   sudo systemctl restart auditd
   ```
2. **Verifikasi rules aktif.**
   ```bash
   sudo ausearch --input-logs -k hids_fim | head
   ```
3. **Inisialisasi Git di direktori target (contoh: `/etc` dan `/var/www/html`).**
   ```bash
   sudo git init /etc
   cd /etc
   sudo git add .
   sudo git commit -m "Initial H-SOAR baseline"
   cd -

   sudo git init /var/www/html
   cd /var/www/html
   sudo git add .
   sudo git commit -m "Initial H-SOAR baseline"
   cd -
   ```
4. **Pastikan file `config/hids_config.json` mengarah ke repo Git tersebut.**
   ```json
   "git_repos": {
     "/etc": "git@localhost:/etc.git",
     "/var/www/html": "git@localhost:/var/www.git"
   }
   ```
   > Sesuaikan jika menggunakan path lain.

5. **Set hak akses.**
   - Buat user khusus monitoring (opsional):
     ```bash
     sudo useradd -m -s /bin/bash hsoar
     sudo usermod -aG sudo hsoar
     ```
   - Pastikan user memiliki akses baca ke audit log dan repo Git (gunakan `sudo` atau `sudoers` granular).

> ✅ **Checklist Fase 1:** Auditd rules aktif, Git repo baseline siap.

---

## Fase 2 – Dataset Nyata & Pelatihan Model

**Tujuan:** Mengumpulkan data real, melatih model, dan memvalidasi performa.

### 2.1 Kumpulkan Dataset

1. **Aktifkan Mode Koleksi.**
   ```bash
   source venv/bin/activate
   python run_system.py --mode collect --duration 24 --label-mode manual
   ```
   - Jalankan minimal 24 jam untuk benign.
   - Gunakan skrip `collect_training_data.sh` untuk simulasi malicious (lihat README).

2. **Label manual/auto.**
   - File hasil di `data/collected_events.csv`.
   - Tambahkan kolom `label` (`benign/suspicious/malicious`).

3. **Kombinasikan dan bersihkan.**
   ```bash
   python scripts/prepare_dataset.py --input data/collected_events.csv --output data/training_dataset.csv
   ```
   > Jika script belum ada, gunakan Pandas untuk mengonversi ke format fitur.

### 2.2 Latih Model

1. **Jalankan pelatihan.**
   ```bash
   python run_system.py --mode train --dataset data/training_dataset.csv
   ```
2. **Periksa `logs/hids.log` untuk metrik (accuracy, precision, recall).**
3. **Simpan model hasil training.**
   - Output default: `models/hids_classifier.pkl` + scaler.
   - Backup model ke storage aman.

> ✅ **Checklist Fase 2:** Dataset real tersedia, model terlatih dengan metrik yang bisa diterima.

---

## Fase 3 – Deploy Monitoring Real-Time

**Tujuan:** Menjalankan H-SOAR secara kontinu di produksi.

1. **Konfigurasi log & threshold di `config/hids_config.json`.**
   - Update `response_threshold`, `alert_cooldown_seconds`, dsb sesuai kebutuhan.
2. **Uji coba monitoring manual.**
   ```bash
   python run_system.py --mode monitor --log-level INFO
   ```
   - Lakukan serangkaian pengujian (ubah file, tambah user, dsb.)
   - Pastikan alert & rollback sesuai ekspektasi.
3. **Konfigurasi sistem service (systemd).**
   - Buat file `/etc/systemd/system/hsoar.service`:
     ```ini
     [Unit]
     Description=H-SOAR HIDS Service
     After=network.target auditd.service

     [Service]
     Type=simple
     User=hsoar
     WorkingDirectory=/opt/hsoar
     ExecStart=/opt/hsoar/venv/bin/python /opt/hsoar/run_system.py --mode monitor
     Restart=always
     RestartSec=5
     Environment=PYTHONUNBUFFERED=1

     [Install]
     WantedBy=multi-user.target
     ```
   - Reload & start service:
     ```bash
     sudo systemctl daemon-reload
     sudo systemctl enable hsoar --now
     sudo systemctl status hsoar
     ```
4. **Logging & rotasi.**
   - Pastikan `logs/` memiliki rotasi (gunakan logrotate).

> ✅ **Checklist Fase 3:** Service jalan otomatis, alert bekerja realtime.

---

## Fase 4 – Hardening & Validasi Keamanan

**Tujuan:** Memastikan alat aman dan dapat dipercaya.

1. **Least privilege.**
   - Jalankan service sebagai user non-root dengan sudo terbatas (untuk git checkout, audit log).
2. **Secure Git repo.**
   - Verifikasi permission `.git`, gunakan `chmod 700` jika perlu.
3. **Isolasi jaringan (opsional).**
   - Gunakan VLAN atau segmentasi untuk host yang dipantau.
4. **Integrasi alerting.**
   - Kirim alert ke SIEM, email, Slack, dsb. (modifikasi `src/reporting`).
5. **Backup & DR plan.**
   - Backup model (`models/`), config, dataset secara berkala.
6. **Penetration test internal.**
   - Lakukan purple-team exercise: uji false positive/negative.
7. **Compliance & logging.**
   - Pastikan log mengandung timestamp, actor, action.

> ✅ **Checklist Fase 4:** Hak akses aman, alert diintegrasi, siap audit.

---

## Fase 5 – Operasional & Continuous Improvement

1. **Monitoring rutin.**
   - Review `logs/hids.log` & `logs/monitoring_results.jsonl` harian.
2. **Retraining periodik.**
   - Jadwalkan ulang pelatihan (mis. tiap bulan) dengan data terbaru.
3. **Update model secara aman.**
   - Uji model baru di staging → deploy ke produksi.
4. **Patch management.**
   - Terapkan update OS, Python package.
5. **Dokumentasi & KPIs.**
   - Catat metrik: false positive rate, waktu respon, jumlah rollback.

---

## Referensi & Sumber Tambahan

- `README.md` – Gambaran umum dan quick start.
- `DATASET_GENERATION.md` – Rincian dataset synthetic + real.
- `collect_training_data.sh` – Skrip koleksi otomatis.
- `docs/IEEE_PAPER.md` – Metodologi & angka performa.
- Dataset publik: ADFA-LD, HIDS2019, LID-DS.

---

## Ringkasan

| Fase | Output Utama | Status |
|------|---------------|--------|
| 0 | Server Linux siap, dependency OK | ☐ |
| 1 | Auditd + Git baseline aktif | ☐ |
| 2 | Dataset real + model terlatih | ☐ |
| 3 | Monitoring realtime berjalan | ☐ |
| 4 | Hardening & validasi selesai | ☐ |
| 5 | Operasional rutin | ongoing |

Gunakan checklist ini sebagai panduan. Tandai setiap fase setelah selesai. Dokumentasikan perubahan dan temuan selama proses. Jika butuh bantuan pada langkah tertentu, rujuk bagian fase terkait atau ajukan pertanyaan lanjutan.
