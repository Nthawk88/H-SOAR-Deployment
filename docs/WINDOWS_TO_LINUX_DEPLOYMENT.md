# Tutorial Lengkap: Deploy H-SOAR dari Windows ke Linux

Panduan step-by-step untuk memindahkan H-SOAR dari Windows ke Linux server dan menjadikannya security tool production-ready.

---

## 📋 Daftar Isi

1. [Persiapan di Windows](#1-persiapan-di-windows)
2. [Transfer ke Linux](#2-transfer-ke-linux)
3. [Setup di Linux](#3-setup-di-linux)
4. [Download & Setup Dataset](#4-download--setup-dataset)
5. [Training Model](#5-training-model)
6. [Deploy Production](#6-deploy-production)
7. [Verifikasi & Testing](#7-verifikasi--testing)

---

## 1. Persiapan di Windows

### 1.1 Backup & Verifikasi Project

```powershell
# Buka PowerShell di folder project
cd "C:\Users\darna\OneDrive - Bina Nusantara\Documents\BINUS\Semester 5\RM\IDS-IPS AutoHealing"

# Verifikasi file penting ada
dir config, src, docs, data, models

# Buat backup (opsional tapi recommended)
Compress-Archive -Path . -DestinationPath "hsoar-backup-$(Get-Date -Format 'yyyyMMdd').zip"
```

### 1.2 Bersihkan File Tidak Perlu

```powershell
# Hapus file temporary (jika ada)
Remove-Item -Recurse -Force __pycache__ -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force *.pyc -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force .pytest_cache -ErrorAction SilentlyContinue

# Hapus virtual environment Windows (akan dibuat ulang di Linux)
Remove-Item -Recurse -Force venv -ErrorAction SilentlyContinue
```

### 1.3 Buat File .gitignore (jika belum ada)

```powershell
# Buat .gitignore
@"
__pycache__/
*.pyc
*.pyo
*.pyd
.Python
venv/
env/
*.log
*.db
*.pkl
data/training_dataset.csv
backups/
.DS_Store
"@ | Out-File -FilePath .gitignore -Encoding utf8
```

### 1.4 Siapkan untuk Transfer

**Opsi A: Git Repository (Recommended)**
```powershell
# Inisialisasi Git (jika belum)
git init
git add .
git commit -m "Initial H-SOAR deployment version"

# Push ke GitHub/GitLab (buat repo dulu di web)
git remote add origin https://github.com/username/hsoar.git
git push -u origin main
```

**Opsi B: Zip File**
```powershell
# Buat zip file
Compress-Archive -Path . -DestinationPath "hsoar-deployment.zip" -Exclude "*.log","*.db","venv","__pycache__"
```

---

## 2. Transfer ke Linux

### 2.1 Persiapan Server Linux

**Pastikan kamu punya:**
- Ubuntu Server 22.04 LTS (atau Debian 11+)
- Akses SSH dengan user yang punya sudo
- Koneksi internet stabil
- Minimal 10GB storage kosong

**Login ke Linux:**
```bash
ssh username@your-linux-server-ip
```

### 2.2 Transfer File

**Metode A: Git Clone (Paling Mudah)**
```bash
# Install Git (jika belum)
sudo apt update
sudo apt install -y git

# Clone repository
cd /opt  # atau /home/username
sudo git clone https://github.com/username/hsoar.git
sudo chown -R $USER:$USER hsoar
cd hsoar
```

**Metode B: SCP dari Windows**
```powershell
# Di Windows PowerShell
scp -r "C:\Users\darna\OneDrive - Bina Nusantara\Documents\BINUS\Semester 5\RM\IDS-IPS AutoHealing\*" username@server-ip:/opt/hsoar/
```

**Metode C: Upload via WinSCP/FileZilla**
- Download WinSCP: https://winscp.net
- Connect ke server Linux
- Drag & drop folder ke `/opt/hsoar/`

**Metode D: Zip + Upload**
```powershell
# Di Windows: Upload zip
scp hsoar-deployment.zip username@server-ip:/tmp/
```

```bash
# Di Linux: Extract
cd /opt
sudo mkdir hsoar
sudo unzip /tmp/hsoar-deployment.zip -d hsoar
sudo chown -R $USER:$USER hsoar
cd hsoar
```

### 2.3 Verifikasi File Terkirim

```bash
# Cek struktur folder
ls -la
tree -L 2  # atau: find . -maxdepth 2 -type d

# Pastikan file penting ada
ls config/ src/ docs/ data/
```

---

## 3. Setup di Linux

### 3.1 Install Dependencies Sistem

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Python & tools
sudo apt install -y python3 python3-venv python3-pip git build-essential

# Install auditd (penting untuk HIDS)
sudo apt install -y auditd audispd-plugins

# Install tools pendukung
sudo apt install -y curl wget unzip tree htop
```

### 3.2 Setup Python Environment

```bash
# Masuk ke folder project
cd /opt/hsoar  # atau path kamu

# Buat virtual environment
python3 -m venv venv

# Aktifkan virtual environment
source venv/bin/activate

# Upgrade pip
pip install --upgrade pip

# Install dependencies
pip install -r requirements.txt

# Verifikasi install
python --version
pip list | grep -E "pandas|numpy|scikit-learn"
```

### 3.3 Setup Auditd

```bash
# Cek auditd status
sudo systemctl status auditd

# Jika belum aktif, enable
sudo systemctl enable auditd
sudo systemctl start auditd

# Verifikasi
sudo auditctl -l
```

### 3.4 Setup Auditd Rules

```bash
# Copy rules dari config
sudo cp config/auditd.rules /etc/audit/rules.d/hids.rules

# Atau buat manual jika file tidak ada
sudo tee /etc/audit/rules.d/hids.rules > /dev/null <<EOF
# H-SOAR HIDS File Integrity Monitoring Rules
-w /etc -p wa -k hids_fim
-w /bin -p wa -k hids_fim
-w /sbin -p wa -k hids_fim
-w /usr/bin -p wa -k hids_fim
-w /var/www/html -p wa -k hids_fim

# Monitor process execution
-a always,exit -F arch=b64 -S execve -k hids_process
-a always,exit -F arch=b32 -S execve -k hids_process

# Monitor file attribute changes
-a always,exit -F arch=b64 -S chmod -k hids_attr
-a always,exit -F arch=b64 -S chown -k hids_attr

# Monitor network connections
-a always,exit -F arch=b64 -S bind -k hids_network
-a always,exit -F arch=b64 -S connect -k hids_network

# Monitor privilege escalation
-a always,exit -F arch=b64 -S setuid -k hids_priv
-a always,exit -F arch=b64 -S setgid -k hids_priv
EOF

# Load rules
sudo augenrules --load

# Restart auditd
sudo systemctl restart auditd

# Verifikasi rules aktif
sudo ausearch --input-logs -k hids_fim | head -5
```

### 3.5 Setup Git Repositories untuk Rollback

```bash
# Buat direktori untuk Git repos (jika belum ada)
sudo mkdir -p /var/www/html

# Initialize Git di /etc (HATI-HATI: ini akan track semua file /etc)
cd /etc
sudo git init
sudo git config user.name "H-SOAR System"
sudo git config user.email "hsoar@localhost"
sudo git add .
sudo git commit -m "Initial H-SOAR baseline - $(date +%Y%m%d)"

# Initialize Git di /var/www/html
cd /var/www/html
sudo git init
sudo git config user.name "H-SOAR System"
sudo git config user.email "hsoar@localhost"
sudo git add .
sudo git commit -m "Initial H-SOAR baseline - $(date +%Y%m%d)"

# Kembali ke project folder
cd /opt/hsoar
```

### 3.6 Test Basic Functionality

```bash
# Aktifkan venv
source venv/bin/activate

# Test import
python -c "import pandas, numpy, sklearn; print('Dependencies OK')"

# Test system status
python run_system.py --mode status

# Test dataset generator (jika ada)
python generate_dataset.py --samples 100 --output data/test_dataset.csv
```

---

## 4. Download & Setup Dataset

### 4.1 Pilihan Dataset

**Rekomendasi: HIDS2019 Dataset**

### 4.2 Download HIDS2019 Dataset

```bash
# Buat folder untuk dataset
mkdir -p data/external
cd data/external

# Clone HIDS2019 dataset
git clone https://github.com/linxiaotian/HIDS2019-dataset.git

# Atau download zip
# wget https://github.com/linxiaotian/HIDS2019-dataset/archive/refs/heads/main.zip
# unzip main.zip

cd ../../  # kembali ke root project
```

### 4.3 Convert Dataset ke Format H-SOAR

Buat script converter:

```bash
# Buat folder scripts jika belum ada
mkdir -p scripts
```

Buat file `scripts/convert_hids2019.py`:

```python
#!/usr/bin/env python3
"""
Convert HIDS2019 dataset to H-SOAR format
"""
import pandas as pd
import numpy as np
import os
import sys
from pathlib import Path

def convert_hids2019(input_dir, output_file):
    """Convert HIDS2019 dataset to H-SOAR training format"""
    
    print(f"Loading HIDS2019 dataset from {input_dir}...")
    
    # Load CSV files from HIDS2019
    csv_files = list(Path(input_dir).glob("*.csv"))
    
    if not csv_files:
        print(f"Error: No CSV files found in {input_dir}")
        return False
    
    all_data = []
    
    for csv_file in csv_files:
        try:
            df = pd.read_csv(csv_file)
            print(f"Loaded {csv_file.name}: {len(df)} rows")
            all_data.append(df)
        except Exception as e:
            print(f"Warning: Could not load {csv_file.name}: {e}")
    
    if not all_data:
        print("Error: No data loaded")
        return False
    
    # Combine all data
    combined_df = pd.concat(all_data, ignore_index=True)
    print(f"Total rows: {len(combined_df)}")
    
    # Map HIDS2019 columns to H-SOAR features
    # Adjust column names based on actual HIDS2019 format
    feature_mapping = {
        # Event features
        'event_type': 'event_type',  # or map from HIDS2019 column
        'action': 'action',  # or map from HIDS2019 column
        
        # File path features
        'filepath': 'filepath',  # adjust based on actual column name
        'filepath_criticality': None,  # calculate from filepath
        'filepath_depth': None,  # calculate from filepath
        'filepath_suspicious': None,  # calculate from filepath
        'file_extension_suspicious': None,  # calculate from filepath
        
        # Process features
        'process': 'process',  # or 'comm', 'exe'
        'process_suspicious': None,  # calculate from process
        'process_is_shell': None,  # calculate from process
        'process_is_web_server': None,  # calculate from process
        'process_is_system': None,  # calculate from process
        'process_name_length': None,  # calculate from process
        
        # User features
        'user': 'uid',  # or 'user', 'auid'
        'user_is_root': None,  # calculate from user
        'user_is_system': None,  # calculate from user
        'user_is_web': None,  # calculate from user
        
        # Action features
        'action_is_write': None,  # calculate from action
        'action_is_delete': None,  # calculate from action
        'action_is_execute': None,  # calculate from action
        'action_is_attribute': None,  # calculate from action
        
        # Temporal features
        'hour_of_day': None,  # extract from timestamp
        'day_of_week': None,  # extract from timestamp
        
        # Label
        'label': 'label'  # or 'class', 'type'
    }
    
    # Create H-SOAR format dataframe
    hsoar_features = []
    
    for idx, row in combined_df.iterrows():
        if idx % 1000 == 0:
            print(f"Processing row {idx}/{len(combined_df)}")
        
        features = {}
        
        # Extract features (implement based on actual HIDS2019 format)
        # This is a template - adjust based on actual dataset structure
        
        # File path criticality
        filepath = str(row.get('filepath', ''))
        features['filepath_criticality'] = calculate_criticality(filepath)
        features['filepath_depth'] = len(Path(filepath).parts) if filepath else 0
        features['filepath_suspicious'] = 1 if any(p in filepath.lower() for p in 
            ['backdoor', 'shell', 'trojan', 'exploit']) else 0
        features['file_extension_suspicious'] = 1 if filepath.endswith(('.php', '.sh', '.py')) else 0
        
        # Process features
        process = str(row.get('process', ''))
        features['process_suspicious'] = 1 if any(p in process.lower() for p in 
            ['nc', 'bash', 'python', 'perl']) else 0
        features['process_is_shell'] = 1 if any(s in process.lower() for s in ['bash', 'sh']) else 0
        features['process_name_length'] = len(process)
        
        # User features
        user = str(row.get('user', ''))
        features['user_is_root'] = 1 if user == '0' or user == 'root' else 0
        
        # Action features
        action = str(row.get('action', ''))
        features['action_is_write'] = 1 if action in ['write', 'create'] else 0
        features['action_is_execute'] = 1 if action == 'execute' else 0
        
        # Temporal (placeholder)
        features['hour_of_day'] = 12
        features['day_of_week'] = 1
        
        # Label
        features['label'] = row.get('label', 'benign')
        
        hsoar_features.append(features)
    
    # Create DataFrame
    hsoar_df = pd.DataFrame(hsoar_features)
    
    # Save
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    hsoar_df.to_csv(output_file, index=False)
    
    print(f"\n✅ Dataset converted and saved to: {output_file}")
    print(f"Total samples: {len(hsoar_df)}")
    print(f"Label distribution:\n{hsoar_df['label'].value_counts()}")
    
    return True

def calculate_criticality(filepath):
    """Calculate file path criticality score"""
    if '/etc/passwd' in filepath or '/etc/shadow' in filepath:
        return 10
    elif '/etc/' in filepath:
        return 7
    elif '/bin/' in filepath or '/sbin/' in filepath:
        return 8
    elif '/var/www/' in filepath:
        return 4
    elif '/tmp/' in filepath:
        return 1
    else:
        return 3

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python convert_hids2019.py <input_dir> <output_file>")
        print("Example: python convert_hids2019.py data/external/HIDS2019-dataset/csv data/training_dataset.csv")
        sys.exit(1)
    
    input_dir = sys.argv[1]
    output_file = sys.argv[2]
    
    convert_hids2019(input_dir, output_file)
```

**Atau gunakan dataset synthetic (lebih cepat untuk testing):**

```bash
# Generate synthetic dataset (10,000 samples)
source venv/bin/activate
python generate_dataset.py --samples 10000 --output data/training_dataset.csv
```

---

## 5. Training Model

### 5.1 Prepare Dataset

```bash
# Aktifkan venv
source venv/bin/activate

# Jika menggunakan HIDS2019, convert dulu
python scripts/convert_hids2019.py data/external/HIDS2019-dataset/csv data/training_dataset.csv

# Atau gunakan synthetic dataset
python generate_dataset.py --samples 10000 --output data/training_dataset.csv

# Verify dataset
python verify_dataset.py
```

### 5.2 Train ML Model

```bash
# Train model
python run_system.py --mode train --dataset data/training_dataset.csv

# Check training results
tail -50 logs/hids.log

# Verify model saved
ls -lh models/hids_classifier.pkl
```

### 5.3 Test Model

```bash
# Test system
python run_system.py --mode test

# Check status
python run_system.py --mode status
```

---

## 6. Deploy Production

### 6.1 Create Systemd Service

```bash
# Buat service file
sudo tee /etc/systemd/system/hsoar.service > /dev/null <<EOF
[Unit]
Description=H-SOAR Host-based Intrusion Detection System
After=network.target auditd.service
Requires=auditd.service

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/opt/hsoar
Environment="PATH=/opt/hsoar/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ExecStart=/opt/hsoar/venv/bin/python /opt/hsoar/run_system.py --mode monitor
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd
sudo systemctl daemon-reload

# Enable service
sudo systemctl enable hsoar

# Start service
sudo systemctl start hsoar

# Check status
sudo systemctl status hsoar
```

### 6.2 Setup Log Rotation

```bash
# Buat logrotate config
sudo tee /etc/logrotate.d/hsoar > /dev/null <<EOF
/opt/hsoar/logs/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0644 root root
}
EOF
```

### 6.3 Monitor Service

```bash
# Check service status
sudo systemctl status hsoar

# View logs
sudo journalctl -u hsoar -f

# View application logs
tail -f /opt/hsoar/logs/hids.log
```

---

## 7. Verifikasi & Testing

### 7.1 Test File Monitoring

```bash
# Test: Modify critical file
sudo touch /etc/test_hsoar.txt
sudo rm /etc/test_hsoar.txt

# Check if detected
sudo ausearch -k hids_fim --start recent | grep test_hsoar
tail -20 /opt/hsoar/logs/hids.log
```

### 7.2 Test Alert System

```bash
# Simulate malicious activity
sudo echo "test" >> /etc/passwd
sudo git -C /etc checkout HEAD -- passwd  # Rollback

# Check alerts
tail -50 /opt/hsoar/logs/hids.log | grep -i "malicious\|alert"
```

### 7.3 Performance Check

```bash
# Check resource usage
htop
# atau
top -p $(pgrep -f "run_system.py")

# Check disk usage
df -h
du -sh /opt/hsoar/*
```

### 7.4 Final Verification Checklist

```bash
# ✅ Service running
sudo systemctl is-active hsoar

# ✅ Auditd active
sudo systemctl is-active auditd

# ✅ Model trained
ls -lh models/hids_classifier.pkl

# ✅ Logs being written
tail -5 logs/hids.log

# ✅ Git repos initialized
sudo git -C /etc log --oneline | head -1
sudo git -C /var/www/html log --oneline | head -1
```

---

## 🎉 Selesai!

H-SOAR sekarang berjalan sebagai security tool production-ready di Linux!

### Next Steps:

1. **Monitor logs** secara rutin: `tail -f logs/hids.log`
2. **Review alerts** setiap hari
3. **Retrain model** secara berkala (bulanan) dengan data baru
4. **Update system** dan dependencies secara rutin
5. **Backup** models dan config secara berkala

### Troubleshooting:

- **Service tidak start**: Check `sudo journalctl -u hsoar -n 50`
- **No alerts**: Verify auditd rules dengan `sudo ausearch -k hids_fim`
- **Model error**: Retrain dengan `python run_system.py --mode train`

---

**Selamat! H-SOAR siap melindungi sistem Linux Anda! 🛡️**

