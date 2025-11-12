# 🚀 Quick Start: Deploy H-SOAR ke Linux

Panduan cepat untuk deploy H-SOAR dari Windows ke Linux server.

---

## ⚡ Quick Steps

### 1. Transfer dari Windows ke Linux

**Opsi A: Git (Recommended)**
```bash
# Di Windows: Push ke GitHub
git init
git add .
git commit -m "H-SOAR deployment"
git remote add origin https://github.com/username/hsoar.git
git push -u origin main

# Di Linux: Clone
cd /opt
sudo git clone https://github.com/username/hsoar.git
sudo chown -R $USER:$USER hsoar
cd hsoar
```

**Opsi B: SCP**
```powershell
# Di Windows PowerShell
scp -r "C:\path\to\hsoar\*" username@server-ip:/opt/hsoar/
```

**Opsi C: Zip + Upload**
```powershell
# Di Windows: Buat zip
Compress-Archive -Path . -DestinationPath hsoar.zip

# Upload via WinSCP/FileZilla ke /tmp/hsoar.zip
# Di Linux: Extract
cd /opt && sudo unzip /tmp/hsoar.zip -d hsoar
```

### 2. Setup di Linux

```bash
# Install dependencies
sudo apt update && sudo apt install -y python3 python3-venv python3-pip auditd git

# Setup Python
cd /opt/hsoar
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Setup auditd
sudo cp config/auditd.rules /etc/audit/rules.d/hids.rules
sudo augenrules --load
sudo systemctl restart auditd
```

### 3. Download Dataset

```bash
# Opsi A: HIDS2019 (Real dataset)
cd data/external
git clone https://github.com/linxiaotian/HIDS2019-dataset.git
cd ../..
python scripts/convert_hids2019.py data/external/HIDS2019-dataset/csv data/training_dataset.csv

# Opsi B: Synthetic (Quick testing)
python generate_dataset.py --samples 10000 --output data/training_dataset.csv
```

### 4. Train Model

```bash
source venv/bin/activate
python run_system.py --mode train --dataset data/training_dataset.csv
```

### 5. Deploy Service

```bash
# Create systemd service
sudo tee /etc/systemd/system/hsoar.service > /dev/null <<EOF
[Unit]
Description=H-SOAR HIDS
After=auditd.service

[Service]
Type=simple
WorkingDirectory=/opt/hsoar
ExecStart=/opt/hsoar/venv/bin/python /opt/hsoar/run_system.py --mode monitor
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# Start service
sudo systemctl daemon-reload
sudo systemctl enable hsoar
sudo systemctl start hsoar
sudo systemctl status hsoar
```

---

## 📖 Full Tutorial

Untuk tutorial lengkap dengan detail setiap langkah, lihat:
- **[WINDOWS_TO_LINUX_DEPLOYMENT.md](docs/WINDOWS_TO_LINUX_DEPLOYMENT.md)** - Tutorial lengkap step-by-step
- **[SECURITY_DEPLOYMENT_TUTORIAL.md](docs/SECURITY_DEPLOYMENT_TUTORIAL.md)** - Security deployment guide

---

## ✅ Verification

```bash
# Check service
sudo systemctl status hsoar

# Check logs
tail -f logs/hids.log

# Test detection
sudo touch /etc/test_file.txt
sudo rm /etc/test_file.txt
tail -20 logs/hids.log
```

---

## 🆘 Troubleshooting

**Service tidak start:**
```bash
sudo journalctl -u hsoar -n 50
```

**No alerts:**
```bash
sudo ausearch -k hids_fim | head
```

**Model error:**
```bash
python run_system.py --mode train --dataset data/training_dataset.csv
```

---

**Selamat! H-SOAR siap melindungi sistem Linux Anda! 🛡️**

