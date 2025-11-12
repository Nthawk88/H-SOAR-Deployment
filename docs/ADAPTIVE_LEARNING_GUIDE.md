# Panduan Adaptive Learning H-SOAR

H-SOAR memiliki kemampuan untuk **belajar dari serangan baru** yang terdeteksi. Fitur ini memungkinkan sistem untuk:

1. ✅ Mengumpulkan events dari serangan yang terdeteksi
2. ✅ Auto-label events (benign/suspicious/malicious)
3. ✅ Retrain model dengan data baru
4. ✅ Meningkatkan akurasi deteksi seiring waktu

---

## 🎯 Cara Kerja Adaptive Learning

### Workflow:
```
1. Monitoring → Deteksi Serangan
2. Collection → Kumpulkan Events dari Serangan
3. Labeling → Auto-label atau Manual Label
4. Retraining → Update Model dengan Data Baru
5. Deployment → Gunakan Model yang Diperbarui
```

---

## 📋 Step-by-Step: Mengaktifkan Adaptive Learning

### Step 1: Aktifkan Dataset Collection

**Opsi A: Collect Events Secara Manual**

```bash
cd ~/hsoar
source venv/bin/activate

# Collect events selama 24 jam dengan auto-labeling
python run_system.py --mode collect --duration 24 --label-mode auto

# Atau collect dengan manual labeling (lebih akurat)
python run_system.py --mode collect --duration 24 --label-mode manual
```

**Opsi B: Aktifkan Collection di Config (Otomatis)**

Edit `config/hids_config.json`:

```json
{
  "dataset": {
    "collection_enabled": true,  // ← Ubah ke true
    "output_path": "data/collected_events.csv",
    "labeling_mode": "auto",     // atau "manual"
    "collection_interval": 1,
    "max_collection_duration_hours": 168
  }
}
```

### Step 2: Monitor & Collect Events dari Serangan

Saat H-SOAR mendeteksi serangan, events akan otomatis dikumpulkan:

```bash
# Monitor service logs untuk melihat deteksi
sudo journalctl -u hsoar -f | grep -i "malicious\|alert"

# Check collected events
tail -f logs/hids.log | grep -i "collected\|attack"
```

### Step 3: Merge Data Baru dengan Dataset Lama

```bash
# Gabungkan dataset lama dengan data baru
python -c "
import pandas as pd
import os

# Load dataset lama
old_df = pd.read_csv('data/training_dataset.csv') if os.path.exists('data/training_dataset.csv') else pd.DataFrame()

# Load data baru
new_df = pd.read_csv('data/collected_events.csv') if os.path.exists('data/collected_events.csv') else pd.DataFrame()

# Merge (jika ada data baru)
if not new_df.empty:
    # Convert format jika perlu
    combined_df = pd.concat([old_df, new_df], ignore_index=True)
    combined_df = combined_df.drop_duplicates()
    
    # Save
    combined_df.to_csv('data/training_dataset.csv', index=False)
    print(f'✅ Dataset updated: {len(combined_df)} total samples')
    print(f'   - Old: {len(old_df)} samples')
    print(f'   - New: {len(new_df)} samples')
else:
    print('⚠️  No new data collected yet')
"
```

### Step 4: Retrain Model dengan Data Baru

```bash
# Retrain model dengan dataset yang sudah di-update
python run_system.py --mode train --dataset data/training_dataset.csv

# Restart service untuk menggunakan model baru
sudo systemctl restart hsoar

# Verify model baru
python -c "
import pickle
with open('models/hids_classifier.pkl', 'rb') as f:
    data = pickle.load(f)
print(f'✅ Model trained: {data.get(\"is_trained\")}')
print(f'✅ Accuracy: {data.get(\"performance_metrics\", {}).get(\"accuracy\", \"N/A\")}')
"
```

---

## 🔄 Automated Retraining (Scheduled)

Untuk retraining otomatis secara berkala, buat cron job:

```bash
# Edit crontab
crontab -e

# Tambahkan untuk retrain setiap minggu
0 2 * * 0 cd /home/kali/hsoar && source venv/bin/activate && python run_system.py --mode train --dataset data/training_dataset.csv && sudo systemctl restart hsoar
```

Atau buat script:

```bash
# Create retrain script
cat > ~/hsoar/scripts/auto_retrain.sh << 'EOF'
#!/bin/bash
cd ~/hsoar
source venv/bin/activate

# Merge new data
python -c "
import pandas as pd
import os

old_df = pd.read_csv('data/training_dataset.csv') if os.path.exists('data/training_dataset.csv') else pd.DataFrame()
new_df = pd.read_csv('data/collected_events.csv') if os.path.exists('data/collected_events.csv') else pd.DataFrame()

if not new_df.empty:
    combined_df = pd.concat([old_df, new_df], ignore_index=True)
    combined_df = combined_df.drop_duplicates()
    combined_df.to_csv('data/training_dataset.csv', index=False)
    print(f'Dataset updated: {len(combined_df)} samples')
"

# Retrain
python run_system.py --mode train --dataset data/training_dataset.csv

# Restart service
sudo systemctl restart hsoar

echo "✅ Auto-retrain completed"
EOF

chmod +x ~/hsoar/scripts/auto_retrain.sh
```

---

## 📊 Monitoring Adaptive Learning

### Check Collection Status

```bash
# Check collected events
python -c "
import pandas as pd
import os

if os.path.exists('data/collected_events.csv'):
    df = pd.read_csv('data/collected_events.csv')
    print(f'✅ Collected events: {len(df)}')
    if 'label' in df.columns:
        print(f'   Label distribution:')
        print(df['label'].value_counts())
else:
    print('⚠️  No collected events yet')
"
```

### Check Model Performance Over Time

```bash
# Compare model accuracy before/after retraining
python -c "
import pickle
import os

model_path = 'models/hids_classifier.pkl'
if os.path.exists(model_path):
    with open(model_path, 'rb') as f:
        data = pickle.load(f)
    metrics = data.get('performance_metrics', {})
    print(f'Current Model Performance:')
    print(f'  Accuracy: {metrics.get(\"accuracy\", \"N/A\")}')
    print(f'  Precision: {metrics.get(\"precision\", \"N/A\")}')
    print(f'  Recall: {metrics.get(\"recall\", \"N/A\")}')
    print(f'  F1-Score: {metrics.get(\"f1_score\", \"N/A\")}')
"
```

---

## ⚙️ Advanced: Self-Learning System

H-SOAR juga memiliki **Advanced Self-Learning System** yang bisa:

1. **Extract attack patterns** dari serangan
2. **Generate signatures** baru
3. **Update feature importance** berdasarkan serangan
4. **Transfer learning** untuk adaptasi cepat

Untuk menggunakan fitur ini, perlu integrasi dengan `src/learning/advanced_self_learning.py`.

---

## 🎯 Best Practices

1. **Collect Data Secara Berkala**
   - Setiap minggu atau bulan
   - Setelah insiden keamanan
   - Setelah update sistem

2. **Review Labels Secara Manual**
   - Auto-labeling bisa salah
   - Review events yang di-label sebagai "malicious"
   - Pastikan false positives tidak masuk dataset

3. **Retrain Setelah Collection**
   - Jangan retrain terlalu sering (overfitting risk)
   - Retrain setelah cukup data baru (min 100-500 samples)
   - Backup model lama sebelum retrain

4. **Monitor Performance**
   - Track accuracy sebelum/sesudah retrain
   - Monitor false positive rate
   - Adjust thresholds jika perlu

---

## 📝 Example Workflow Lengkap

```bash
# 1. Start collection (24 jam)
python run_system.py --mode collect --duration 24 --label-mode auto

# 2. Tunggu collection selesai, lalu merge data
python -c "
import pandas as pd
old = pd.read_csv('data/training_dataset.csv')
new = pd.read_csv('data/collected_events.csv')
combined = pd.concat([old, new], ignore_index=True).drop_duplicates()
combined.to_csv('data/training_dataset.csv', index=False)
print(f'Merged: {len(combined)} samples')
"

# 3. Retrain model
python run_system.py --mode train --dataset data/training_dataset.csv

# 4. Restart service
sudo systemctl restart hsoar

# 5. Verify
sudo journalctl -u hsoar -n 20 | grep "Model status"
```

---

## ⚠️ Catatan Penting

1. **Auto-labeling tidak 100% akurat** - Review manual tetap diperlukan
2. **Retraining membutuhkan waktu** - Jangan retrain terlalu sering
3. **Backup model lama** - Selalu backup sebelum retrain
4. **Monitor false positives** - Pastikan tidak terlalu banyak false positives masuk dataset

---

## 🚀 Quick Start

Untuk mulai adaptive learning sekarang:

```bash
cd ~/hsoar
source venv/bin/activate

# 1. Collect events (background)
nohup python run_system.py --mode collect --duration 168 --label-mode auto > logs/collection.log 2>&1 &

# 2. Check status
tail -f logs/collection.log

# 3. Setelah cukup data, retrain
python run_system.py --mode train --dataset data/training_dataset.csv
sudo systemctl restart hsoar
```

---

**H-SOAR akan semakin pintar seiring waktu dengan adaptive learning!** 🧠✨

