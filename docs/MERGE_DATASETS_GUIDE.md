# Panduan Merge Datasets untuk H-SOAR

Panduan lengkap untuk merge LID-DS 2021 dengan CIC-IDS2017.

---

## 📋 Prerequisites

1. **LID-DS 2021** sudah di-convert → `data/training_dataset_lid2021.csv` ✅ (Sudah ada)
2. **CIC-IDS2017** perlu di-download dan di-convert

---

## 🚀 Step-by-Step: Merge LID-DS 2021 + CIC-IDS2017

### Step 1: Cek CIC-IDS2017 Dataset

```bash
cd ~/hsoar
source venv/bin/activate

# Cek apakah CIC-IDS2017 sudah ada
ls -lh data/external/cic_ids2017/MachineLearningCSV/ 2>/dev/null || echo "CIC-IDS2017 belum ada"
```

**Jika belum ada:**

#### Opsi A: Download Otomatis (jika ada koneksi internet)

```bash
cd ~/hsoar
bash scripts/download_additional_datasets.sh
# Pilih opsi 3 (CIC-IDS2017)
```

#### Opsi B: Transfer dari Windows (jika sudah download di Windows)

Jika sudah download `MachineLearningCSV.zip` di Windows:

```bash
# Di Windows (PowerShell):
# Transfer file ke Linux menggunakan scp atau copy via shared folder

# Atau jika menggunakan WSL/VM shared folder:
# Copy dari Windows ke Linux VM
```

**Lokasi yang diharapkan:**
```
data/external/cic_ids2017/MachineLearningCSV/
  ├── Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv
  ├── Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv
  ├── Friday-WorkingHours-Morning.pcap_ISCX.csv
  └── ... (file CSV lainnya)
```

---

### Step 2: Convert CIC-IDS2017

```bash
cd ~/hsoar
source venv/bin/activate

# Convert CIC-IDS2017 ke format H-SOAR
python scripts/convert_paper_dataset.py \
    data/external/cic_ids2017/MachineLearningCSV \
    data/training_dataset_cic2017.csv
```

**Expected output:**
- Dataset akan di-convert dengan label: `benign`, `malicious`, `suspicious`
- CIC-IDS2017 memiliki banyak benign samples (normal traffic)
- Proses mungkin memakan waktu beberapa menit (dataset besar)

---

### Step 3: Verify Both Datasets

```bash
# Verify LID-DS 2021
echo "=== LID-DS 2021 ==="
python -c "
import pandas as pd
df = pd.read_csv('data/training_dataset_lid2021.csv')
print(f'Samples: {len(df)}')
print(f'Labels: {df[\"label\"].value_counts().to_dict()}')
"

# Verify CIC-IDS2017
echo "=== CIC-IDS2017 ==="
python -c "
import pandas as pd
df = pd.read_csv('data/training_dataset_cic2017.csv')
print(f'Samples: {len(df)}')
print(f'Labels: {df[\"label\"].value_counts().to_dict()}')
"
```

**Expected:**
- LID-DS 2021: ~13,718 samples, 100% malicious
- CIC-IDS2017: ~10,000-50,000 samples, mix of benign/malicious/suspicious

---

### Step 4: Merge Datasets

```bash
cd ~/hsoar
source venv/bin/activate

# Merge kedua dataset
python scripts/merge_datasets.py \
    data/training_dataset_merged.csv \
    data/training_dataset_lid2021.csv \
    data/training_dataset_cic2017.csv
```

**Expected output:**
- Total samples: ~23,000-63,000 (tergantung CIC-IDS2017)
- Label distribution: Mix of benign, malicious, suspicious
- File size: ~1-3 MB

---

### Step 5: Verify Merged Dataset

```bash
# Verify merged dataset
python verify_dataset.py data/training_dataset_merged.csv
```

Atau manual:

```bash
python -c "
import pandas as pd
df = pd.read_csv('data/training_dataset_merged.csv')
print(f'Total samples: {len(df)}')
print(f'Features: {len(df.columns) - 1}')
print(f'\nLabel distribution:')
print(df['label'].value_counts())
print(f'\nPercentage:')
print(df['label'].value_counts(normalize=True) * 100)
"
```

---

### Step 6: Train Model dengan Merged Dataset

```bash
cd ~/hsoar
source venv/bin/activate

# Train dengan merged dataset
python run_system.py --mode train --dataset data/training_dataset_merged.csv
```

---

## 📊 Expected Results

### Before Merge:
- **LID-DS 2021**: 13,718 samples (100% malicious)
- **CIC-IDS2017**: ~10,000-50,000 samples (mix)

### After Merge:
- **Total**: ~23,000-63,000 samples
- **Benign**: ~30-50%
- **Malicious**: ~40-60%
- **Suspicious**: ~5-10%

---

## ⚠️ Troubleshooting

### Error: "CIC-IDS2017 not found"

**Solution:**
```bash
# Download manual
cd ~/hsoar/data/external
mkdir -p cic_ids2017
cd cic_ids2017

# Download dari browser atau wget
wget http://cicresearch.ca/MachineLearningCSV.zip

# Extract
unzip MachineLearningCSV.zip
```

### Error: "No events extracted from CIC-IDS2017"

**Solution:**
- Pastikan folder `MachineLearningCSV` berisi file CSV
- Cek format CSV dengan: `head -1 data/external/cic_ids2017/MachineLearningCSV/*.csv | head -1`

### Error: "Label mismatch" saat merge

**Solution:**
- Pastikan kedua dataset memiliki kolom `label` dengan nilai: `benign`, `malicious`, `suspicious`
- Cek dengan: `python -c "import pandas as pd; df = pd.read_csv('data/training_dataset_cic2017.csv'); print(df['label'].unique())"`

---

## 🎯 Quick Command Summary

```bash
# 1. Convert CIC-IDS2017
python scripts/convert_paper_dataset.py \
    data/external/cic_ids2017/MachineLearningCSV \
    data/training_dataset_cic2017.csv

# 2. Merge
python scripts/merge_datasets.py \
    data/training_dataset_merged.csv \
    data/training_dataset_lid2021.csv \
    data/training_dataset_cic2017.csv

# 3. Verify
python verify_dataset.py data/training_dataset_merged.csv

# 4. Train
python run_system.py --mode train --dataset data/training_dataset_merged.csv
```

---

## 📝 Notes

1. **CIC-IDS2017** adalah network-based dataset, tapi converter akan map ke host-based features
2. **LID-DS 2021** adalah host-based dataset (system calls)
3. Merge akan memberikan balance antara benign dan malicious samples
4. Model yang di-train dengan merged dataset akan lebih robust

---

## ✅ Success Criteria

Setelah merge berhasil, Anda akan memiliki:
- ✅ Dataset dengan mix of benign/malicious/suspicious
- ✅ ~20,000+ samples untuk training
- ✅ Dataset siap untuk training ML model
- ✅ Model yang lebih general dan robust

