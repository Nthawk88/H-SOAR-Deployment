# Guide: Download & Convert Paper Datasets untuk H-SOAR

Panduan untuk download dan convert dataset dari paper-paper penelitian yang sudah digunakan untuk HIDS.

---

## 📚 Dataset yang Tersedia

### 0. **ADFA-LD** (Easiest - GitHub) ⭐ Quick Start

**Paper:** Creech & Hu, "A Semantic Approach to Host-based Intrusion Detection Systems using Contiguous and Discontinuous System Call Patterns", IEEE TIFS, 2014

**Download:**
- **URL:** https://github.com/verazuo/a-labelled-version-of-the-ADFA-LD-dataset
- **Size:** ~100-200MB
- **Format:** System call traces
- **Keuntungan:** Direct download dari GitHub, tidak perlu registrasi

**Cara Download:**
```bash
cd ~/hsoar/data/external
git clone https://github.com/verazuo/a-labelled-version-of-the-ADFA-LD-dataset.git
cd a-labelled-version-of-the-ADFA-LD-dataset
unzip ADFA-LD.zip
cd ../../..
```

**Convert:**
```bash
python scripts/convert_paper_dataset.py data/external/a-labelled-version-of-the-ADFA-LD-dataset/ADFA-LD data/training_dataset.csv
```

---

### 1. **LID-DS 2021** (Recommended - Direct Download)

**Paper:** Martinez-Torres et al., "LID-DS: A Linux Intrusion Detection Dataset", Future Generation Computer Systems, 2022

**Download:**
- **URL:** https://zenodo.org/record/5773804
- **Size:** ~500MB-1GB
- **Format:** Auditd logs dengan berbagai attack scenarios
- **Keuntungan:** Direct download, tidak perlu registrasi

**Cara Download:**
```bash
cd ~/hsoar
source venv/bin/activate

# Download via script
bash scripts/download_paper_datasets.sh
# Pilih opsi 1 (LID-DS 2021)

# Atau manual download
cd data/external
wget https://zenodo.org/record/5773804/files/lid_ds.zip
unzip lid_ds.zip
cd ../..
```

**Convert:**
```bash
python scripts/convert_paper_dataset.py data/external/lid_ds data/training_dataset.csv
```

---

### 2. **ADFA-LD** (UNSW Canberra)

**Paper:** Creech & Hu, "A Semantic Approach to Host-based Intrusion Detection Systems using Contiguous and Discontinuous System Call Patterns", IEEE TIFS, 2014

**Download:**
- **URL:** https://www.unsw.adfa.edu.au/unsw-canberra-cyber/cybersecurity/ADFA-LD
- **Size:** ~100-200MB
- **Format:** System call traces
- **Catatan:** Perlu registrasi (gratis)

**Cara Download:**
1. Visit: https://www.unsw.adfa.edu.au/unsw-canberra-cyber/cybersecurity/ADFA-LD
2. Register (gratis)
3. Download dataset
4. Extract ke: `data/external/ADFA-LD/`

**Convert:**
```bash
python scripts/convert_paper_dataset.py data/external/ADFA-LD data/training_dataset.csv
```

---

## 🚀 Quick Start

### Step 1: Download Dataset

**Opsi A: LID-DS 2021 (Paling Mudah)**
```bash
cd ~/hsoar
source venv/bin/activate

# Download
cd data/external
wget https://zenodo.org/record/5773804/files/lid_ds.zip
unzip lid_ds.zip
cd ../..
```

**Opsi B: ADFA-LD**
- Download manual dari website UNSW
- Extract ke `data/external/ADFA-LD/`

### Step 2: Convert Dataset

```bash
# Untuk LID-DS 2021
python scripts/convert_paper_dataset.py data/external/lid_ds data/training_dataset.csv

# Untuk ADFA-LD
python scripts/convert_paper_dataset.py data/external/ADFA-LD data/training_dataset.csv
```

### Step 3: Verify Dataset

```bash
python verify_dataset.py
```

### Step 4: Train Model

```bash
python run_system.py --mode train --dataset data/training_dataset.csv
```

---

## 📊 Dataset Comparison

| Dataset | Size | Format | Download | Label Quality |
|---------|------|--------|---------|---------------|
| **LID-DS 2021** | ~500MB-1GB | Auditd logs | Direct | Excellent |
| **ADFA-LD** | ~100-200MB | Syscall traces | Registration | Good |
| **Synthetic** | ~0.5MB | Generated | Instant | Good (for testing) |

---

## 🔍 Dataset Details

### LID-DS 2021 Structure
```
lid_ds/
├── scenario1/
│   ├── audit.log
│   └── ...
├── scenario2/
│   └── ...
└── ...
```

### ADFA-LD Structure
```
ADFA-LD/
├── Training_Data_Master/
│   ├── UADTrain*.txt
│   └── ...
├── Attack_Data_Master/
│   ├── UADAttack*.txt
│   └── ...
└── Validation_Data_Master/
    └── ...
```

---

## ⚠️ Troubleshooting

### Dataset tidak ditemukan
```bash
# Cek apakah dataset sudah di-download
ls -la data/external/

# Cek struktur dataset
tree data/external/ -L 2
```

### Convert error
```bash
# Cek log error
python scripts/convert_paper_dataset.py data/external/lid_ds data/training_dataset.csv 2>&1 | tee convert.log

# Pastikan dataset format benar
head -20 data/external/lid_ds/*/audit.log
```

### Dataset terlalu besar
```bash
# Limit jumlah events yang di-convert (edit script)
# Atau gunakan subset dataset
```

---

## 📝 Notes

1. **LID-DS 2021** recommended untuk production karena:
   - Format auditd langsung (realistic)
   - Berbagai attack scenarios
   - Label quality tinggi

2. **ADFA-LD** bagus untuk:
   - Baseline comparison
   - System call analysis
   - Research purposes

3. **Synthetic dataset** tetap berguna untuk:
   - Quick testing
   - Development
   - Proof of concept

---

## 📚 References

- **ADFA-LD:** Creech & Hu, "A Semantic Approach to Host-based Intrusion Detection Systems using Contiguous and Discontinuous System Call Patterns", IEEE Transactions on Information Forensics and Security, 2014. DOI: 10.1109/TIFS.2014.2312812
- **LID-DS 2021:** Martinez-Torres et al., "LID-DS: A Linux Intrusion Detection Dataset", Future Generation Computer Systems, 2022. DOI: 10.1016/j.future.2022.01.015
- **LID-DS 2019:** FKIE-CAD, Fraunhofer Institute. Website: https://fkie-cad.github.io/COMIDDS/content/datasets/lids_ds_2019/
- **UNSW-NB15:** Moustafa & Slay, "UNSW-NB15: A comprehensive data set for network intrusion detection systems", IEEE MILCOM, 2015
- **CIC-IDS2017:** Sharafaldin et al., "Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization", ICISSP, 2018

---

## 📖 Additional Datasets

Untuk dataset tambahan lainnya, lihat: [`docs/ADDITIONAL_DATASETS.md`](ADDITIONAL_DATASETS.md)

---

**Selamat menggunakan dataset real untuk training H-SOAR! 🎯**

