# Dataset Real Tambahan untuk H-SOAR

Daftar dataset real-world tambahan dari paper/journal yang cocok untuk H-SOAR training.

---

## 🎯 Dataset Host-Based yang Cocok

### 1. **LID-DS 2019** ⭐ Recommended

**Paper:** 
- "LID-DS: A Linux Intrusion Detection Dataset" (2019 version)
- FKIE-CAD, Fraunhofer Institute

**Info:**
- **Format:** System calls dengan parameters
- **Size:** ~200-500MB
- **Attack Types:** Berbagai serangan berdasarkan CVE/CWE
- **Normal Activity:** Synthetic normal activity
- **Duration:** ~30 detik per simulasi

**Download:**
```bash
# Visit: https://fkie-cad.github.io/COMIDDS/content/datasets/lids_ds_2019/
# Download dataset
# Extract to: data/external/lid_ds_2019/
```

**Convert:**
```bash
python scripts/convert_paper_dataset.py data/external/lid_ds_2019 data/training_dataset.csv
```

**Reference:**
- Website: https://fkie-cad.github.io/COMIDDS/content/datasets/lids_ds_2019/
- Paper: Related to COMIDDS project

---

### 2. **UNSW-NB15** (Host-based subset)

**Paper:**
- Moustafa & Slay, "UNSW-NB15: A comprehensive data set for network intrusion detection systems (UNSW-NB15 network data set)"
- IEEE Military Communications Conference, 2015

**Info:**
- **Format:** Network + Host features
- **Size:** ~100MB
- **Attack Types:** 9 attack types
- **Normal Activity:** Real normal traffic
- **Note:** Network-based tapi ada host features yang bisa digunakan

**Download:**
```bash
# Visit: https://www.unsw.adfa.edu.au/unsw-canberra-cyber/cybersecurity/ADFA-NB15-Datasets/
# Download UNSW-NB15 dataset
# Extract to: data/external/unsw_nb15/
```

**Reference:**
- Website: https://www.unsw.adfa.edu.au/unsw-canberra-cyber/cybersecurity/ADFA-NB15-Datasets/
- Paper: DOI: 10.1109/MILCOM.2015.7359069

---

### 3. **CIC-IDS2017** (Host-based features)

**Paper:**
- Sharafaldin et al., "Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization"
- ICISSP 2018

**Info:**
- **Format:** Network + Host logs
- **Size:** ~2.5GB
- **Attack Types:** 7 attack categories
- **Normal Activity:** Real normal traffic
- **Note:** Bisa extract host-based features dari network logs

**Download:**
```bash
# Visit: https://www.unb.ca/cic/datasets/ids-2017.html
# Download CIC-IDS2017 dataset
# Extract to: data/external/cic_ids2017/
```

**Reference:**
- Website: https://www.unb.ca/cic/datasets/ids-2017.html
- Paper: DOI: 10.5220/0006639801080116

---

### 4. **HIDS2019** (Host-based Intrusion Detection Dataset 2019)

**Paper:**
- Various research papers on host-based IDS

**Info:**
- **Format:** System calls, process logs
- **Size:** ~100-300MB
- **Attack Types:** Various host-based attacks
- **Note:** Perlu cari di GitHub atau research repositories

**Download:**
```bash
# Search GitHub for "HIDS2019" or "host-based intrusion detection dataset"
# Or check research paper repositories
```

---

### 5. **DARPA Intrusion Detection Evaluation Dataset**

**Paper:**
- MIT Lincoln Laboratory, DARPA Intrusion Detection Evaluation

**Info:**
- **Format:** System logs, network logs
- **Size:** Large (multiple GB)
- **Attack Types:** Various attacks
- **Normal Activity:** Real normal activity
- **Note:** Classic dataset, bisa diadaptasi untuk host-based

**Download:**
```bash
# Visit: https://archive.ll.mit.edu/ideval/data/
# Download DARPA dataset
# Extract to: data/external/darpa/
```

**Reference:**
- Website: https://archive.ll.mit.edu/ideval/data/
- Paper: MIT Lincoln Laboratory Technical Reports

---

## 📊 Dataset Comparison

| Dataset | Type | Size | Format | Download | Label Quality |
|---------|------|------|--------|----------|---------------|
| **LID-DS 2019** | Host-based | ~200-500MB | Syscalls | Direct | Excellent |
| **LID-DS 2021** | Host-based | ~500MB-1GB | Auditd logs | Zenodo | Excellent |
| **ADFA-LD** | Host-based | ~100-200MB | Syscall traces | GitHub/Registration | Good |
| **UNSW-NB15** | Network+Host | ~100MB | CSV features | Direct | Good |
| **CIC-IDS2017** | Network+Host | ~2.5GB | PCAP/CSV | Direct | Excellent |
| **DARPA** | Mixed | Large | Logs | Archive | Good (old) |

---

## 🚀 Quick Start: Download Multiple Datasets

### Step 1: Download Script

```bash
cd ~/hsoar
source venv/bin/activate

# Run download script
bash scripts/download_additional_datasets.sh
```

### Step 2: Convert All Datasets

```bash
# Convert each dataset
python scripts/convert_paper_dataset.py data/external/lid_ds_2019 data/training_dataset_lid2019.csv
python scripts/convert_paper_dataset.py data/external/unsw_nb15 data/training_dataset_unsw.csv
python scripts/convert_paper_dataset.py data/external/cic_ids2017 data/training_dataset_cic.csv

# Merge all datasets
python scripts/merge_datasets.py \
    data/training_dataset_lid2019.csv \
    data/training_dataset_unsw.csv \
    data/training_dataset_cic.csv \
    data/training_dataset.csv
```

### Step 3: Train with Combined Dataset

```bash
python run_system.py --mode train --dataset data/training_dataset.csv
```

---

## 📝 Notes

1. **LID-DS 2019** sangat recommended karena:
   - Host-based dengan syscalls
   - Berbagai attack scenarios
   - Format compatible dengan H-SOAR

2. **UNSW-NB15** bagus untuk:
   - Baseline comparison
   - Network + Host features
   - Real-world traffic

3. **CIC-IDS2017** bagus untuk:
   - Large dataset
   - Various attack types
   - Real normal traffic

4. **Multiple datasets** akan meningkatkan:
   - Model generalization
   - Attack coverage
   - Real-world accuracy

---

## 🔍 Finding More Datasets

### Search Strategies:

1. **GitHub Search:**
   ```bash
   # Search for host-based IDS datasets
   # Keywords: "host-based intrusion detection dataset", "HIDS dataset", "system call dataset"
   ```

2. **Research Paper Repositories:**
   - IEEE Xplore
   - ACM Digital Library
   - arXiv
   - ResearchGate

3. **Dataset Repositories:**
   - Zenodo: https://zenodo.org/search?q=host-based%20intrusion
   - Kaggle: https://www.kaggle.com/datasets?search=ids
   - UCI ML Repository: https://archive.ics.uci.edu/

4. **Specific Search Terms:**
   - "host-based intrusion detection dataset"
   - "HIDS dataset system calls"
   - "Linux auditd dataset labeled"
   - "file integrity monitoring dataset"

---

## ⚠️ Important Notes

1. **License Check:** Pastikan cek lisensi dataset sebelum digunakan
2. **Format Conversion:** Beberapa dataset perlu conversion ke format H-SOAR
3. **Label Quality:** Review labels untuk memastikan kualitas
4. **Size Consideration:** Dataset besar membutuhkan lebih banyak resources

---

## 📚 References

1. **LID-DS 2019:** https://fkie-cad.github.io/COMIDDS/content/datasets/lids_ds_2019/
2. **UNSW-NB15:** https://www.unsw.adfa.edu.au/unsw-canberra-cyber/cybersecurity/ADFA-NB15-Datasets/
3. **CIC-IDS2017:** https://www.unb.ca/cic/datasets/ids-2017.html
4. **DARPA:** https://archive.ll.mit.edu/ideval/data/
5. **LID-DS 2021:** https://zenodo.org/record/5773804
6. **ADFA-LD:** https://www.unsw.adfa.edu.au/unsw-canberra-cyber/cybersecurity/ADFA-LD

---

**Selamat mengumpulkan dataset real untuk meningkatkan performa H-SOAR! 🎯**

