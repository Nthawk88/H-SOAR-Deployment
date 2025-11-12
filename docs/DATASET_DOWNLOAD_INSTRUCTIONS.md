# Instruksi Download Dataset Real untuk H-SOAR

Karena beberapa URL dataset mungkin berubah, berikut adalah cara download dataset real yang lebih reliable.

---

## 🎯 Dataset yang Recommended

### **Option 1: ADFA-LD (Labeled Version) - Paling Mudah**

**Sumber:** GitHub - Labeled version of ADFA-LD
**Paper:** Creech & Hu, IEEE TIFS 2014

**Download di Linux:**
```bash
cd ~/hsoar/data/external
git clone https://github.com/verazuo/a-labelled-version-of-the-ADFA-LD-dataset.git
cd ../..
```

**Convert:**
```bash
source venv/bin/activate
python scripts/convert_paper_dataset.py data/external/a-labelled-version-of-the-ADFA-LD-dataset data/training_dataset.csv
```

---

### **Option 2: LID-DS 2021 - Manual Download**

**Sumber:** Zenodo (perlu cari record yang benar)
**Paper:** Martinez-Torres et al., Future Generation Computer Systems 2022

**Cara Download:**
1. Visit: https://zenodo.org/search?q=LID-DS
2. Cari record dengan "Linux Intrusion Detection Dataset" atau "LID-DS 2021"
3. Download dataset
4. Extract ke: `data/external/lid_ds/`

**Convert:**
```bash
python scripts/convert_paper_dataset.py data/external/lid_ds data/training_dataset.csv
```

---

### **Option 3: Gunakan Synthetic Dataset (Cepat untuk Testing)**

Jika download dataset real bermasalah, gunakan synthetic dataset yang sudah ada:

```bash
cd ~/hsoar
source venv/bin/activate
python generate_dataset.py --samples 10000 --output data/training_dataset.csv
```

---

## 🚀 Quick Start (Recommended)

**Gunakan ADFA-LD dari GitHub (paling mudah):**

```bash
cd ~/hsoar
source venv/bin/activate

# Download
cd data/external
git clone https://github.com/verazuo/a-labelled-version-of-the-ADFA-LD-dataset.git
cd ../..

# Convert
python scripts/convert_paper_dataset.py data/external/a-labelled-version-of-the-ADFA-LD-dataset data/training_dataset.csv

# Verify
python verify_dataset.py

# Train
python run_system.py --mode train --dataset data/training_dataset.csv
```

---

## 📝 Notes

- **ADFA-LD** lebih mudah didapat karena ada di GitHub
- **LID-DS 2021** mungkin perlu cari URL yang benar di Zenodo
- **Synthetic dataset** tetap valid untuk testing dan development

Setelah dataset siap, lanjutkan dengan training model!

