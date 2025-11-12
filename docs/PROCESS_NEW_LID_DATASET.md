# Panduan Memproses Dataset LID-DS Baru

Panduan untuk memproses dataset LID-DS baru (CVE-2020-23839 atau dataset LID-DS lainnya).

---

## Step 1: Extract Dataset

```bash
cd ~/hsoar
source venv/bin/activate

# Pindahkan file ZIP ke folder external
mkdir -p data/external/lid_ds_new
mv ~/Downloads/CVE-2020-23839.zip data/external/lid_ds_new/

# Extract
cd data/external/lid_ds_new
unzip CVE-2020-23839.zip

# Cek struktur folder
ls -la
```

**Expected structure:**
```
lid_ds_new/
├── CVE-2020-23839/
│   ├── training/
│   │   └── *.zip files
│   ├── validation/
│   │   └── *.zip files
│   └── ...
```

---

## Step 2: Convert ke Format H-SOAR

```bash
cd ~/hsoar
source venv/bin/activate

# Convert dataset baru
python scripts/convert_paper_dataset.py \
    data/external/lid_ds_new/CVE-2020-23839 \
    data/training_dataset_cve2020.csv
```

**Expected output:**
- Dataset akan di-convert dengan label: `malicious`
- Proses akan extract ZIP files dan parse `.sc` dan `.json` files
- Output: CSV file dengan format H-SOAR

---

## Step 3: Verify Dataset

```bash
# Verify dataset yang baru
python verify_dataset.py data/training_dataset_cve2020.csv
```

**Check:**
- Total samples
- Label distribution
- Features count

---

## Step 4: Merge dengan Dataset Lain (Optional)

Jika ingin merge dengan dataset yang sudah ada:

```bash
# Merge dengan LID-DS 2021
python scripts/merge_datasets.py \
    data/training_dataset_merged_new.csv \
    data/training_dataset_lid2021.csv \
    data/training_dataset_cve2020.csv \
    --no-dedup

# Atau merge dengan semua dataset
python scripts/merge_datasets.py \
    data/training_dataset_all.csv \
    data/training_dataset_lid2021.csv \
    data/training_dataset_cic2017.csv \
    data/training_dataset_cve2020.csv \
    --no-dedup
```

---

## Step 5: Retrain Model

```bash
# Train dengan dataset baru saja
python run_system.py --mode train --dataset data/training_dataset_cve2020.csv

# Atau train dengan merged dataset
python run_system.py --mode train --dataset data/training_dataset_merged_new.csv
```

---

## Step 6: Test Classification

```bash
# Test dengan model yang baru
python test_classification.py
```

---

## Troubleshooting

### Error: "No events extracted from dataset"

**Penyebab:** Struktur folder berbeda atau format file tidak dikenali

**Solusi:**
```bash
# Cek struktur folder
find data/external/lid_ds_new -type f -name "*.sc" | head -5
find data/external/lid_ds_new -type f -name "*.json" | head -5

# Cek format file
head -5 data/external/lid_ds_new/CVE-2020-23839/training/*.sc | head -1
```

### Error: "Permission denied" saat extract

**Solusi:**
```bash
# Extract dengan permission yang benar
unzip -o CVE-2020-23839.zip
chmod -R 755 CVE-2020-23839/
```

### Dataset terlalu kecil setelah convert

**Penyebab:** Converter mungkin tidak menemukan semua file atau ada error parsing

**Solusi:**
- Cek log output dari converter
- Pastikan semua ZIP files sudah di-extract
- Cek apakah ada error parsing di log

---

## Expected Results

Setelah convert berhasil:
- ✅ Dataset dengan format H-SOAR (CSV)
- ✅ Label: `malicious` (karena LID-DS adalah attack dataset)
- ✅ Features: 23 features
- ✅ Siap untuk training

Setelah training:
- ✅ Model accuracy: 85-95%
- ✅ Model bisa membedakan benign dan malicious
- ✅ Siap untuk real-time detection

---

## Next Steps

1. Extract dataset
2. Convert ke format H-SOAR
3. Verify dataset
4. Merge dengan dataset lain (optional)
5. Retrain model
6. Test classification

