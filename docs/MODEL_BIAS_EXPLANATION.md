# Penjelasan: Kenapa Model Selalu Memprediksi "Malicious"?

## 🔍 Masalah yang Terjadi

Model H-SOAR selalu memprediksi **"malicious"** untuk semua event, bahkan yang seharusnya **"benign"** (seperti normal file read).

---

## 🎯 Penyebab Utama

### 1. **Dataset Memiliki 99%+ Duplicates**

**Fakta:**
- CIC-IDS2017: 80,000 samples → hanya 7 unique (99.99% duplicates!)
- LID-DS 2021: 13,718 samples → hanya 98 unique (99.3% duplicates!)
- CVE-2020-23839: 8,000 samples → hanya 56 unique (99.3% duplicates!)

**Dampak:**
- Model hanya belajar dari ~161 unique samples (terlalu kecil!)
- Model overfit karena melihat data yang sama berulang-ulang
- Model tidak bisa generalize dengan baik

### 2. **Dataset Tidak Seimbang**

**Distribusi setelah deduplication:**
- Benign: 6 samples (3.7%)
- Malicious: 155 samples (96.3%)

**Dampak:**
- Model bias ke "malicious" karena 96% data adalah malicious
- Model tidak pernah melihat cukup contoh "benign"
- Model selalu memilih "malicious" karena itu yang paling sering muncul

### 3. **Feature Extraction Masalah**

**Masalah:**
- Feature extraction mungkin membuat semua event terlihat malicious
- Contoh: `filepath_criticality` terlalu tinggi untuk file normal
- Contoh: `action` di-encode sebagai 0 (unknown) untuk 'read'

**Dampak:**
- Semua event memiliki feature values yang mirip
- Model tidak bisa membedakan benign vs malicious
- Model default ke "malicious" karena itu mayoritas

### 4. **Model Overfit**

**Tanda-tanda:**
- Training accuracy: 100% (sempurna!)
- Test accuracy: 21.4% (sangat buruk!)
- Precision: 10.7% (sangat rendah!)

**Dampak:**
- Model menghafal training data (banyak duplicates)
- Model tidak bisa generalize ke data baru
- Model selalu memprediksi "malicious" karena itu yang dihafal

---

## 💡 Solusi

### Solusi 1: Perbaiki Dataset Converter (Recommended)

**Masalah:** Converter menghasilkan terlalu banyak rows identik

**Solusi:**
- Tambahkan variasi pada feature extraction
- Gunakan lebih banyak informasi dari source data
- Jangan generate default values yang sama

### Solusi 2: Gunakan Dataset yang Lebih Beragam

**Masalah:** Dataset saat ini terlalu banyak duplicates

**Solusi:**
- Download dataset yang lebih beragam
- Gunakan dataset yang sudah memiliki variasi lebih baik
- Atau collect real data dari production environment

### Solusi 3: Data Augmentation

**Masalah:** Dataset terlalu kecil setelah deduplication

**Solusi:**
- Tambahkan noise kecil ke features
- Variasi feature values dengan range yang wajar
- Generate synthetic samples yang mirip tapi tidak identik

### Solusi 4: Gunakan Synthetic Dataset untuk Testing

**Masalah:** Real dataset memiliki banyak duplicates

**Solusi:**
- Gunakan synthetic dataset untuk development/testing
- Synthetic dataset memiliki variasi yang lebih baik
- Lebih mudah untuk balance classes

```bash
# Generate synthetic dataset (10,000 samples, balanced)
python generate_dataset.py \
    --samples 10000 \
    --benign-ratio 0.7 \
    --suspicious-ratio 0.1 \
    --malicious-ratio 0.2 \
    --output data/training_dataset_synthetic.csv

# Train dengan synthetic dataset
python run_system.py --mode train --dataset data/training_dataset_synthetic.csv
```

---

## 📊 Perbandingan

| Dataset | Original | After Dedup | Unique % | Balance |
|---------|----------|-------------|----------|---------|
| CIC-IDS2017 | 80,000 | 7 | 0.009% | 6 benign, 1 malicious |
| LID-DS 2021 | 13,718 | 98 | 0.7% | 0 benign, 98 malicious |
| CVE-2020-23839 | 8,000 | 56 | 0.7% | 0 benign, 56 malicious |
| **Total** | **101,718** | **161** | **0.16%** | **6 benign, 155 malicious** |

**Kesimpulan:** Dataset memiliki terlalu banyak duplicates dan tidak seimbang!

---

## ✅ Rekomendasi

### Untuk Development/Testing:
1. **Gunakan Synthetic Dataset** - lebih mudah, lebih beragam, lebih seimbang
2. **Generate 10,000-50,000 samples** dengan balance 70% benign, 20% malicious, 10% suspicious
3. **Train dan test** dengan synthetic dataset

### Untuk Production:
1. **Collect real data** dari production environment
2. **Label manual** untuk mendapatkan dataset yang berkualitas
3. **Retrain** dengan real data yang sudah di-label

### Untuk Research/Paper:
1. **Perbaiki converter** untuk menghasilkan lebih banyak variasi
2. **Gunakan dataset yang lebih beragam** (CIC-IDS2018, dll)
3. **Combine multiple datasets** dengan deduplication yang lebih baik

---

## 🔧 Quick Fix: Gunakan Synthetic Dataset

```bash
# Generate balanced synthetic dataset
python generate_dataset.py \
    --samples 20000 \
    --benign-ratio 0.7 \
    --suspicious-ratio 0.1 \
    --malicious-ratio 0.2 \
    --output data/training_dataset_synthetic.csv

# Train
python run_system.py --mode train --dataset data/training_dataset_synthetic.csv

# Test
python test_classification.py
```

**Expected results:**
- Model accuracy: 85-95%
- Model bisa membedakan benign dan malicious
- Tidak selalu memprediksi "malicious"

---

## 📝 Summary

**Kenapa selalu memprediksi "malicious"?**
1. ✅ Dataset 99%+ duplicates → hanya ~161 unique samples
2. ✅ Dataset tidak seimbang → 96% malicious, 4% benign
3. ✅ Model overfit → menghafal duplicates
4. ✅ Feature extraction → semua event terlihat mirip

**Solusi terbaik:**
- Gunakan synthetic dataset untuk development/testing
- Perbaiki converter untuk production
- Collect real data untuk production deployment

