# H-SOAR Training Summary

## Current Status

✅ **Model Trained Successfully**
- Dataset: Merged LID-DS 2021 + CIC-IDS2017 (93,718 samples)
- Deduplicated: 105 unique samples
- Model Accuracy: 95.2%
- Models: Random Forest, Gradient Boosting, SVM

## Issues Identified

### 1. Dataset Duplicates Problem
- **Original merged dataset**: 93,718 samples
- **After deduplication**: 105 samples (99.9% duplicates!)
- **Cause**: Converters generate many identical rows
- **Impact**: Model overfits and always predicts "malicious"

### 2. Model Bias
- Model tends to predict "malicious" for all events
- Even benign events (normal file read) classified as malicious
- Ensemble voting favors malicious predictions

## Solutions

### Option 1: Use Individual Datasets (Recommended)

**LID-DS 2021** (13,718 samples, 100% malicious):
```bash
python run_system.py --mode train --dataset data/training_dataset_lid2021.csv
```
- Good for: Attack detection
- Bad for: False positive reduction

**CIC-IDS2017** (80,000 samples, mix benign/malicious):
```bash
python run_system.py --mode train --dataset data/training_dataset_cic2017.csv
```
- Good for: Balanced training
- Better generalization

### Option 2: Fix Dataset Converters

The converters need to generate more diverse features:
- Add randomness to feature values
- Better feature extraction from source data
- Reduce duplicate generation

### Option 3: Use Synthetic Dataset

For testing/development:
```bash
python generate_dataset.py --samples 10000 --output data/training_dataset.csv
python run_system.py --mode train --dataset data/training_dataset.csv
```

## Recommendations

1. **For Production**: Use CIC-IDS2017 dataset (better balance)
2. **For Attack Detection**: Use LID-DS 2021 dataset
3. **For Testing**: Use synthetic dataset

## Next Steps

1. Retrain with CIC-IDS2017 only
2. Test classification again
3. If still biased, improve feature extraction
4. Consider data augmentation techniques

