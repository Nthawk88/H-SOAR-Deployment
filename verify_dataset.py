#!/usr/bin/env python3
"""Quick script to verify dataset"""

import pandas as pd
import sys
import os

# Get dataset path from argument or use default
if len(sys.argv) > 1:
    dataset_path = sys.argv[1]
else:
    dataset_path = 'data/training_dataset.csv'

if not os.path.exists(dataset_path):
    print(f"❌ Error: Dataset file not found: {dataset_path}")
    print(f"\nUsage: python verify_dataset.py [dataset_path]")
    print(f"Example: python verify_dataset.py data/training_dataset_merged.csv")
    sys.exit(1)

try:
    df = pd.read_csv(dataset_path)
    print(f"✅ Dataset loaded: {len(df)} samples")
    print(f"✅ Features: {len(df.columns) - 1}")
    print(f"✅ File: {dataset_path}")
    print(f"✅ File size: {os.path.getsize(dataset_path) / (1024*1024):.2f} MB")
    
    if 'label' not in df.columns:
        print(f"❌ Error: No 'label' column found in dataset")
        sys.exit(1)
    
    print(f"\nLabel distribution:")
    for label, count in df['label'].value_counts().items():
        percentage = count / len(df) * 100
        print(f"  {label:12s}: {count:6d} ({percentage:5.2f}%)")
    
    print(f"\n✅ Dataset is valid and ready for training!")
    sys.exit(0)
except Exception as e:
    print(f"❌ Error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)


