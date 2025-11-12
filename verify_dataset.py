#!/usr/bin/env python3
"""Quick script to verify dataset"""

import pandas as pd
import sys

dataset_path = 'data/training_dataset.csv'

try:
    df = pd.read_csv(dataset_path)
    print(f"✅ Dataset loaded: {len(df)} samples")
    print(f"✅ Features: {len(df.columns) - 1}")
    print(f"\nLabel distribution:")
    for label, count in df['label'].value_counts().items():
        percentage = count / len(df) * 100
        print(f"  {label:12s}: {count:6d} ({percentage:5.2f}%)")
    print(f"\n✅ Dataset is valid and ready for training!")
    sys.exit(0)
except Exception as e:
    print(f"❌ Error: {e}")
    sys.exit(1)


