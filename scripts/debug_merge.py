#!/usr/bin/env python3
"""
Debug script to understand why merge is removing so many duplicates
"""

import pandas as pd
import sys

def debug_datasets(file1, file2):
    """Compare two datasets to understand duplicate issue"""
    
    print("="*80)
    print("Debugging Dataset Merge")
    print("="*80)
    print()
    
    # Load datasets
    print(f"Loading {file1}...")
    df1 = pd.read_csv(file1)
    print(f"  Samples: {len(df1)}")
    print(f"  Columns: {len(df1.columns)}")
    
    print(f"\nLoading {file2}...")
    df2 = pd.read_csv(file2)
    print(f"  Samples: {len(df2)}")
    print(f"  Columns: {len(df2.columns)}")
    
    # Check column alignment
    print(f"\nColumn comparison:")
    cols1 = set(df1.columns)
    cols2 = set(df2.columns)
    print(f"  {file1}: {len(cols1)} columns")
    print(f"  {file2}: {len(cols2)} columns")
    print(f"  Common: {len(cols1 & cols2)}")
    print(f"  Only in {file1}: {cols1 - cols2}")
    print(f"  Only in {file2}: {cols2 - cols1}")
    
    # Check for duplicates within each dataset
    print(f"\nDuplicates within datasets:")
    feature_cols1 = [c for c in df1.columns if c != 'label']
    feature_cols2 = [c for c in df2.columns if c != 'label']
    
    dup1 = df1.duplicated(subset=feature_cols1).sum()
    dup2 = df2.duplicated(subset=feature_cols2).sum()
    print(f"  {file1}: {dup1} duplicate rows (based on features)")
    print(f"  {file2}: {dup2} duplicate rows (based on features)")
    
    # Show sample rows
    print(f"\nSample rows from {file1} (first 3):")
    print(df1[feature_cols1[:10] + ['label']].head(3).to_string())
    
    print(f"\nSample rows from {file2} (first 3):")
    print(df2[feature_cols2[:10] + ['label']].head(3).to_string())
    
    # Check value ranges
    print(f"\nValue ranges (first 5 numeric columns):")
    for col in feature_cols1[:5]:
        if col in df1.columns and col in df2.columns:
            print(f"\n  {col}:")
            print(f"    {file1}: min={df1[col].min():.2f}, max={df1[col].max():.2f}, unique={df1[col].nunique()}")
            print(f"    {file2}: min={df2[col].min():.2f}, max={df2[col].max():.2f}, unique={df2[col].nunique()}")
    
    # Check label distribution
    print(f"\nLabel distribution:")
    print(f"  {file1}:")
    print(df1['label'].value_counts())
    print(f"\n  {file2}:")
    print(df2['label'].value_counts())
    
    # Try to find overlapping feature combinations
    print(f"\nChecking for overlapping feature combinations...")
    # Sample a subset for comparison
    sample_size = min(1000, len(df1), len(df2))
    df1_sample = df1[feature_cols1].head(sample_size)
    df2_sample = df2[feature_cols2].head(sample_size)
    
    # Merge to find overlaps
    merged = pd.merge(df1_sample, df2_sample, how='inner', left_on=feature_cols1, right_on=feature_cols2)
    print(f"  Overlapping rows (in first {sample_size} samples): {len(merged)}")
    
    if len(merged) > 0:
        print(f"  This suggests many feature combinations are identical between datasets")
        print(f"  This could be because:")
        print(f"    1. Both converters use similar default values")
        print(f"    2. Datasets have similar structure")
        print(f"    3. Feature extraction produces similar values")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python debug_merge.py <dataset1.csv> <dataset2.csv>")
        sys.exit(1)
    
    debug_datasets(sys.argv[1], sys.argv[2])

