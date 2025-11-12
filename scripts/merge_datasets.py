#!/usr/bin/env python3
"""
Merge multiple H-SOAR training datasets into one
"""

import pandas as pd
import sys
import os
from pathlib import Path

def merge_datasets(input_files, output_file):
    """Merge multiple CSV datasets into one"""
    print("="*80)
    print("Merging H-SOAR Training Datasets")
    print("="*80)
    print()
    
    all_dataframes = []
    
    for i, input_file in enumerate(input_files, 1):
        if not os.path.exists(input_file):
            print(f"⚠️  Warning: {input_file} not found, skipping...")
            continue
        
        print(f"Loading dataset {i}/{len(input_files)}: {input_file}")
        try:
            df = pd.read_csv(input_file)
            print(f"  ✅ Loaded {len(df)} samples with {len(df.columns)} features")
            
            # Check if has 'label' column
            if 'label' not in df.columns:
                print(f"  ⚠️  Warning: No 'label' column found, skipping...")
                continue
            
            all_dataframes.append(df)
            
        except Exception as e:
            print(f"  ❌ Error loading {input_file}: {e}")
            continue
    
    if not all_dataframes:
        print("\n❌ Error: No valid datasets to merge!")
        return False
    
    print(f"\nMerging {len(all_dataframes)} datasets...")
    
    # Merge all dataframes
    try:
        merged_df = pd.concat(all_dataframes, ignore_index=True)
        
        # Remove duplicates
        initial_count = len(merged_df)
        merged_df = merged_df.drop_duplicates()
        duplicates_removed = initial_count - len(merged_df)
        
        # Save merged dataset
        os.makedirs(os.path.dirname(output_file) if os.path.dirname(output_file) else '.', exist_ok=True)
        merged_df.to_csv(output_file, index=False)
        
        print(f"\n✅ Merged dataset saved to: {output_file}")
        print(f"   Total samples: {len(merged_df)}")
        print(f"   Duplicates removed: {duplicates_removed}")
        
        # Show label distribution
        if 'label' in merged_df.columns:
            print(f"\nLabel distribution:")
            label_counts = merged_df['label'].value_counts()
            for label, count in label_counts.items():
                percentage = (count / len(merged_df)) * 100
                print(f"   {label:15s}: {count:6d} ({percentage:5.2f}%)")
        
        # Show features
        print(f"\nFeatures: {len(merged_df.columns) - 1}")  # -1 for label column
        print(f"File size: {os.path.getsize(output_file) / (1024*1024):.2f} MB")
        
        print(f"\n{'='*80}")
        print("Dataset merge completed!")
        print(f"{'='*80}")
        
        return True
        
    except Exception as e:
        print(f"\n❌ Error merging datasets: {e}")
        return False

def main():
    if len(sys.argv) < 3:
        print("Usage: python merge_datasets.py <output_file> <input_file1> [input_file2] ...")
        print("\nExamples:")
        print("  python merge_datasets.py data/training_dataset.csv \\")
        print("    data/training_dataset_adfa.csv \\")
        print("    data/training_dataset_lid2019.csv")
        print("\n  python merge_datasets.py data/training_dataset_merged.csv \\")
        print("    data/training_dataset.csv \\")
        print("    data/training_dataset_unsw.csv \\")
        print("    data/training_dataset_cic.csv")
        sys.exit(1)
    
    output_file = sys.argv[1]
    input_files = sys.argv[2:]
    
    success = merge_datasets(input_files, output_file)
    
    if success:
        print("\nNext steps:")
        print(f"1. Verify dataset: python verify_dataset.py")
        print(f"2. Train model: python run_system.py --mode train --dataset {output_file}")
    else:
        sys.exit(1)

if __name__ == "__main__":
    main()

