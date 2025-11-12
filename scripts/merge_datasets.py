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
    
    # Align columns before merging
    print("Aligning columns...")
    all_columns = set()
    for df in all_dataframes:
        all_columns.update(df.columns)
    
    all_columns = sorted(list(all_columns))
    print(f"  Total unique columns: {len(all_columns)}")
    
    # Reindex all dataframes to have same columns (fill missing with NaN)
    aligned_dataframes = []
    for i, df in enumerate(all_dataframes, 1):
        print(f"  Aligning dataset {i}...")
        aligned_df = df.reindex(columns=all_columns)
        
        # Convert numeric columns to same type (handle mixed types)
        for col in aligned_df.columns:
            if col != 'label':  # Don't convert label column
                # Try to convert to numeric, if fails keep as is
                try:
                    aligned_df[col] = pd.to_numeric(aligned_df[col], errors='coerce')
                except:
                    pass
        
        aligned_dataframes.append(aligned_df)
    
    # Merge all dataframes
    try:
        merged_df = pd.concat(aligned_dataframes, ignore_index=True)
        initial_count = len(merged_df)
        
        # Remove duplicates - but be more conservative
        # Option 1: Don't remove duplicates at all (keep all samples)
        # Option 2: Only remove if ALL columns (including label) are identical
        # Option 3: Only remove duplicates within each original dataset, not cross-dataset
        
        print(f"\nRemoving duplicates...")
        print(f"  Strategy: Only remove rows that are identical in ALL columns (including label)")
        print(f"  This preserves samples with same features but different labels")
        
        initial_count = len(merged_df)
        # Only remove if EVERYTHING is identical (including label)
        merged_df = merged_df.drop_duplicates(keep='first')
        duplicates_removed = initial_count - len(merged_df)
        
        print(f"  Initial samples: {initial_count}")
        print(f"  After deduplication: {len(merged_df)}")
        print(f"  Duplicates removed: {duplicates_removed}")
        
        if duplicates_removed > initial_count * 0.5:
            print(f"\n  ⚠️  Warning: More than 50% of samples were removed as duplicates!")
            print(f"  This suggests datasets may have many identical rows.")
            print(f"  Consider checking the datasets with: python scripts/debug_merge.py <file1> <file2>")
        
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

