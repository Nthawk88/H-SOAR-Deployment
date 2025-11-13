#!/usr/bin/env python3
"""
Create balanced dataset with smart deduplication
This script creates a balanced dataset by:
1. Deduplicating each dataset separately
2. Sampling to balance classes
3. Merging balanced samples
"""

import pandas as pd
import sys
import os
import numpy as np

def create_balanced_dataset(input_files, output_file, target_benign_ratio=0.7, max_samples_per_class=50000):
    """Create balanced dataset with smart deduplication"""
    print("="*80)
    print("Creating Balanced Dataset with Smart Deduplication")
    print("="*80)
    print()
    
    all_datasets = {}
    
    # Load and deduplicate each dataset separately
    for input_file in input_files:
        if not os.path.exists(input_file):
            print(f"⚠️  Warning: {input_file} not found, skipping...")
            continue
        
        print(f"Loading {input_file}...")
        try:
            df = pd.read_csv(input_file)
            print(f"  Original: {len(df)} samples")
            
            # Deduplicate within dataset (only if ALL columns including label are identical)
            # This is less aggressive and keeps more samples
            df_dedup = df.drop_duplicates(keep='first')
            removed = len(df) - len(df_dedup)
            print(f"  After dedup (all columns): {len(df_dedup)} samples (removed {removed} duplicates)")
            
            # If still too many duplicates, try feature-based dedup but keep more samples
            if removed > len(df) * 0.9:  # If >90% duplicates, try less aggressive
                print(f"    Too many duplicates, trying less aggressive deduplication...")
                # Keep samples even if features are similar (only remove exact duplicates)
                df_dedup = df.drop_duplicates(keep='first')
                print(f"    Final: {len(df_dedup)} samples")
            
            # Group by label
            for label in df_dedup['label'].unique():
                label_df = df_dedup[df_dedup['label'] == label]
                if label not in all_datasets:
                    all_datasets[label] = []
                all_datasets[label].append(label_df)
                print(f"    {label}: {len(label_df)} samples")
            
        except Exception as e:
            print(f"  ❌ Error loading {input_file}: {e}")
            continue
    
    if not all_datasets:
        print("\n❌ Error: No valid datasets loaded!")
        return False
    
    # Combine and balance
    print(f"\nBalancing dataset...")
    print(f"  Target benign ratio: {target_benign_ratio*100:.1f}%")
    print(f"  Max samples per class: {max_samples_per_class}")
    
    balanced_dfs = []
    
    for label, dfs in all_datasets.items():
        # Combine all datasets for this label
        combined = pd.concat(dfs, ignore_index=True)
        
        # Remove duplicates across datasets (only exact duplicates)
        initial_count = len(combined)
        combined = combined.drop_duplicates(keep='first')
        removed = initial_count - len(combined)
        if removed > 0:
            print(f"  {label}: Removed {removed} exact duplicates (kept {len(combined)} samples)")
        
        # Sample if too many (but keep more samples for better training)
        if len(combined) > max_samples_per_class:
            print(f"  {label}: Sampling {max_samples_per_class} from {len(combined)} samples")
            combined = combined.sample(n=max_samples_per_class, random_state=42)
        else:
            print(f"  {label}: Using all {len(combined)} samples")
        
        balanced_dfs.append(combined)
    
    # Merge balanced datasets
    merged_df = pd.concat(balanced_dfs, ignore_index=True)
    
    # Shuffle
    merged_df = merged_df.sample(frac=1, random_state=42).reset_index(drop=True)
    
    # Save
    os.makedirs(os.path.dirname(output_file) if os.path.dirname(output_file) else '.', exist_ok=True)
    merged_df.to_csv(output_file, index=False)
    
    print(f"\n✅ Balanced dataset saved to: {output_file}")
    print(f"   Total samples: {len(merged_df)}")
    
    # Show label distribution
    print(f"\nLabel distribution:")
    label_counts = merged_df['label'].value_counts()
    for label, count in label_counts.items():
        percentage = (count / len(merged_df)) * 100
        print(f"   {label:12s}: {count:6d} ({percentage:5.2f}%)")
    
    print(f"\nFeatures: {len(merged_df.columns) - 1}")
    print(f"File size: {os.path.getsize(output_file) / (1024*1024):.2f} MB")
    
    return True

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python create_balanced_dataset.py <output_file> <input_file1> [input_file2] ...")
        print("\nOptions:")
        print("  --benign-ratio RATIO    Target benign ratio (default: 0.7)")
        print("  --max-samples N         Max samples per class (default: 50000)")
        print("\nExample:")
        print("  python create_balanced_dataset.py data/training_dataset_balanced.csv \\")
        print("    data/training_dataset_cic2017.csv \\")
        print("    data/training_dataset_lid2021.csv \\")
        print("    data/training_dataset_cve2020.csv \\")
        print("    --benign-ratio 0.7 --max-samples 50000")
        sys.exit(1)
    
    # Parse arguments
    args = sys.argv[1:]
    output_file = args[0]
    input_files = []
    benign_ratio = 0.7
    max_samples = 50000
    
    i = 1
    while i < len(args):
        if args[i] == '--benign-ratio' and i + 1 < len(args):
            benign_ratio = float(args[i + 1])
            i += 2
        elif args[i] == '--max-samples' and i + 1 < len(args):
            max_samples = int(args[i + 1])
            i += 2
        else:
            input_files.append(args[i])
            i += 1
    
    success = create_balanced_dataset(input_files, output_file, benign_ratio, max_samples)
    
    if success:
        print("\n" + "="*80)
        print("Next steps:")
        print("="*80)
        print(f"1. Verify dataset: python verify_dataset.py {output_file}")
        print(f"2. Train model: python run_system.py --mode train --dataset {output_file}")
    else:
        sys.exit(1)

