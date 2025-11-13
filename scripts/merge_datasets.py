#!/usr/bin/env python3
"""
Merge multiple H-SOAR training datasets into one
"""

import pandas as pd
import sys
import os
from pathlib import Path

def merge_datasets(input_files, output_file, skip_dedup=False, dedup_malicious=False):
    """Merge multiple CSV datasets into one
    
    Args:
        input_files: List of input CSV files
        output_file: Output CSV file
        skip_dedup: If True, skip duplicate removal (keep all samples)
    """
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
        
        initial_count = len(merged_df)
        
        if skip_dedup:
            print(f"\n⚠️  Skipping duplicate removal (keeping all {initial_count} samples)")
            print(f"  This is recommended for training datasets with many similar samples")
            duplicates_removed = 0
        else:
            print(f"\nRemoving duplicates...")
            
            # Strategy: Remove duplicates within each original dataset first,
            # then merge, then optionally remove cross-dataset duplicates
            print(f"  Removing duplicates within each source dataset first...")
            deduped_dataframes = []
            within_duplicates = 0
            for i, df in enumerate(aligned_dataframes, 1):
                before = len(df)
                df_dedup = df.drop_duplicates()
                after = len(df_dedup)
                removed = before - after
                within_duplicates += removed
                dataset_name = f"dataset_{i}"
                print(f"    {dataset_name}: Removed {removed} duplicates ({removed/before*100 if before else 0:.1f}%)")
                deduped_dataframes.append(df_dedup)
            
            merged_df = pd.concat(deduped_dataframes, ignore_index=True)
            after_within = len(merged_df)
            print(f"  Removing cross-dataset duplicates (only if ALL columns identical)...")
            merged_df_dedup = merged_df.drop_duplicates()
            cross_duplicates = after_within - len(merged_df_dedup)
            merged_df = merged_df_dedup
            duplicates_removed = within_duplicates + cross_duplicates
            
            print(f"  Initial samples: {initial_count}")
            print(f"  After within-dataset deduplication: {after_within}")
            print(f"  After cross-dataset deduplication: {len(merged_df)}")
            print(f"  Within-dataset duplicates removed: {within_duplicates}")
            print(f"  Cross-dataset duplicates removed: {cross_duplicates}")
            print(f"  Total duplicates removed: {duplicates_removed}")
            
            if duplicates_removed > initial_count * 0.5:
                print(f"\n  ⚠️  Warning: More than 50% of samples were removed as duplicates!")
                print(f"  This suggests datasets may have many identical rows.")
                print(f"  Consider using --no-dedup flag to keep all samples for training.")
                print(f"  Or check datasets with: python scripts/debug_merge.py <file1> <file2>")
        
        malicious_dedup_removed = 0
        if dedup_malicious:
            if 'label' not in merged_df.columns:
                print("\n⚠️  Cannot deduplicate malicious samples: no 'label' column present.")
            else:
                feature_columns = [col for col in merged_df.columns if col != 'label']
                malicious_mask = merged_df['label'] == 'malicious'
                malicious_df = merged_df[malicious_mask]
                others_df = merged_df[~malicious_mask]
                before_malicious = len(malicious_df)
                malicious_df = malicious_df.drop_duplicates(subset=feature_columns + ['label'])
                malicious_dedup_removed = before_malicious - len(malicious_df)
                if malicious_dedup_removed > 0:
                    print(f"\nRemoving duplicates specifically from malicious samples...")
                    print(f"  Malicious samples before: {before_malicious}")
                    print(f"  Malicious duplicates removed: {malicious_dedup_removed}")
                merged_df = pd.concat([others_df, malicious_df], ignore_index=True)
        
        # Save merged dataset
        os.makedirs(os.path.dirname(output_file) if os.path.dirname(output_file) else '.', exist_ok=True)
        merged_df.to_csv(output_file, index=False)
        
        print(f"\n✅ Merged dataset saved to: {output_file}")
        total_removed = duplicates_removed + malicious_dedup_removed
        print(f"   Total samples: {len(merged_df)}")
        print(f"   Duplicates removed: {total_removed}")
        if malicious_dedup_removed > 0:
            print(f"   (Including {malicious_dedup_removed} malicious duplicates)")
        
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
        print("Usage: python merge_datasets.py <output_file> <input_file1> [input_file2] ... [--no-dedup] [--dedup-malicious]")
        print("\nOptions:")
        print("  --no-dedup    Skip duplicate removal (keep all samples)")
        print("  --dedup-malicious  Remove duplicates only from malicious samples (can be combined with --no-dedup)")
        print("\nExamples:")
        print("  python merge_datasets.py data/training_dataset.csv \\")
        print("    data/training_dataset_adfa.csv \\")
        print("    data/training_dataset_lid2019.csv")
        print("\n  python merge_datasets.py data/training_dataset_merged.csv \\")
        print("    data/training_dataset.csv \\")
        print("    data/training_dataset_unsw.csv \\")
        print("    data/training_dataset_cic.csv \\")
        print("    --no-dedup")
        sys.exit(1)
    
    # Parse arguments
    args = sys.argv[1:]
    skip_dedup = '--no-dedup' in args
    if skip_dedup:
        args.remove('--no-dedup')

    dedup_malicious = '--dedup-malicious' in args
    if dedup_malicious:
        args.remove('--dedup-malicious')
    
    output_file = args[0]
    input_files = args[1:]
    
    success = merge_datasets(input_files, output_file, skip_dedup=skip_dedup, dedup_malicious=dedup_malicious)
    
    if success:
        print("\nNext steps:")
        print(f"1. Verify dataset: python verify_dataset.py")
        print(f"2. Train model: python run_system.py --mode train --dataset {output_file}")
    else:
        sys.exit(1)

if __name__ == "__main__":
    main()

