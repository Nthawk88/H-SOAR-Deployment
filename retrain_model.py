#!/usr/bin/env python3
"""
Retrain model with deduplicated dataset
This will create a deduplicated version and retrain
"""

import pandas as pd
import sys
import os

def create_deduplicated_dataset(input_file, output_file):
    """Create deduplicated dataset for training"""
    print("="*80)
    print("Creating Deduplicated Dataset for Training")
    print("="*80)
    print()
    
    print(f"Loading dataset: {input_file}")
    df = pd.read_csv(input_file)
    print(f"  Original samples: {len(df)}")
    
    # Remove duplicates (keep first occurrence)
    print(f"\nRemoving duplicates...")
    df_dedup = df.drop_duplicates(keep='first')
    duplicates_removed = len(df) - len(df_dedup)
    print(f"  After deduplication: {len(df_dedup)}")
    print(f"  Duplicates removed: {duplicates_removed} ({duplicates_removed/len(df)*100:.1f}%)")
    
    # Show label distribution
    print(f"\nLabel distribution:")
    label_counts = df_dedup['label'].value_counts()
    for label, count in label_counts.items():
        percentage = (count / len(df_dedup)) * 100
        print(f"  {label:12s}: {count:6d} ({percentage:5.2f}%)")
    
    # Save deduplicated dataset
    os.makedirs(os.path.dirname(output_file) if os.path.dirname(output_file) else '.', exist_ok=True)
    df_dedup.to_csv(output_file, index=False)
    
    print(f"\n✅ Deduplicated dataset saved to: {output_file}")
    print(f"   Total samples: {len(df_dedup)}")
    print(f"   File size: {os.path.getsize(output_file) / (1024*1024):.2f} MB")
    
    return output_file

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python retrain_model.py <input_dataset.csv> [output_dataset.csv]")
        print("\nExample:")
        print("  python retrain_model.py data/training_dataset_merged.csv data/training_dataset_dedup.csv")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else input_file.replace('.csv', '_dedup.csv')
    
    if not os.path.exists(input_file):
        print(f"❌ Error: Dataset file not found: {input_file}")
        sys.exit(1)
    
    create_deduplicated_dataset(input_file, output_file)
    
    print("\n" + "="*80)
    print("Next step: Retrain model with deduplicated dataset")
    print("="*80)
    print(f"\nRun: python run_system.py --mode train --dataset {output_file}")

