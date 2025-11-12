#!/bin/bash
# Download real HIDS datasets from papers for H-SOAR training

set -e

echo "=========================================="
echo "H-SOAR Paper Dataset Downloader"
echo "=========================================="
echo ""

# Create data directory
mkdir -p data/external
cd data/external

echo "Available datasets from papers:"
echo "1. LID-DS 2021 (Zenodo) - Recommended, direct download"
echo "2. ADFA-LD (UNSW Canberra) - Requires registration"
echo ""

read -p "Choose dataset (1-2): " choice

case $choice in
    1)
        echo ""
        echo "LID-DS 2021 Dataset Download"
        echo "Dataset: Linux Intrusion Detection Dataset 2021"
        echo "Paper: Martinez-Torres et al., Future Generation Computer Systems 2022"
        echo ""
        echo "⚠️  Direct download URL may not be available."
        echo "Please download manually:"
        echo ""
        echo "Option 1: Visit Zenodo"
        echo "  1. Go to: https://zenodo.org/search?q=LID-DS"
        echo "  2. Search for 'LID-DS 2021' or 'Linux Intrusion Detection Dataset'"
        echo "  3. Download the dataset"
        echo "  4. Extract to: data/external/lid_ds/"
        echo ""
        echo "Option 2: Use ADFA-LD (Alternative)"
        echo "  ADFA-LD is more readily available (see option 2)"
        echo ""
        read -p "Have you downloaded and extracted LID-DS 2021? (y/n): " downloaded
        
        if [ "$downloaded" != "y" ]; then
            echo ""
            echo "Please download LID-DS 2021 manually first."
            echo "Or choose option 2 for ADFA-LD which is easier to get."
            exit 1
        fi
        
        if [ ! -d "lid_ds" ]; then
            echo "Error: lid_ds directory not found in data/external/"
            echo "Please extract LID-DS 2021 dataset to data/external/lid_ds/"
            exit 1
        fi
        
        echo "✅ LID-DS 2021 dataset found!"
        DATASET_PATH="lid_ds"
        ;;
    
    2)
        echo ""
        echo "ADFA-LD Dataset Download"
        echo "Paper: Creech & Hu, IEEE TIFS 2014"
        echo ""
        echo "Downloading labeled ADFA-LD from GitHub (easier than official site)..."
        echo ""
        
        if [ ! -d "a-labelled-version-of-the-ADFA-LD-dataset" ]; then
            echo "Cloning ADFA-LD labeled version from GitHub..."
            git clone https://github.com/verazuo/a-labelled-version-of-the-ADFA-LD-dataset.git || {
                echo "Error: Failed to clone ADFA-LD dataset"
                echo ""
                echo "Manual download:"
                echo "1. Visit: https://github.com/verazuo/a-labelled-version-of-the-ADFA-LD-dataset"
                echo "2. Download as ZIP or clone"
                echo "3. Extract to: data/external/a-labelled-version-of-the-ADFA-LD-dataset/"
                exit 1
            }
        fi
        
        # Create symlink or copy to ADFA-LD name
        if [ ! -d "ADFA-LD" ] && [ -d "a-labelled-version-of-the-ADFA-LD-dataset" ]; then
            ln -s a-labelled-version-of-the-ADFA-LD-dataset ADFA-LD || {
                cp -r a-labelled-version-of-the-ADFA-LD-dataset ADFA-LD
            }
        fi
        
        if [ ! -d "ADFA-LD" ]; then
            echo "Error: ADFA-LD directory not found"
            exit 1
        fi
        
        echo "✅ ADFA-LD dataset ready!"
        DATASET_PATH="ADFA-LD"
        ;;
    
    *)
        echo "Invalid choice"
        exit 1
        ;;
esac

cd ../../

echo ""
echo "=========================================="
echo "Dataset downloaded successfully!"
echo "Location: data/external/$DATASET_PATH"
echo "=========================================="
echo ""
echo "Next step: Convert dataset to H-SOAR format"
echo "Run: python scripts/convert_paper_dataset.py data/external/$DATASET_PATH data/training_dataset.csv"

