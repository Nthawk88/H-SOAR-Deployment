#!/bin/bash
# Download additional real HIDS datasets from papers for H-SOAR training

set -e

echo "=========================================="
echo "H-SOAR Additional Dataset Downloader"
echo "=========================================="
echo ""

# Create data directory
mkdir -p data/external
cd data/external

echo "Available additional datasets:"
echo "1. LID-DS 2019 (FKIE-CAD) - Host-based, syscalls with parameters"
echo "2. UNSW-NB15 (UNSW Canberra) - Network+Host features"
echo "3. CIC-IDS2017 (University of New Brunswick) - Large dataset"
echo "4. ADFA-LD (UNSW Canberra) - Already have, skip"
echo "5. LID-DS 2021 (Zenodo) - Already have, skip"
echo ""

read -p "Choose dataset (1-3): " choice

case $choice in
    1)
        echo ""
        echo "LID-DS 2019 Dataset Download"
        echo "Paper: FKIE-CAD, Fraunhofer Institute"
        echo "Format: System calls with parameters"
        echo ""
        echo "⚠️  Manual download required"
        echo ""
        echo "Steps:"
        echo "1. Visit: https://fkie-cad.github.io/COMIDDS/content/datasets/lids_ds_2019/"
        echo "2. Download the dataset"
        echo "3. Extract to: data/external/lid_ds_2019/"
        echo ""
        read -p "Have you downloaded and extracted LID-DS 2019? (y/n): " downloaded
        
        if [ "$downloaded" != "y" ]; then
            echo ""
            echo "Please download LID-DS 2019 manually first."
            echo "Website: https://fkie-cad.github.io/COMIDDS/content/datasets/lids_ds_2019/"
            exit 1
        fi
        
        if [ ! -d "lid_ds_2019" ]; then
            echo "Error: lid_ds_2019 directory not found in data/external/"
            echo "Please extract LID-DS 2019 dataset to data/external/lid_ds_2019/"
            exit 1
        fi
        
        echo "✅ LID-DS 2019 dataset found!"
        DATASET_PATH="lid_ds_2019"
        ;;
    
    2)
        echo ""
        echo "UNSW-NB15 Dataset Download"
        echo "Paper: Moustafa & Slay, IEEE MILCOM 2015"
        echo ""
        echo "⚠️  Manual download required"
        echo ""
        echo "Steps:"
        echo "1. Visit: https://www.unsw.adfa.edu.au/unsw-canberra-cyber/cybersecurity/ADFA-NB15-Datasets/"
        echo "2. Download UNSW-NB15 dataset"
        echo "3. Extract to: data/external/unsw_nb15/"
        echo ""
        read -p "Have you downloaded and extracted UNSW-NB15? (y/n): " downloaded
        
        if [ "$downloaded" != "y" ]; then
            echo ""
            echo "Please download UNSW-NB15 manually first."
            echo "Website: https://www.unsw.adfa.edu.au/unsw-canberra-cyber/cybersecurity/ADFA-NB15-Datasets/"
            exit 1
        fi
        
        if [ ! -d "unsw_nb15" ]; then
            echo "Error: unsw_nb15 directory not found in data/external/"
            echo "Please extract UNSW-NB15 dataset to data/external/unsw_nb15/"
            exit 1
        fi
        
        echo "✅ UNSW-NB15 dataset found!"
        DATASET_PATH="unsw_nb15"
        ;;
    
    3)
        echo ""
        echo "CIC-IDS2017 Dataset Download"
        echo "Paper: Sharafaldin et al., ICISSP 2018"
        echo ""
        echo "⚠️  Large dataset (~2.5GB), manual download required"
        echo ""
        echo "Steps:"
        echo "1. Visit: https://www.unb.ca/cic/datasets/ids-2017.html"
        echo "2. Download CIC-IDS2017 dataset"
        echo "3. Extract to: data/external/cic_ids2017/"
        echo ""
        read -p "Have you downloaded and extracted CIC-IDS2017? (y/n): " downloaded
        
        if [ "$downloaded" != "y" ]; then
            echo ""
            echo "Please download CIC-IDS2017 manually first."
            echo "Website: https://www.unb.ca/cic/datasets/ids-2017.html"
            exit 1
        fi
        
        if [ ! -d "cic_ids2017" ]; then
            echo "Error: cic_ids2017 directory not found in data/external/"
            echo "Please extract CIC-IDS2017 dataset to data/external/cic_ids2017/"
            exit 1
        fi
        
        echo "✅ CIC-IDS2017 dataset found!"
        DATASET_PATH="cic_ids2017"
        ;;
    
    *)
        echo "Invalid choice"
        exit 1
        ;;
esac

cd ../../

echo ""
echo "=========================================="
echo "Dataset ready!"
echo "Location: data/external/$DATASET_PATH"
echo "=========================================="
echo ""
echo "Next step: Convert dataset to H-SOAR format"
echo "Run: python scripts/convert_paper_dataset.py data/external/$DATASET_PATH data/training_dataset_${DATASET_PATH}.csv"
echo ""
echo "Then merge with existing dataset:"
echo "python scripts/merge_datasets.py data/training_dataset.csv data/training_dataset_${DATASET_PATH}.csv data/training_dataset_merged.csv"

