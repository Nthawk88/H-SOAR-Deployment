#!/bin/bash
# Quick script to check LID-DS dataset structure

echo "Checking CVE-2020-23839 dataset structure..."
echo ""

cd data/external/lid_ds_new/CVE-2020-23839

echo "Top-level directories:"
ls -d */

echo ""
echo "Checking for training/test/validation folders:"
for dir in training test validation; do
    if [ -d "$dir" ]; then
        echo "  ✅ Found $dir/"
        echo "    Files: $(find $dir -type f | wc -l)"
        echo "    ZIP files: $(find $dir -name "*.zip" | wc -l)"
        echo "    .sc files: $(find $dir -name "*.sc" | wc -l)"
        echo "    .json files: $(find $dir -name "*.json" | wc -l)"
    fi
done

echo ""
echo "Sample files:"
find . -name "*.zip" | head -3
find . -name "*.sc" | head -3
find . -name "*.json" | head -3

