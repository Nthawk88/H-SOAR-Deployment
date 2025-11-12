# H-SOAR HIDS Dataset Generation Guide

## Overview

This guide explains how to generate training datasets for H-SOAR HIDS ML models. The system includes a synthetic dataset generator that creates realistic training data based on the IEEE paper specifications.

## Quick Start

### Windows (PowerShell)

```powershell
# Run the PowerShell script
.\generate_dataset.ps1

# Or generate manually
python generate_dataset.py --samples 10000 --output data/training_dataset.csv
```

### Linux/Mac

```bash
# Make script executable
chmod +x generate_dataset.py

# Generate dataset
python generate_dataset.py --samples 10000 --output data/training_dataset.csv
```

## Dataset Specifications

### Default Configuration

- **Total Samples**: 10,000 events
- **Benign Events**: 80% (8,000 events)
- **Suspicious Events**: 12% (1,200 events)
- **Malicious Events**: 8% (800 events)
- **Features**: 23 features per event
- **Format**: CSV file

### Feature Set

The dataset includes 23 features:

1. **Event Type**: File integrity, process execution, file attribute, network, privilege
2. **Action**: Open, write, delete, execute, chmod, chown
3. **File Path Criticality**: 1-10 scale based on system importance
4. **File Path Depth**: Directory nesting level
5. **File Path Suspiciousness**: Pattern matching for suspicious names
6. **File Extension Suspiciousness**: Risk assessment of file types
7. **System Directory Flag**: Binary flag for system directories
8. **Web Directory Flag**: Binary flag for web directories
9. **Temp Directory Flag**: Binary flag for temporary directories
10. **Process Suspiciousness**: Binary flag for suspicious processes
11. **Shell Process Flag**: Binary flag for shell processes
12. **Web Server Process Flag**: Binary flag for web server processes
13. **System Process Flag**: Binary flag for system processes
14. **Process Name Length**: Length of process name
15. **Root User Flag**: Binary flag for root user
16. **System User Flag**: Binary flag for system users
17. **Web User Flag**: Binary flag for web users
18. **Write Action Flag**: Binary flag for write operations
19. **Delete Action Flag**: Binary flag for delete operations
20. **Execute Action Flag**: Binary flag for execute operations
21. **Attribute Action Flag**: Binary flag for attribute changes
22. **Hour of Day**: Temporal feature (0-23)
23. **Day of Week**: Temporal feature (0-6)

## Usage

### Basic Usage

```bash
# Generate default dataset (10,000 samples)
python generate_dataset.py --output data/training_dataset.csv

# Generate custom dataset
python generate_dataset.py --samples 5000 --benign-ratio 0.75 --suspicious-ratio 0.15 --malicious-ratio 0.10 --output data/training_dataset.csv
```

### Command Line Arguments

- `--samples`: Number of samples to generate (default: 10000)
- `--benign-ratio`: Ratio of benign events (default: 0.80)
- `--suspicious-ratio`: Ratio of suspicious events (default: 0.10)
- `--malicious-ratio`: Ratio of malicious events (default: 0.10)
- `--output`: Output CSV file path (default: data/training_dataset.csv)
- `--seed`: Random seed for reproducibility (default: 42)

### Examples

```bash
# Generate small dataset for testing (1,000 samples)
python generate_dataset.py --samples 1000 --output data/test_dataset.csv

# Generate large dataset for training (50,000 samples)
python generate_dataset.py --samples 50000 --output data/large_dataset.csv

# Generate balanced dataset (33% each class)
python generate_dataset.py --samples 9000 --benign-ratio 0.33 --suspicious-ratio 0.33 --malicious-ratio 0.34 --output data/balanced_dataset.csv

# Generate dataset with custom seed
python generate_dataset.py --samples 10000 --seed 123 --output data/training_dataset.csv
```

## Dataset Format

### CSV Structure

The generated CSV file has the following structure:

```csv
event_type,action,filepath_criticality,filepath_depth,...,label
1,4,5,4,...,benign
2,2,7,3,...,benign
1,2,9,3,...,malicious
```

### Label Values

- `benign`: Normal system activities
- `suspicious`: Potentially malicious activities
- `malicious`: Confirmed malicious activities

## Dataset Statistics

After generation, the script displays:

- Total samples count
- Label distribution (counts and percentages)
- Feature statistics (mean, std, min, max)
- File size

### Example Output

```
Dataset generated successfully!
Total samples: 10000
Features: 23

Label distribution:
  benign      :   8000 (80.00%)
  suspicious  :   1200 (12.00%)
  malicious   :    800 ( 8.00%)

Feature statistics:
  filepath_criticality: mean=5.53, std=2.27, min=1, max=10
  process_suspicious: mean=0.13, std=0.34, min=0, max=1
  ...
```

## Training with Generated Dataset

After generating the dataset, train the ML model:

```bash
# Train ML model
python run_system.py --mode train --dataset data/training_dataset.csv

# Check training status
python run_system.py --mode status

# Test system
python run_system.py --mode test
```

## Real Dataset Collection (Linux Only)

For production deployment, you should collect real data from a Linux system:

### Prerequisites

- Ubuntu Server 22.04+ (or similar Linux distribution)
- auditd installed and configured
- Root privileges
- Git repositories initialized for monitored directories

### Collection Process

1. **Setup auditd rules**:
   ```bash
   sudo cp config/auditd.rules /etc/audit/rules.d/hids.rules
   sudo systemctl restart auditd
   ```

2. **Collect benign events** (2+ hours):
   ```bash
   python run_system.py --mode collect --duration 2 --label-mode auto
   ```

3. **Collect malicious events** (simulated attacks):
   ```bash
   ./collect_training_data.sh
   ```

4. **Combine and train**:
   ```bash
   python run_system.py --mode train --dataset data/training_dataset.csv
   ```

## Dataset Quality

### Synthetic Dataset

- **Pros**: 
  - Fast generation
  - Reproducible
  - Works on any platform
  - Good for testing and development

- **Cons**:
  - May not capture all real-world patterns
  - Limited to predefined patterns
  - May have biases

### Real Dataset

- **Pros**:
  - Captures real-world patterns
  - More accurate for production
  - Includes edge cases

- **Cons**:
  - Requires Linux environment
  - Time-consuming collection
  - Requires manual labeling
  - May contain sensitive data

## Troubleshooting

### Common Issues

1. **Import Error**: Install required packages
   ```bash
   pip install pandas numpy
   ```

2. **Permission Error**: Check file permissions
   ```bash
   chmod 755 generate_dataset.py
   ```

3. **Memory Error**: Reduce sample size
   ```bash
   python generate_dataset.py --samples 1000
   ```

4. **Invalid Ratios**: Ensure ratios sum to 1.0
   ```bash
   # Correct
   --benign-ratio 0.80 --suspicious-ratio 0.10 --malicious-ratio 0.10
   ```

## Best Practices

1. **Use synthetic data for development**: Fast and reproducible
2. **Collect real data for production**: More accurate results
3. **Validate dataset**: Check label distribution and feature statistics
4. **Version control**: Save datasets with version numbers
5. **Documentation**: Record dataset generation parameters

## References

- [IEEE Paper](docs/IEEE_PAPER.md): Complete methodology
- [System Architecture](docs/SYSTEM_ARCHITECTURE.md): System design
- [User Guide](docs/USER_GUIDE.md): Complete usage instructions

## Support

For issues or questions:
- Check logs: `logs/hids.log`
- Review documentation: `docs/`
- Create issue: GitHub Issues

---

**H-SOAR HIDS Dataset Generation** - Synthetic dataset generation for ML model training


