#!/bin/bash
# H-SOAR HIDS Complete Execution Script
# Run all H-SOAR modes and operations

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
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

print_header "H-SOAR HIDS COMPLETE EXECUTION SCRIPT"
print_info "Running all H-SOAR modes and operations"

echo ""

# Function to run mode with error handling
run_mode() {
    local mode=$1
    local description=$2
    
    print_step "Running $mode mode: $description"
    
    if python run_system.py --mode $mode; then
        print_success "$mode mode completed successfully"
    else
        print_error "$mode mode failed"
        return 1
    fi
    
    echo ""
}

# Step 1: System Status
run_mode "status" "Check H-SOAR system status and component health"

# Step 2: System Test
run_mode "test" "Run comprehensive system test"

# Step 3: Check if training data exists
print_step "Checking training data availability"
if [ -f "data/training_dataset.csv" ]; then
    print_success "Training dataset found"
    
    # Step 4: Train Models
    run_mode "train" "Train ML models with available dataset"
else
    print_warning "Training dataset not found"
    print_info "Skipping training mode"
    echo ""
fi

# Step 5: Check if collection is needed
print_step "Checking data collection status"
if [ ! -f "data/training_dataset.csv" ]; then
    print_warning "No training data available"
    print_info "Starting data collection..."
    
    # Collect training data
    print_info "Collecting training data for 1 hour..."
    python run_system.py --mode collect --duration 1 --label-mode auto &
    COLLECTION_PID=$!
    
    print_info "Data collection started (PID: $COLLECTION_PID)"
    print_info "Collection will run for 1 hour in background"
    
    # Wait a bit for collection to start
    sleep 10
    
    print_info "Collection is running in background. You can continue with other operations."
else
    print_success "Training data is available"
fi

echo ""

# Step 6: Interactive Mode Selection
print_step "Interactive Mode Selection"
print_info "Choose what you want to do next:"

echo "1. Start Monitoring (Real-time HIDS monitoring)"
echo "2. Run Demo (Complete demonstration)"
echo "3. Collect Training Data (Data collection for ML)"
echo "4. Train Models (Train ML models)"
echo "5. System Status (Check system status)"
echo "6. System Test (Run comprehensive test)"
echo "7. Exit"

read -p "Enter your choice (1-7): " choice

case $choice in
    1)
        print_step "Starting H-SOAR Monitoring"
        print_info "Starting real-time HIDS monitoring..."
        print_warning "Press Ctrl+C to stop monitoring"
        echo ""
        python run_system.py --mode monitor
        ;;
    2)
        print_step "Running H-SOAR Demo"
        print_info "Starting comprehensive demonstration..."
        ./demo_hsoar.sh
        ;;
    3)
        print_step "Collecting Training Data"
        print_info "Starting training data collection..."
        ./collect_training_data.sh
        ;;
    4)
        print_step "Training ML Models"
        print_info "Training ML models..."
        python run_system.py --mode train
        ;;
    5)
        print_step "System Status Check"
        print_info "Checking system status..."
        python run_system.py --mode status
        ;;
    6)
        print_step "System Test"
        print_info "Running system test..."
        python run_system.py --mode test
        ;;
    7)
        print_info "Exiting..."
        exit 0
        ;;
    *)
        print_error "Invalid choice. Please run the script again."
        exit 1
        ;;
esac

echo ""

# Step 7: Final Status Check
print_step "Final Status Check"
print_info "Checking final system status..."

python run_system.py --mode status

echo ""

# Step 8: Generate Execution Report
print_step "Generating Execution Report"
print_info "Creating execution report..."

cat > execution_report.txt << EOF
H-SOAR HIDS EXECUTION REPORT
Generated: $(date)

EXECUTION SUMMARY:
- Script: run_all_modes.sh
- Python Version: $(python --version)
- Ubuntu Version: $(lsb_release -rs)
- Virtual Environment: $VIRTUAL_ENV

MODES EXECUTED:
1. Status Mode: System status check
2. Test Mode: Comprehensive system test
3. Training Mode: ML model training (if data available)
4. Collection Mode: Data collection (if needed)
5. Interactive Mode: User-selected operation

SYSTEM STATUS:
$(python run_system.py --mode status | grep -A 20 "COMPONENT STATUS")

TEST RESULTS:
$(python run_system.py --mode test | grep -A 10 "TEST RESULTS")

FILES GENERATED:
- execution_report.txt - This report
- logs/ - System logs
- data/ - Training data (if collected)
- models/ - ML models (if trained)

NEXT STEPS:
1. Review execution_report.txt for detailed results
2. Check logs/ directory for detailed logs
3. Run 'python run_system.py --mode monitor' for continuous monitoring
4. Use './demo_hsoar.sh' for demonstrations

CONCLUSION:
H-SOAR HIDS execution completed successfully.
System is ready for production monitoring.
EOF

print_success "Execution report generated: execution_report.txt"

echo ""

# Step 9: Final Summary
print_step "Execution Summary"
print_header "H-SOAR HIDS EXECUTION COMPLETED"

print_success "Execution Results:"
echo "✓ System status checked"
echo "✓ System test completed"
echo "✓ Modes executed successfully"
echo "✓ Execution report generated"

echo ""

print_info "Generated Files:"
echo "• execution_report.txt - Complete execution report"
echo "• logs/ - System logs"
echo "• data/ - Training data (if collected)"
echo "• models/ - ML models (if trained)"

echo ""

print_info "Available Commands:"
echo "• python run_system.py --mode status - Check system status"
echo "• python run_system.py --mode test - Run system test"
echo "• python run_system.py --mode monitor - Start monitoring"
echo "• python run_system.py --mode train - Train ML models"
echo "• python run_system.py --mode collect - Collect training data"
echo "• ./demo_hsoar.sh - Run demonstration"
echo "• ./collect_training_data.sh - Collect training data"

echo ""

print_header "H-SOAR HIDS IS READY FOR PRODUCTION USE"

print_success "Execution completed successfully! H-SOAR HIDS is ready for production deployment."
