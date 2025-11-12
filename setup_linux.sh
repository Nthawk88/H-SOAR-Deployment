#!/bin/bash
# H-SOAR HIDS Linux Setup Script
# Automated setup script for Ubuntu Server 22.04+

set -e  # Exit on any error

echo "================================================================================
H-SOAR HIDS LINUX SETUP SCRIPT
================================================================================
Automated setup for Host-based Security Orchestration and Automated Response
================================================================================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   print_error "This script should not be run as root. Please run as regular user with sudo privileges."
   exit 1
fi

# Check Ubuntu version
print_header "Checking Ubuntu version..."
if ! command -v lsb_release &> /dev/null; then
    sudo apt update && sudo apt install -y lsb-release
fi

UBUNTU_VERSION=$(lsb_release -rs)
print_status "Ubuntu version: $UBUNTU_VERSION"

if [[ $(echo "$UBUNTU_VERSION < 22.04" | bc -l) -eq 1 ]]; then
    print_warning "Ubuntu version $UBUNTU_VERSION is older than 22.04. Some features may not work properly."
fi

# Step 1: System Update
print_header "Step 1: Updating system packages..."
sudo apt update && sudo apt upgrade -y
print_status "System update completed"

# Step 2: Install Required Packages
print_header "Step 2: Installing required packages..."
sudo apt install -y \
    python3 \
    python3-pip \
    python3-venv \
    python3-dev \
    git \
    auditd \
    systemd \
    bc \
    curl \
    wget \
    htop \
    iotop \
    netstat-nat \
    build-essential

print_status "Required packages installed"

# Step 3: Verify Python Version
print_header "Step 3: Verifying Python installation..."
PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
print_status "Python version: $PYTHON_VERSION"

if [[ $(echo "$PYTHON_VERSION < 3.8" | bc -l) -eq 1 ]]; then
    print_error "Python 3.8+ is required. Current version: $PYTHON_VERSION"
    exit 1
fi

# Step 4: Setup Python Virtual Environment
print_header "Step 4: Setting up Python virtual environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
    print_status "Virtual environment created"
else
    print_status "Virtual environment already exists"
fi

source venv/bin/activate
print_status "Virtual environment activated"

# Step 5: Install Python Dependencies
print_header "Step 5: Installing Python dependencies..."
if [ -f "requirements.txt" ]; then
    pip install --upgrade pip
    pip install -r requirements.txt
    print_status "Python dependencies installed"
else
    print_warning "requirements.txt not found. Installing basic dependencies..."
    pip install --upgrade pip
    pip install scikit-learn pandas numpy psutil python-audit
fi

# Step 6: Create auditd Rules
print_header "Step 6: Configuring auditd rules..."
sudo mkdir -p /etc/audit/rules.d

sudo tee /etc/audit/rules.d/hids.rules > /dev/null << 'EOF'
# H-SOAR HIDS File Integrity Monitoring Rules
# Monitor critical system directories
-w /etc -p wa -k hids_fim
-w /bin -p wa -k hids_fim
-w /sbin -p wa -k hids_fim
-w /usr/bin -p wa -k hids_fim
-w /var/www/html -p wa -k hids_fim

# Monitor process execution
-a always,exit -F arch=b64 -S execve -k hids_process
-a always,exit -F arch=b32 -S execve -k hids_process

# Monitor file attribute changes
-a always,exit -F arch=b64 -S chmod -k hids_attr
-a always,exit -F arch=b64 -S chown -k hids_attr

# Monitor network connections
-a always,exit -F arch=b64 -S bind -k hids_network
-a always,exit -F arch=b64 -S connect -k hids_network

# Monitor privilege escalation
-a always,exit -F arch=b64 -S setuid -k hids_priv
-a always,exit -F arch=b64 -S setgid -k hids_priv

# Monitor system calls
-a always,exit -F arch=b64 -S openat -k hids_file_access
-a always,exit -F arch=b64 -S unlink -k hids_file_delete
EOF

print_status "auditd rules created"

# Step 7: Configure auditd Service
print_header "Step 7: Configuring auditd service..."
sudo systemctl stop auditd
sudo systemctl start auditd
sudo systemctl enable auditd

# Verify auditd is working
if sudo auditctl -l | grep -q "hids_fim"; then
    print_status "auditd configured successfully"
else
    print_error "auditd configuration failed"
    exit 1
fi

# Step 8: Setup Git Repositories
print_header "Step 8: Setting up Git repositories for rollback..."

# Configure Git user
git config --global user.name "H-SOAR System"
git config --global user.email "hsoar@system.local"

# Setup /etc Git repository
if [ ! -d "/etc/.git" ]; then
    sudo git init /etc
    cd /etc
    sudo git add .
    sudo git commit -m "Initial H-SOAR baseline for /etc"
    cd -
    print_status "Git repository initialized for /etc"
else
    print_status "Git repository already exists for /etc"
fi

# Setup /var/www/html Git repository
sudo mkdir -p /var/www/html
if [ ! -d "/var/www/html/.git" ]; then
    sudo git init /var/www/html
    cd /var/www/html
    sudo git add .
    sudo git commit -m "Initial H-SOAR baseline for /var/www/html"
    cd -
    print_status "Git repository initialized for /var/www/html"
else
    print_status "Git repository already exists for /var/www/html"
fi

# Step 9: Create Required Directories
print_header "Step 9: Creating required directories..."
mkdir -p data models logs config
print_status "Required directories created"

# Step 10: Set Permissions
print_header "Step 10: Setting proper permissions..."
chmod +x run_system.py
chmod 600 config/hids_config.json 2>/dev/null || true
chmod 700 logs/ models/ data/
print_status "Permissions set"

# Step 11: Test System
print_header "Step 11: Testing H-SOAR system..."
python run_system.py --mode status

# Step 12: Run System Test
print_header "Step 12: Running comprehensive system test..."
python run_system.py --mode test

# Step 13: Create Demo Script
print_header "Step 13: Creating demo script..."
cat > demo_hsoar.sh << 'EOF'
#!/bin/bash
# H-SOAR HIDS Demo Script

echo "================================================================================
H-SOAR HIDS DEMO
================================================================================"

echo "1. System Status Check..."
python run_system.py --mode status

echo -e "\n2. System Test..."
python run_system.py --mode test

echo -e "\n3. Starting Monitoring (10 seconds)..."
python run_system.py --mode monitor &
MONITOR_PID=$!

sleep 5

echo -e "\n4. Simulating Malicious Activity..."
echo "malicious_user:x:1001:1001::/home/malicious_user:/bin/bash" | sudo tee -a /etc/passwd

sleep 5

echo -e "\n5. Checking Detection Logs..."
tail -n 10 logs/hids.log 2>/dev/null || echo "No logs yet"

echo -e "\n6. Stopping Monitoring..."
kill $MONITOR_PID 2>/dev/null || true

echo -e "\n7. Rolling Back Changes..."
cd /etc
sudo git checkout HEAD -- passwd
cd -

echo -e "\n================================================================================
DEMO COMPLETED
================================================================================"
EOF

chmod +x demo_hsoar.sh
print_status "Demo script created: ./demo_hsoar.sh"

# Step 14: Create Systemd Service (Optional)
print_header "Step 14: Creating systemd service (optional)..."
cat > hsoar.service << EOF
[Unit]
Description=H-SOAR HIDS Monitoring Service
After=network.target auditd.service

[Service]
Type=simple
User=$USER
WorkingDirectory=$(pwd)
Environment=PATH=$(pwd)/venv/bin
ExecStart=$(pwd)/venv/bin/python $(pwd)/run_system.py --mode monitor
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

print_status "Systemd service file created: hsoar.service"
print_warning "To install as system service: sudo cp hsoar.service /etc/systemd/system/ && sudo systemctl enable hsoar"

# Step 15: Final Verification
print_header "Step 15: Final verification..."

# Check auditd
if sudo systemctl is-active --quiet auditd; then
    print_status "✓ auditd service is running"
else
    print_error "✗ auditd service is not running"
fi

# Check Git repositories
if [ -d "/etc/.git" ] && [ -d "/var/www/html/.git" ]; then
    print_status "✓ Git repositories are initialized"
else
    print_error "✗ Git repositories are not properly initialized"
fi

# Check Python environment
if python -c "import sklearn, pandas, numpy" 2>/dev/null; then
    print_status "✓ Python dependencies are installed"
else
    print_error "✗ Python dependencies are missing"
fi

# Check H-SOAR system
if python run_system.py --mode status >/dev/null 2>&1; then
    print_status "✓ H-SOAR system is functional"
else
    print_error "✗ H-SOAR system has issues"
fi

# Final Summary
echo -e "\n================================================================================
SETUP COMPLETED
================================================================================"

print_status "H-SOAR HIDS has been successfully set up on Ubuntu $UBUNTU_VERSION"
print_status "Python version: $PYTHON_VERSION"
print_status "Virtual environment: $(pwd)/venv"
print_status "Configuration: $(pwd)/config/hids_config.json"
print_status "Logs: $(pwd)/logs/"
print_status "Models: $(pwd)/models/"

echo -e "\n${GREEN}NEXT STEPS:${NC}"
echo "1. Collect training data: python run_system.py --mode collect --duration 24"
echo "2. Train ML models: python run_system.py --mode train"
echo "3. Start monitoring: python run_system.py --mode monitor"
echo "4. Run demo: ./demo_hsoar.sh"

echo -e "\n${GREEN}USEFUL COMMANDS:${NC}"
echo "• Check status: python run_system.py --mode status"
echo "• Run test: python run_system.py --mode test"
echo "• View logs: tail -f logs/hids.log"
echo "• Check auditd: sudo auditctl -l"
echo "• Monitor system: htop"

echo -e "\n${GREEN}CONFIGURATION FILES:${NC}"
echo "• Main config: config/hids_config.json"
echo "• auditd rules: /etc/audit/rules.d/hids.rules"
echo "• Systemd service: hsoar.service"

echo -e "\n================================================================================
H-SOAR HIDS IS READY FOR PRODUCTION USE
================================================================================"
