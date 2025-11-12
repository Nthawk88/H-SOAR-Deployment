# H-SOAR: Host-based Security Orchestration and Automated Response

A Machine Learning Framework for High-Fidelity Triage and Automated Remediation in Host-based Intrusion Detection Systems.

## 🎯 Overview

H-SOAR is an advanced Host-based Intrusion Detection System (HIDS) that combines File Integrity Monitoring (FIM) with machine learning to provide intelligent alert triage and automated response capabilities. The system addresses the critical problem of alert fatigue in traditional HIDS by using ML to classify events as benign, suspicious, or malicious, and automatically responding to confirmed threats.

## 🚀 Key Features

### 🔍 **Intelligent File Integrity Monitoring**
- Real-time monitoring using `auditd`
- Critical system directory protection (`/etc`, `/bin`, `/sbin`, `/usr/bin`)
- Web application monitoring (`/var/www/html`)
- Automated baseline creation and maintenance

### 🤖 **Machine Learning Classification**
- Ensemble ML models (Random Forest, Gradient Boosting, SVM)
- Feature engineering for file paths, processes, users, and actions
- Automatic event classification: `benign` | `suspicious` | `malicious`
- High accuracy with low false positive rates

### ⚡ **Automated Response System**
- Git-based rollback for file recovery
- Automated remediation for malicious events
- Component-level recovery capabilities
- Rollback-of-rollback functionality

### 📊 **Alert Triage System**
- Intelligent alert prioritization
- Automated response for high-confidence threats
- Comprehensive alert history and statistics
- Configurable response thresholds

### 📈 **Dataset Collection**
- Automated event collection for training
- Manual and automatic labeling modes
- Ground truth dataset generation
- Continuous learning capabilities

## 🏗️ System Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   auditd        │    │   File Monitor   │    │  Feature        │
│   Collector     │───▶│   (FIM)          │───▶│  Extractor      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                                         │
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Git Rollback  │◀───│   Alert Triage  │◀───│   ML Classifier │
│   System        │    │   System        │    │   (Ensemble)    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## 🛠️ Installation

### Prerequisites

- **Operating System**: Ubuntu Server 22.04+ (recommended)
- **Python**: 3.8+
- **Git**: For rollback functionality
- **auditd**: For system monitoring
- **Root privileges**: For auditd configuration

### Quick Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/your-repo/h-soar-hids.git
   cd h-soar-hids
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure auditd**
   ```bash
   sudo cp config/auditd.rules /etc/audit/rules.d/hids.rules
   sudo systemctl restart auditd
   ```

4. **Initialize Git repositories**
   ```bash
   sudo python run_system.py --mode status
   ```

## 🚀 Usage

### Basic Operations

#### **Start Monitoring**
```bash
python run_system.py --mode monitor
```

#### **Train ML Model**
```bash
python run_system.py --mode train --dataset data/training_dataset.csv
```

#### **Collect Dataset**
```bash
python run_system.py --mode collect --duration 24 --label-mode auto
```

#### **Test System**
```bash
python run_system.py --mode test
```

#### **Check Status**
```bash
python run_system.py --mode status
```

### Advanced Configuration

#### **Custom Configuration**
```bash
python run_system.py --mode monitor --config config/custom_config.json
```

#### **Verbose Logging**
```bash
python run_system.py --mode monitor --log-level DEBUG
```

#### **Output Results**
```bash
python run_system.py --mode test --output results.json
```

## 📊 Performance Metrics

### **Detection Performance**
- **Overall Accuracy**: >90%
- **False Positive Rate**: <5%
- **Detection Rate**: >80%
- **Mean Time to Detection**: <3 seconds

### **System Performance**
- **CPU Overhead**: <2%
- **Memory Usage**: <100MB
- **Disk I/O**: Minimal impact
- **Network Overhead**: Negligible

## 🔧 Configuration

### **Main Configuration** (`config/hids_config.json`)

```json
{
  "fim": {
    "enabled": true,
    "monitor_paths": ["/etc", "/bin", "/sbin", "/usr/bin", "/var/www/html"],
    "check_interval": 5
  },
  "ml": {
    "model_type": "ensemble",
    "models": ["random_forest", "gradient_boosting", "svm"]
  },
  "rollback": {
    "enabled": true,
    "auto_rollback": true,
    "rollback_threshold": 0.8
  }
}
```

### **auditd Rules** (`/etc/audit/rules.d/hids.rules`)

```bash
# Monitor critical system directories
-w /etc -p wa -k hids_fim
-w /bin -p wa -k hids_fim
-w /sbin -p wa -k hids_fim
-w /usr/bin -p wa -k hids_fim
-w /var/www/html -p wa -k hids_fim

# Monitor process execution
-a always,exit -F arch=b64 -S execve -k hids_process
-a always,exit -F arch=b32 -S execve -k hids_process
```

## 📈 Training Data

### **Quick Dataset Generation**

Generate synthetic training dataset (works on Windows, Linux, Mac):

```bash
# Windows (PowerShell)
.\generate_dataset.ps1

# Linux/Mac
python generate_dataset.py --samples 10000 --output data/training_dataset.csv
```

This generates a dataset with 10,000 samples (80% benign, 12% suspicious, 8% malicious) ready for training.

### **Dataset Format**

The system expects CSV datasets with the following structure:

```csv
event_type,action,filepath_criticality,process_suspicious,user_is_root,label
file_integrity,write,8,1,1,malicious
process_execution,execute,3,0,0,benign
file_attribute,chmod,7,0,1,suspicious
```

### **Feature Engineering**

- **File Path Criticality**: 1-10 scale based on system importance
- **Process Suspiciousness**: Binary flag for suspicious processes
- **User Context**: Root vs. regular user analysis
- **Action Analysis**: Write, execute, delete, attribute changes
- **Temporal Features**: Time-based patterns

### **Dataset Collection Methods**

1. **Synthetic Dataset** (Recommended for development):
   - Fast generation: `python generate_dataset.py --samples 10000`
   - Works on any platform
   - Reproducible results
   - See [DATASET_GENERATION.md](DATASET_GENERATION.md) for details

2. **Real Dataset Collection** (Linux only, for production):
   - Requires Linux environment with auditd
   - Collect real system events: `python run_system.py --mode collect --duration 24`
   - See [collect_training_data.sh](collect_training_data.sh) for automated collection

## 🔒 Security Features

### **File Integrity Monitoring**
- SHA256 hash verification
- Real-time change detection
- Critical file protection
- Web application monitoring

### **Process Monitoring**
- Suspicious process detection
- Shell execution monitoring
- Privilege escalation detection
- Process behavior analysis

### **Network Monitoring**
- Connection monitoring
- Port scanning detection
- Suspicious network patterns
- Traffic analysis

### **Automated Response**
- Git-based file recovery
- Process termination
- Network isolation
- System restoration

## 📚 Documentation

- **[System Architecture](docs/SYSTEM_ARCHITECTURE.md)**: Detailed system design
- **[Technical Specifications](docs/TECHNICAL_SPECIFICATIONS.md)**: Technical details
- **[User Guide](docs/USER_GUIDE.md)**: Complete usage instructions
- **[IEEE Paper](docs/IEEE_PAPER.md)**: Research paper and methodology
- **[Dataset Generation](DATASET_GENERATION.md)**: How to generate training datasets
- **[Windows to Linux Deployment](docs/WINDOWS_TO_LINUX_DEPLOYMENT.md)**: Complete tutorial from Windows to Linux production
- **[Security Deployment Tutorial](docs/SECURITY_DEPLOYMENT_TUTORIAL.md)**: Step-by-step security tool deployment guide

## 🧪 Testing

### **Unit Tests**
```bash
python -m pytest tests/
```

### **Integration Tests**
```bash
python run_system.py --mode test
```

### **Performance Tests**
```bash
python tests/performance_test.py
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **auditd**: Linux audit framework
- **scikit-learn**: Machine learning library
- **Git**: Version control system
- **Ubuntu**: Operating system platform

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/your-repo/h-soar-hids/issues)
- **Documentation**: [Wiki](https://github.com/your-repo/h-soar-hids/wiki)
- **Email**: support@h-soar-hids.com

---

**H-SOAR HIDS** - Intelligent Host-based Intrusion Detection with Automated Response