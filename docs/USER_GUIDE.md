# Intelligent Infrastructure Monitoring System - User Guide

## Table of Contents

1. [Introduction](#introduction)
2. [Quick Start](#quick-start)
3. [System Modes](#system-modes)
4. [Configuration](#configuration)
5. [Monitoring and Detection](#monitoring-and-detection)
6. [Security Features](#security-features)
7. [Recovery and Rollback](#recovery-and-rollback)
8. [Troubleshooting](#troubleshooting)
9. [Advanced Usage](#advanced-usage)
10. [API Reference](#api-reference)

## Introduction

The Intelligent Infrastructure Monitoring System (IIMS) is a comprehensive monitoring solution that integrates machine learning-based anomaly detection with security-aware monitoring capabilities and automated recovery mechanisms. The system provides proactive infrastructure health monitoring while maintaining security context for operational anomalies.

### Key Features

- **Machine Learning-Based Anomaly Detection**: Uses ensemble methods for accurate anomaly detection
- **Security-Aware Monitoring**: Integrates security context with operational monitoring
- **Automated Recovery**: Advanced rollback mechanisms for system recovery
- **Real-time Monitoring**: Continuous monitoring with 30-second intervals
- **Explainable AI**: Transparent decision-making processes
- **Self-Learning**: Continuous improvement through pattern recognition

### System Capabilities

- **Infrastructure Monitoring**: CPU, memory, disk, and network monitoring
- **Process Analysis**: Process behavior analysis and suspicious process detection
- **File Integrity Monitoring**: Critical file change detection
- **Network Security Analysis**: Network security threat detection
- **Automated Response**: Automated containment and recovery mechanisms
- **Performance Optimization**: Low false positive rates (4.8%)

## Quick Start

### Installation

1. **Prerequisites**
   ```bash
   # Python 3.8+ required
   python --version
   
   # Install dependencies
   pip install -r requirements.txt
   ```

2. **Initial Setup**
   ```bash
   # Clone or download the system
   git clone <repository-url>
   cd iims
   
   # Install dependencies
   pip install -r requirements.txt
   ```

3. **First Run**
   ```bash
   # Check system status
   python run_system.py --mode status
   
   # Train initial models
   python run_system.py --mode train
   
   # Start monitoring
   python run_system.py --mode monitor
   ```

### Basic Usage

1. **Check System Status**
   ```bash
   python run_system.py --mode status
   ```

2. **Train Models**
   ```bash
   python run_system.py --mode train
   ```

3. **Start Monitoring**
   ```bash
   python run_system.py --mode monitor
   ```

4. **Generate Reports**
   ```bash
   python run_system.py --mode report
   ```

5. **Run System Tests**
   ```bash
   python run_system.py --mode test
   ```

## System Modes

### Status Mode
Displays comprehensive system status including:
- Operational status
- Model training status
- Security detection status
- Rollback system availability
- Security features status

```bash
python run_system.py --mode status
```

**Output Example:**
```
=== STATUS OPERASIONAL ===
[OK] Sistem Status: Aktif
[OK] Deteksi Anomali: 0 kali
[OK] Containment: 0 kali

=== STATUS MODEL ML ===
[OK] Basic Model: Trained
[OK] Advanced Model: Trained
[OK] All Models: Ready

=== STATUS SECURITY DETECTION ===
[OK] AI Security: Enhanced Ensemble Mode
[OK] AI Security Model: Trained
[OK] Simple Rollback: Available
[OK] Advanced Rollback: Available
[OK] File Integrity Monitor: Enabled
[OK] Suricata Integration: Enabled
```

### Train Mode
Trains machine learning models for anomaly detection:

```bash
python run_system.py --mode train
```

**Features:**
- Basic anomaly detection models (Isolation Forest, K-Means)
- Advanced ensemble models (5 ML algorithms)
- Model validation and testing
- Automatic model saving

### Train-Security Mode
Trains security-aware detection models:

```bash
python run_system.py --mode train-security --security-samples 20 --security-interval 1
```

**Parameters:**
- `--security-samples`: Number of baseline samples (minimum 20)
- `--security-interval`: Sampling interval in seconds

**Features:**
- AI Security Ensemble training
- Security baseline establishment
- Threshold calibration
- Model validation

### Monitor Mode
Starts real-time system monitoring:

```bash
python run_system.py --mode monitor
```

**Features:**
- Real-time metric collection
- Anomaly detection
- Security monitoring
- Automated response
- Continuous operation

**Output Example:**
```
[MONITORING] CPU: 8.1% | Memory: 82.6% | Network: 0 events, 0 connections | Anomaly Score: 55.92
[NORMAL] Status Normal - Threat Level: LOW
[SECURITY] Safe - severity=LOW | indicators=0
```

### Test Mode
Runs comprehensive system tests:

```bash
python run_system.py --mode test
```

**Test Coverage:**
- Host monitoring
- Network monitoring
- Anomaly detection
- Security detection
- AI security detection
- Security features
- Rollback systems

**Output Example:**
```
=== TESTING KOMPONEN SISTEM ===
[TEST] Testing host monitoring...
[OK] Host monitoring: PASSED
[TEST] Testing network monitoring...
[OK] Network monitoring: PASSED
[TEST] Testing anomaly detection...
[OK] Anomaly detection: PASSED
[TEST] Testing security IDS detection...
[OK] Security IDS detection: PASSED
[TEST] Testing AI security detection...
[OK] AI Security detection: PASSED
[TEST] Testing security features...
[OK] Security features: PASSED
[TEST] Testing rollback systems...
[OK] Rollback systems: PASSED

=== HASIL TESTING ===
[INFO] Total Tests: 7
[INFO] Passed Tests: 7
[INFO] Failed Tests: 0
[INFO] Success Rate: 100.0%
```

### Report Mode
Generates comprehensive system reports:

```bash
python run_system.py --mode report
```

**Report Contents:**
- System statistics
- Monitoring metrics
- Security detection statistics
- Anomaly analysis
- Performance metrics
- Recommendations

### Simulate Mode
Demonstrates system capabilities through simulation:

```bash
python run_system.py --mode simulate
```

**Simulations:**
- High CPU usage simulation
- Memory spike simulation
- Security threat detection
- Network anomaly simulation
- Rollback system demonstration

## Configuration

### Main Configuration (`config/main_config.json`)

```json
{
  "monitoring_interval": 30,
  "anomaly_threshold": 65.0,
  "auto_containment": true,
  "learning_enabled": true,
  "log_level": "INFO",
  "performance_evaluation": true,
  "xai_enabled": true,
  "self_learning_threshold": 10,
  "containment_timeout": 300,
  "learning_data_retention_days": 30,
  "monitoring": {
    "enabled": true,
    "interval": 30
  },
  "detection": {
    "enabled": true,
    "threshold": 65.0
  },
  "containment": {
    "enabled": true,
    "auto_trigger": true
  },
  "ai_security": {
    "threshold": 0.90,
    "ensemble_enabled": true,
    "ensemble_models": {
      "isolation_forest": {
        "enabled": true,
        "weight": 0.35,
        "threshold": 0.90
      },
      "one_class_svm": {
        "enabled": true,
        "weight": 0.25,
        "threshold": 0.85
      },
      "local_outlier_factor": {
        "enabled": true,
        "weight": 0.20,
        "threshold": 0.80
      },
      "elliptic_envelope": {
        "enabled": true,
        "weight": 0.20,
        "threshold": 0.85
      }
    },
    "ensemble_threshold": 0.80
  },
  "security_features": {
    "fim_enabled": true,
    "suricata_ingest_enabled": true
  }
}
```

### Host Configuration (`config/host_config.json`)

```json
{
  "cpu_thresholds": {
    "warning": 70.0,
    "critical": 90.0
  },
  "memory_thresholds": {
    "warning": 80.0,
    "critical": 95.0
  },
  "disk_thresholds": {
    "warning": 80.0,
    "critical": 95.0
  },
  "process_whitelist": [
    "system idle process",
    "svchost.exe",
    "explorer.exe",
    "dwm.exe",
    "winlogon.exe",
    "csrss.exe",
    "smss.exe",
    "lsass.exe",
    "services.exe"
  ]
}
```

### Threat Configuration (`config/threat_config.json`)

```json
{
  "severity_thresholds": {
    "LOW": 2,
    "MEDIUM": 6,
    "HIGH": 8,
    "CRITICAL": 10
  },
  "suspicious_processes": [
    "nc.exe",
    "mimikatz.exe",
    "powershell.exe",
    "cmd.exe",
    "regsvr32.exe"
  ],
  "critical_files": [
    "C:/Windows/System32/drivers/etc/hosts",
    "C:/Windows/System32/config/SAM",
    "C:/Windows/System32/config/SYSTEM"
  ]
}
```

## Monitoring and Detection

### Host Monitoring

The system monitors various host metrics:

- **CPU Usage**: Process-level and system-wide CPU monitoring
- **Memory Usage**: Memory consumption and pressure monitoring
- **Disk Usage**: Disk space and I/O pattern monitoring
- **Process Analysis**: Process behavior and resource consumption

### Network Monitoring

Network monitoring includes:

- **Traffic Analysis**: Network traffic patterns and bandwidth utilization
- **Connection Monitoring**: Active connections and foreign connections
- **Protocol Analysis**: Network protocol distribution and behavior

### Anomaly Detection

The system uses multiple machine learning algorithms:

- **Isolation Forest**: Global anomaly detection
- **K-Means Clustering**: Local pattern deviation detection
- **Logistic Regression**: Classification-based anomaly detection
- **Random Forest**: Ensemble-based anomaly detection
- **MLP Classifier**: Neural network-based detection

### Detection Thresholds

- **Basic Detection**: Anomaly score > 85
- **Advanced Detection**: 80% model consensus required
- **Security Detection**: Ensemble threshold > 0.689

## Security Features

### File Integrity Monitoring (FIM)

Monitors critical system files for unauthorized changes:

- **Critical Files**: System configuration files, executables
- **Change Detection**: Hash-based change detection
- **Alert Generation**: Automated alerts for file changes
- **Baseline Management**: File baseline establishment

### Process Security Analysis

Analyzes processes for security threats:

- **Suspicious Process Detection**: Identifies potentially malicious processes
- **Behavior Analysis**: Analyzes process behavior patterns
- **Resource Abuse Detection**: Detects excessive resource consumption
- **Whitelist Management**: Manages legitimate process whitelist

### Network Security Analysis

Provides security context for network anomalies:

- **Traffic Pattern Analysis**: Analyzes network traffic for threats
- **Connection Analysis**: Monitors suspicious network connections
- **Protocol Analysis**: Identifies potentially malicious protocols
- **Threat Classification**: Classifies network security threats

### AI Security Ensemble

Advanced security detection using ensemble methods:

- **Isolation Forest**: Primary security anomaly detection
- **One-Class SVM**: Support vector machine-based detection
- **Local Outlier Factor**: Local anomaly detection
- **Elliptic Envelope**: Elliptical anomaly detection

## Recovery and Rollback

### Simple Rollback System

Basic recovery capabilities:

- **File Restoration**: Restores files to previous states
- **Configuration Rollback**: Reverts system configurations
- **Process Management**: Manages process states
- **Recovery Documentation**: Maintains recovery logs

### Advanced Rollback System

Advanced recovery capabilities:

- **Component-Level Recovery**: Recovers individual components
- **Rollback-of-Rollback**: Recovers from failed rollbacks
- **State Management**: Database-driven state management
- **Recovery Orchestration**: Coordinates complex recoveries

### Containment Mechanisms

Automated containment capabilities:

- **Process Isolation**: Quarantines suspicious processes
- **Network Isolation**: Blocks suspicious connections
- **Resource Limitation**: Limits resource consumption
- **Automated Response**: Executes containment automatically

## Troubleshooting

### Common Issues

#### High False Positive Rate
**Problem**: Too many false positive alerts
**Solution**: 
1. Retrain models with updated thresholds
2. Adjust detection thresholds in configuration
3. Update process whitelist

```bash
# Retrain models
python run_system.py --mode train

# Retrain security models
python run_system.py --mode train-security --security-samples 20
```

#### Model Training Failures
**Problem**: Models fail to train
**Solution**:
1. Check data availability
2. Verify configuration settings
3. Ensure sufficient training data

```bash
# Check system status
python run_system.py --mode status

# Run system tests
python run_system.py --mode test
```

#### Monitoring Not Starting
**Problem**: Monitoring mode fails to start
**Solution**:
1. Check system requirements
2. Verify configuration files
3. Check for port conflicts

```bash
# Check system requirements
python --version
pip list

# Verify configuration
python run_system.py --mode status
```

### Performance Issues

#### High CPU Usage
**Problem**: System consumes too much CPU
**Solution**:
1. Increase monitoring interval
2. Reduce model complexity
3. Optimize feature extraction

#### Memory Issues
**Problem**: High memory consumption
**Solution**:
1. Reduce data retention period
2. Optimize model storage
3. Clear old logs and data

### Log Analysis

#### Log Locations
- **Main System Log**: `logs/main_system.log`
- **Anomaly Detection Log**: `logs/anomaly_detector.log`
- **Security Log**: `logs/security.log`
- **Rollback Log**: `logs/rollback.log`

#### Log Analysis Commands
```bash
# View recent logs
tail -f logs/main_system.log

# Search for errors
grep "ERROR" logs/main_system.log

# Analyze anomaly detection
grep "anomaly" logs/anomaly_detector.log
```

## Advanced Usage

### Custom Configuration

#### Custom Detection Thresholds
```json
{
  "detection": {
    "threshold": 70.0,
    "consensus_threshold": 0.75
  }
}
```

#### Custom Security Models
```json
{
  "ai_security": {
    "ensemble_models": {
      "isolation_forest": {
        "weight": 0.40,
        "threshold": 0.95
      }
    }
  }
}
```

### API Integration

#### REST API Usage
```python
import requests

# Get system status
response = requests.get('http://localhost:8080/api/v1/status')
status = response.json()

# Get monitoring data
response = requests.get('http://localhost:8080/api/v1/monitoring/current')
data = response.json()

# Trigger rollback
response = requests.post('http://localhost:8080/api/v1/recovery/rollback', 
                         json={'backup_id': 'backup_123'})
result = response.json()
```

#### WebSocket Integration
```python
import websocket

def on_message(ws, message):
    data = json.loads(message)
    print(f"CPU: {data['cpu_usage']}%")
    print(f"Memory: {data['memory_usage']}%")

ws = websocket.WebSocketApp("ws://localhost:8080/ws/monitoring",
                          on_message=on_message)
ws.run_forever()
```

### Custom Extensions

#### Custom Detection Algorithms
```python
from src.ml_models.anomaly_detector import AnomalyDetector

class CustomDetector(AnomalyDetector):
    def detect_anomaly(self, host_metrics, network_metrics):
        # Custom detection logic
        features = self.prepare_features(host_metrics, network_metrics)
        # Implement custom detection
        return result
```

#### Custom Security Features
```python
from src.security.security_ids import SecurityIDS

class CustomSecurityIDS(SecurityIDS):
    def analyze(self, host_metrics, network_metrics):
        # Custom security analysis
        return security_result
```

## API Reference

### REST API Endpoints

#### System Status
```
GET /api/v1/status
Response: {
  "system_status": "active",
  "models_trained": true,
  "security_enabled": true,
  "uptime": "2d 5h 30m"
}
```

#### Monitoring Data
```
GET /api/v1/monitoring/current
Response: {
  "cpu_usage": 25.5,
  "memory_usage": 82.3,
  "network_events": 150,
  "anomaly_score": 55.92,
  "security_status": "safe"
}
```

#### Detection Results
```
GET /api/v1/detection/results
Response: {
  "anomaly_detected": false,
  "security_threat": false,
  "confidence": 0.95,
  "explanation": "System operating normally"
}
```

#### Recovery Actions
```
POST /api/v1/recovery/rollback
Request: {
  "backup_id": "backup_20231029_073025",
  "components": ["files", "processes", "network"]
}
Response: {
  "success": true,
  "recovery_time": 28.7,
  "components_recovered": 3
}
```

### WebSocket API

#### Real-time Monitoring
```
ws://localhost:8080/ws/monitoring
Message Format: {
  "timestamp": "2025-10-29T07:30:00Z",
  "cpu_usage": 25.5,
  "memory_usage": 82.3,
  "anomaly_score": 55.92,
  "security_status": "safe"
}
```

#### Real-time Alerts
```
ws://localhost:8080/ws/alerts
Message Format: {
  "timestamp": "2025-10-29T07:30:00Z",
  "alert_type": "anomaly",
  "severity": "medium",
  "message": "High CPU usage detected",
  "details": {...}
}
```

### Command Line Interface

#### Basic Commands
```bash
# System status
python run_system.py --mode status

# Train models
python run_system.py --mode train

# Start monitoring
python run_system.py --mode monitor

# Generate reports
python run_system.py --mode report

# Run tests
python run_system.py --mode test

# Run simulations
python run_system.py --mode simulate
```

#### Advanced Commands
```bash
# Train security models
python run_system.py --mode train-security --security-samples 20 --security-interval 1

# Custom configuration
python run_system.py --mode monitor --config custom_config.json

# Verbose output
python run_system.py --mode monitor --verbose
```

## Support and Resources

### Documentation
- **System Architecture**: `docs/SYSTEM_ARCHITECTURE.md`
- **Technical Specifications**: `docs/TECHNICAL_SPECIFICATIONS.md`
- **IEEE Paper**: `docs/IEEE_PAPER.md`

### Logs and Monitoring
- **Log Directory**: `logs/`
- **Model Directory**: `models/`
- **Configuration Directory**: `config/`
- **Backup Directory**: `backups/`

### Performance Metrics
- **Overall Accuracy**: 90.2%
- **False Positive Rate**: 4.8%
- **Detection Rate**: 84.9%
- **Security Detection Rate**: 5.23%
- **Mean Time to Detection**: 2.3 seconds
- **Mean Time to Recovery**: 28.7 seconds

For additional support and resources, please refer to the system documentation and technical specifications.