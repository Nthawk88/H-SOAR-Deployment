#!/usr/bin/env python3
"""
H-SOAR: A Machine Learning Framework for High-Fidelity Triage and 
Automated Remediation in Host-Based Intrusion Detection

Main system orchestrator for HIDS with FIM capabilities.
"""

import os
import sys
import json
import logging
import argparse
from pathlib import Path
from typing import Dict, Any, List, Optional

# Suppress TensorFlow logging
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
import warnings
warnings.filterwarnings('ignore')

try:
    import tensorflow as tf
    tf.get_logger().setLevel('ERROR')
    tf.autograph.set_verbosity(0)
except ImportError:
    pass

# Import HIDS components
from src.hids.file_monitor import FileIntegrityMonitor
from src.hids.auditd_collector import AuditdCollector
from src.hids.feature_extractor import HIDSFeatureExtractor
from src.hids.ml_classifier import HIDSMLClassifier
from src.hids.git_rollback import GitRollbackSystem
from src.hids.alert_triage import AlertTriageSystem
from src.hids.dataset_collector import DatasetCollector

class HSOARSystem:
    """
    H-SOAR: Host-based Security Orchestration and Automated Response
    Main system class for HIDS with FIM capabilities
    """
    
    def __init__(self, config_path: str = "config/hids_config.json"):
        """Initialize H-SOAR system"""
        self.config_path = config_path
        self.config = self._load_config()
        self.logger = self._setup_logging()
        
        # Initialize components
        self.file_monitor = FileIntegrityMonitor(self.config.get('fim', {}))
        self.auditd_collector = AuditdCollector(self.config.get('auditd', {}))
        self.feature_extractor = HIDSFeatureExtractor(self.config.get('features', {}))
        self.ml_classifier = HIDSMLClassifier(self.config.get('ml', {}))
        self.git_rollback = GitRollbackSystem(self.config.get('rollback', {}))
        self.alert_triage = AlertTriageSystem(self.config.get('triage', {}))
        self.dataset_collector = DatasetCollector(self.config.get('dataset', {}))
        
        self.is_running = False
        self.logger.info("H-SOAR system initialized successfully")
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file"""
        try:
            with open(self.config_path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            self.logger.warning(f"Config file {self.config_path} not found, using defaults")
            return self._get_default_config()
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration"""
        return {
            "fim": {
                "enabled": True,
                "monitor_paths": ["/etc", "/bin", "/sbin", "/usr/bin", "/var/www/html"],
                "exclude_patterns": ["*.log", "*.tmp", "/tmp/*"],
                "check_interval": 5
            },
            "auditd": {
                "enabled": True,
                "rules_file": "/etc/audit/rules.d/hids.rules",
                "log_file": "/var/log/audit/audit.log"
            },
            "features": {
                "filepath_criticality": True,
                "process_analysis": True,
                "user_context": True,
                "file_attributes": True,
                "temporal_features": True
            },
            "ml": {
                "model_type": "ensemble",
                "models": ["random_forest", "gradient_boosting", "svm"],
                "training_data_path": "data/training_dataset.csv",
                "model_save_path": "models/hids_classifier.pkl"
            },
            "rollback": {
                "enabled": True,
                "git_repos": {
                    "/etc": "git@localhost:/etc.git",
                    "/var/www/html": "git@localhost:/var/www.git"
                },
                "auto_rollback": True,
                "rollback_threshold": 0.8
            },
            "triage": {
                "enabled": True,
                "alert_categories": ["benign", "suspicious", "malicious"],
                "auto_response": True,
                "response_threshold": 0.9
            },
            "dataset": {
                "collection_enabled": False,
                "output_path": "data/collected_events.csv",
                "labeling_mode": "manual"
            }
        }
    
    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration"""
        logger = logging.getLogger('HSOAR')
        logger.setLevel(logging.INFO)
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        
        return logger
    
    def start_monitoring(self):
        """Start HIDS monitoring"""
        self.logger.info("Starting H-SOAR monitoring...")
        self.is_running = True
        
        try:
            # Start auditd collection
            if self.config.get('auditd', {}).get('enabled', True):
                self.auditd_collector.start_collection()
            
            # Start file monitoring
            if self.config.get('fim', {}).get('enabled', True):
                self.file_monitor.start_monitoring()
            
            # Main monitoring loop
            while self.is_running:
                try:
                    # Collect events from auditd
                    events = self.auditd_collector.get_latest_events()
                    
                    for event in events:
                        # Extract features
                        features = self.feature_extractor.extract_features(event)
                        
                        # Classify event
                        classification = self.ml_classifier.classify(features)
                        
                        # Triage alert
                        triage_result = self.alert_triage.triage_alert(event, classification)
                        
                        # Auto-response if malicious
                        if triage_result.get('category') == 'malicious':
                            self._handle_malicious_event(event, triage_result)
                    
                    # Sleep for monitoring interval
                    import time
                    time.sleep(self.config.get('fim', {}).get('check_interval', 5))
                    
                except KeyboardInterrupt:
                    self.logger.info("Monitoring stopped by user")
                    break
                except Exception as e:
                    self.logger.error(f"Error in monitoring loop: {e}")
                    continue
        
        except Exception as e:
            self.logger.error(f"Failed to start monitoring: {e}")
        finally:
            self.stop_monitoring()
    
    def _handle_malicious_event(self, event: Dict[str, Any], triage_result: Dict[str, Any]):
        """Handle malicious event with automated response"""
        self.logger.warning(f"Malicious event detected: {event.get('filepath', 'unknown')}")
        
        # Log the event
        self.logger.info(f"Event details: {json.dumps(event, indent=2)}")
        self.logger.info(f"Triage result: {json.dumps(triage_result, indent=2)}")
        
        # Execute rollback if enabled
        if self.config.get('rollback', {}).get('enabled', True):
            rollback_result = self.git_rollback.execute_rollback(event)
            if rollback_result.get('success'):
                self.logger.info(f"Rollback successful: {rollback_result.get('message')}")
            else:
                self.logger.error(f"Rollback failed: {rollback_result.get('error')}")
    
    def stop_monitoring(self):
        """Stop HIDS monitoring"""
        self.logger.info("Stopping H-SOAR monitoring...")
        self.is_running = False
        
        # Stop components
        if hasattr(self.auditd_collector, 'stop_collection'):
            self.auditd_collector.stop_collection()
        
        if hasattr(self.file_monitor, 'stop_monitoring'):
            self.file_monitor.stop_monitoring()
    
    def train_model(self, dataset_path: str = None):
        """Train ML model for event classification"""
        self.logger.info("Training HIDS ML model...")
        
        try:
            # Use provided dataset or default
            if dataset_path is None:
                dataset_path = self.config.get('ml', {}).get('training_data_path', 'data/training_dataset.csv')
            
            # Train the model
            training_result = self.ml_classifier.train(dataset_path)
            
            if training_result.get('success'):
                self.logger.info("Model training completed successfully")
                self.logger.info(f"Accuracy: {training_result.get('accuracy', 0):.3f}")
                self.logger.info(f"Precision: {training_result.get('precision', 0):.3f}")
                self.logger.info(f"Recall: {training_result.get('recall', 0):.3f}")
                self.logger.info(f"F1-Score: {training_result.get('f1_score', 0):.3f}")
            else:
                self.logger.error(f"Model training failed: {training_result.get('error')}")
        
        except Exception as e:
            self.logger.error(f"Error during model training: {e}")
    
    def collect_dataset(self, duration_hours: int = 24, label_mode: str = "manual"):
        """Collect dataset for training"""
        self.logger.info(f"Starting dataset collection for {duration_hours} hours...")
        
        try:
            # Configure dataset collection
            self.dataset_collector.configure_collection(
                duration_hours=duration_hours,
                label_mode=label_mode
            )
            
            # Start collection
            collection_result = self.dataset_collector.start_collection()
            
            if collection_result.get('success'):
                self.logger.info("Dataset collection started successfully")
                self.logger.info(f"Output path: {collection_result.get('output_path')}")
            else:
                self.logger.error(f"Dataset collection failed: {collection_result.get('error')}")
        
        except Exception as e:
            self.logger.error(f"Error during dataset collection: {e}")
    
    def get_system_status(self) -> Dict[str, Any]:
        """Get system status"""
        return {
            "system_name": "H-SOAR",
            "version": "1.0.0",
            "status": "running" if self.is_running else "stopped",
            "components": {
                "file_monitor": self.file_monitor.get_status(),
                "auditd_collector": self.auditd_collector.get_status(),
                "ml_classifier": self.ml_classifier.get_status(),
                "git_rollback": self.git_rollback.get_status(),
                "alert_triage": self.alert_triage.get_status()
            },
            "config": {
                "fim_enabled": self.config.get('fim', {}).get('enabled', False),
                "auditd_enabled": self.config.get('auditd', {}).get('enabled', False),
                "rollback_enabled": self.config.get('rollback', {}).get('enabled', False),
                "triage_enabled": self.config.get('triage', {}).get('enabled', False)
            }
        }
    
    def run_system_test(self) -> Dict[str, Any]:
        """Run comprehensive system test"""
        self.logger.info("Running H-SOAR system test...")
        
        test_results = {
            "file_monitoring": False,
            "auditd_collection": False,
            "feature_extraction": False,
            "ml_classification": False,
            "rollback_system": False,
            "alert_triage": False,
            "overall_status": "FAILED"
        }
        
        try:
            # Test file monitoring
            self.logger.info("Testing file monitoring...")
            fim_status = self.file_monitor.get_status()
            test_results["file_monitoring"] = fim_status.get('active', False)
            
            # Test auditd collection
            self.logger.info("Testing auditd collection...")
            auditd_status = self.auditd_collector.get_status()
            test_results["auditd_collection"] = auditd_status.get('active', False)
            
            # Test feature extraction
            self.logger.info("Testing feature extraction...")
            test_event = {
                "filepath": "/etc/passwd",
                "action": "modify",
                "process": "nano",
                "user": "root",
                "timestamp": "2024-01-01T00:00:00Z"
            }
            features = self.feature_extractor.extract_features(test_event)
            test_results["feature_extraction"] = len(features) > 0
            
            # Test ML classification
            self.logger.info("Testing ML classification...")
            ml_status = self.ml_classifier.get_status()
            test_results["ml_classification"] = ml_status.get('trained', False)
            
            # Test rollback system
            self.logger.info("Testing rollback system...")
            rollback_status = self.git_rollback.get_status()
            test_results["rollback_system"] = rollback_status.get('available', False)
            
            # Test alert triage
            self.logger.info("Testing alert triage...")
            triage_status = self.alert_triage.get_status()
            test_results["alert_triage"] = triage_status.get('active', False)
            
            # Calculate overall status
            core_tests = [
                test_results["file_monitoring"],
                test_results["auditd_collection"],
                test_results["feature_extraction"],
                test_results["ml_classification"]
            ]
            
            if all(core_tests):
                test_results["overall_status"] = "PASSED"
            else:
                test_results["overall_status"] = "FAILED"
            
            # Log results
            passed_tests = sum([1 for v in test_results.values() if v is True])
            total_tests = len(test_results) - 1  # Exclude overall_status
            
            self.logger.info(f"Test Results: {passed_tests}/{total_tests} passed")
            self.logger.info(f"Overall Status: {test_results['overall_status']}")
            
            return test_results
        
        except Exception as e:
            self.logger.error(f"System test failed: {e}")
            return {"error": str(e), "overall_status": "FAILED"}

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='H-SOAR: Host-based Security Orchestration and Automated Response')
    parser.add_argument('--mode', choices=['monitor', 'train', 'collect', 'test', 'status'], 
                       default='monitor', help='Operation mode')
    parser.add_argument('--config', default='config/hids_config.json', 
                       help='Configuration file path')
    parser.add_argument('--dataset', help='Dataset path for training')
    parser.add_argument('--duration', type=int, default=24, 
                       help='Dataset collection duration in hours')
    parser.add_argument('--label-mode', choices=['manual', 'auto'], default='manual',
                       help='Dataset labeling mode')
    
    args = parser.parse_args()
    
    try:
        # Initialize system
        system = HSOARSystem(args.config)
        
        if args.mode == 'monitor':
            print("=== H-SOAR MONITORING MODE ===")
            print("Starting Host-based Intrusion Detection System with FIM...")
            print("Press Ctrl+C to stop monitoring")
            print("=" * 50)
            system.start_monitoring()
        
        elif args.mode == 'train':
            print("=== H-SOAR TRAINING MODE ===")
            print("Training ML model for event classification...")
            system.train_model(args.dataset)
        
        elif args.mode == 'collect':
            print("=== H-SOAR DATASET COLLECTION MODE ===")
            print(f"Collecting dataset for {args.duration} hours...")
            system.collect_dataset(args.duration, args.label_mode)
        
        elif args.mode == 'test':
            print("=== H-SOAR SYSTEM TEST MODE ===")
            print("Running comprehensive system test...")
            results = system.run_system_test()
            print(f"Test Results: {results}")
        
        elif args.mode == 'status':
            print("=== H-SOAR SYSTEM STATUS ===")
            status = system.get_system_status()
            print(json.dumps(status, indent=2))
    
    except KeyboardInterrupt:
        print("\nSystem stopped by user")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()