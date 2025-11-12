#!/usr/bin/env python3
"""
Dataset Collector for H-SOAR HIDS
Collects and labels events for training dataset
"""

import os
import json
import logging
import csv
import pandas as pd
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
import threading
import time

class DatasetCollector:
    """
    Dataset collector for HIDS training data
    """
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize dataset collector"""
        self.config = config
        self.logger = logging.getLogger('DatasetCollector')
        
        # Configuration
        self.collection_enabled = config.get('collection_enabled', False)
        self.output_path = config.get('output_path', 'data/collected_events.csv')
        self.labeling_mode = config.get('labeling_mode', 'manual')
        
        # Collection state
        self.is_collecting = False
        self.collection_thread = None
        self.collected_events = []
        
        # Labeling rules for automatic labeling
        self.labeling_rules = self._load_labeling_rules()
        
        # Statistics
        self.stats = {
            'total_events': 0,
            'labeled_events': 0,
            'benign_events': 0,
            'suspicious_events': 0,
            'malicious_events': 0,
            'collection_start_time': None,
            'collection_duration': 0
        }
    
    def _load_labeling_rules(self) -> Dict[str, Any]:
        """Load automatic labeling rules"""
        return {
            'benign': {
                'conditions': [
                    {'filepath_criticality': {'max': 3}},
                    {'process_suspicious': {'max': 0}},
                    {'action_is_write': {'max': 0}},
                    {'user_is_root': {'max': 0}}
                ],
                'confidence': 0.8
            },
            'suspicious': {
                'conditions': [
                    {'filepath_criticality': {'min': 4, 'max': 7}},
                    {'process_suspicious': {'max': 1}},
                    {'action_is_write': {'max': 1}}
                ],
                'confidence': 0.6
            },
            'malicious': {
                'conditions': [
                    {'filepath_criticality': {'min': 8}},
                    {'process_suspicious': {'min': 1}},
                    {'action_is_write': {'min': 1}},
                    {'user_is_root': {'min': 1}}
                ],
                'confidence': 0.9
            }
        }
    
    def configure_collection(self, duration_hours: int = 24, label_mode: str = "manual"):
        """Configure dataset collection"""
        self.collection_duration = duration_hours
        self.labeling_mode = label_mode
        
        self.logger.info(f"Collection configured: {duration_hours} hours, {label_mode} labeling")
    
    def start_collection(self) -> Dict[str, Any]:
        """Start dataset collection"""
        try:
            if self.is_collecting:
                return {
                    'success': False,
                    'error': 'Collection already in progress'
                }
            
            # Create output directory
            os.makedirs(os.path.dirname(self.output_path), exist_ok=True)
            
            # Initialize collection
            self.is_collecting = True
            self.collected_events = []
            self.stats['collection_start_time'] = datetime.now()
            
            # Start collection thread
            self.collection_thread = threading.Thread(target=self._collect_events)
            self.collection_thread.daemon = True
            self.collection_thread.start()
            
            self.logger.info("Dataset collection started")
            
            return {
                'success': True,
                'message': 'Dataset collection started',
                'output_path': self.output_path,
                'duration_hours': self.collection_duration,
                'labeling_mode': self.labeling_mode
            }
        
        except Exception as e:
            self.logger.error(f"Error starting collection: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def stop_collection(self) -> Dict[str, Any]:
        """Stop dataset collection"""
        try:
            if not self.is_collecting:
                return {
                    'success': False,
                    'error': 'Collection not in progress'
                }
            
            # Stop collection
            self.is_collecting = False
            
            if self.collection_thread:
                self.collection_thread.join(timeout=5)
            
            # Calculate collection duration
            if self.stats['collection_start_time']:
                self.stats['collection_duration'] = (datetime.now() - self.stats['collection_start_time']).total_seconds()
            
            # Save collected data
            self._save_collected_data()
            
            self.logger.info("Dataset collection stopped")
            
            return {
                'success': True,
                'message': 'Dataset collection stopped',
                'events_collected': len(self.collected_events),
                'duration_seconds': self.stats['collection_duration']
            }
        
        except Exception as e:
            self.logger.error(f"Error stopping collection: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _collect_events(self):
        """Main event collection loop"""
        try:
            end_time = datetime.now() + timedelta(hours=self.collection_duration)
            
            while self.is_collecting and datetime.now() < end_time:
                # Simulate event collection (in real implementation, this would collect from auditd)
                event = self._simulate_event_collection()
                
                if event:
                    # Label event
                    labeled_event = self._label_event(event)
                    
                    # Add to collection
                    self.collected_events.append(labeled_event)
                    self.stats['total_events'] += 1
                    
                    if labeled_event.get('label'):
                        self.stats['labeled_events'] += 1
                        label = labeled_event['label']
                        self.stats[f'{label}_events'] += 1
                
                # Sleep for collection interval
                time.sleep(1)
            
            # Collection completed
            self.is_collecting = False
            
        except Exception as e:
            self.logger.error(f"Error in collection loop: {e}")
            self.is_collecting = False
    
    def _simulate_event_collection(self) -> Optional[Dict[str, Any]]:
        """Simulate event collection (placeholder for real implementation)"""
        # This is a placeholder - in real implementation, this would collect from auditd
        import random
        
        # Simulate different types of events
        event_types = ['file_integrity', 'process_execution', 'file_attribute']
        actions = ['write', 'execute', 'chmod', 'chown', 'delete']
        processes = ['nano', 'vim', 'bash', 'python3', 'nginx', 'apache2', 'systemd']
        filepaths = ['/etc/passwd', '/etc/hosts', '/var/www/html/index.php', '/tmp/temp.txt', '/bin/ls']
        users = ['root', 'www-data', 'admin', 'user']
        
        # Generate random event
        event = {
            'timestamp': datetime.now().isoformat(),
            'event_type': random.choice(event_types),
            'action': random.choice(actions),
            'filepath': random.choice(filepaths),
            'process': random.choice(processes),
            'user': random.choice(users)
        }
        
        return event
    
    def _label_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Label event based on labeling mode"""
        labeled_event = event.copy()
        
        if self.labeling_mode == 'manual':
            # Manual labeling - require human input
            labeled_event['label'] = None
            labeled_event['labeling_method'] = 'manual'
            labeled_event['labeling_confidence'] = 0.0
        
        elif self.labeling_mode == 'auto':
            # Automatic labeling using rules
            label_result = self._auto_label_event(event)
            labeled_event['label'] = label_result.get('label', 'unknown')
            labeled_event['labeling_method'] = 'auto'
            labeled_event['labeling_confidence'] = label_result.get('confidence', 0.0)
        
        else:
            # Unknown labeling mode
            labeled_event['label'] = 'unknown'
            labeled_event['labeling_method'] = 'unknown'
            labeled_event['labeling_confidence'] = 0.0
        
        return labeled_event
    
    def _auto_label_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Automatically label event using rules"""
        try:
            # Extract features for labeling
            features = self._extract_labeling_features(event)
            
            # Apply labeling rules
            for label, rules in self.labeling_rules.items():
                if self._matches_labeling_rules(features, rules):
                    return {
                        'label': label,
                        'confidence': rules.get('confidence', 0.5)
                    }
            
            # Default to suspicious if no rules match
            return {
                'label': 'suspicious',
                'confidence': 0.3
            }
        
        except Exception as e:
            self.logger.error(f"Error in auto labeling: {e}")
            return {
                'label': 'unknown',
                'confidence': 0.0
            }
    
    def _extract_labeling_features(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Extract features for labeling"""
        features = {}
        
        # File path criticality
        filepath = event.get('filepath', '')
        features['filepath_criticality'] = self._calculate_filepath_criticality(filepath)
        
        # Process analysis
        process = event.get('process', '')
        features['process_suspicious'] = self._is_suspicious_process(process)
        
        # Action analysis
        action = event.get('action', '')
        features['action_is_write'] = 1 if action in ['write', 'create', 'modify'] else 0
        features['action_is_execute'] = 1 if action == 'execute' else 0
        features['action_is_delete'] = 1 if action == 'delete' else 0
        
        # User context
        user = event.get('user', '')
        features['user_is_root'] = 1 if user == 'root' else 0
        
        return features
    
    def _matches_labeling_rules(self, features: Dict[str, Any], rules: Dict[str, Any]) -> bool:
        """Check if features match labeling rules"""
        conditions = rules.get('conditions', [])
        
        for condition in conditions:
            for feature_name, criteria in condition.items():
                feature_value = features.get(feature_name, 0)
                
                # Check criteria
                if 'min' in criteria and feature_value < criteria['min']:
                    return False
                elif 'max' in criteria and feature_value > criteria['max']:
                    return False
                elif 'equals' in criteria and feature_value != criteria['equals']:
                    return False
        
        return True
    
    def _calculate_filepath_criticality(self, filepath: str) -> int:
        """Calculate file path criticality score"""
        criticality_scores = {
            '/etc/passwd': 10,
            '/etc/shadow': 10,
            '/etc/sudoers': 10,
            '/etc/hosts': 8,
            '/etc/ssh/sshd_config': 9,
            '/var/www/html': 6,
            '/bin': 8,
            '/sbin': 8,
            '/usr/bin': 6,
            '/tmp': 2,
            '/var/log': 5
        }
        
        # Check exact matches
        if filepath in criticality_scores:
            return criticality_scores[filepath]
        
        # Check directory matches
        for critical_path, score in criticality_scores.items():
            if filepath.startswith(critical_path + '/'):
                return score
        
        # Default scoring
        if '/etc/' in filepath:
            return 7
        elif '/bin/' in filepath or '/sbin/' in filepath:
            return 6
        elif '/var/www/' in filepath:
            return 4
        elif '/tmp/' in filepath:
            return 1
        else:
            return 3
    
    def _is_suspicious_process(self, process: str) -> int:
        """Check if process is suspicious"""
        suspicious_processes = [
            'nc', 'netcat', 'ncat',
            'wget', 'curl',
            'python', 'python3', 'perl', 'ruby',
            'bash', 'sh', 'zsh',
            'nmap', 'masscan',
            'mimikatz', 'metasploit',
            'powershell', 'cmd'
        ]
        
        process_lower = process.lower()
        for suspicious_proc in suspicious_processes:
            if suspicious_proc in process_lower:
                return 1
        
        return 0
    
    def _save_collected_data(self):
        """Save collected data to CSV file"""
        try:
            if not self.collected_events:
                self.logger.warning("No events collected to save")
                return
            
            # Convert to DataFrame
            df = pd.DataFrame(self.collected_events)
            
            # Save to CSV
            df.to_csv(self.output_path, index=False)
            
            self.logger.info(f"Collected data saved to {self.output_path}")
            self.logger.info(f"Total events: {len(self.collected_events)}")
            self.logger.info(f"Labeled events: {self.stats['labeled_events']}")
        
        except Exception as e:
            self.logger.error(f"Error saving collected data: {e}")
    
    def load_existing_dataset(self, dataset_path: str) -> Dict[str, Any]:
        """Load existing dataset"""
        try:
            if not os.path.exists(dataset_path):
                return {
                    'success': False,
                    'error': f'Dataset file not found: {dataset_path}'
                }
            
            # Load dataset
            df = pd.read_csv(dataset_path)
            
            # Analyze dataset
            analysis = {
                'total_samples': len(df),
                'features': list(df.columns),
                'label_distribution': df['label'].value_counts().to_dict() if 'label' in df.columns else {},
                'missing_values': df.isnull().sum().to_dict(),
                'data_types': df.dtypes.to_dict()
            }
            
            return {
                'success': True,
                'dataset_path': dataset_path,
                'analysis': analysis
            }
        
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def get_collection_status(self) -> Dict[str, Any]:
        """Get collection status"""
        return {
            'collecting': self.is_collecting,
            'collected_events': len(self.collected_events),
            'stats': self.stats,
            'output_path': self.output_path,
            'labeling_mode': self.labeling_mode
        }
    
    def get_dataset_summary(self) -> Dict[str, Any]:
        """Get dataset summary"""
        if not self.collected_events:
            return {
                'total_events': 0,
                'labeled_events': 0,
                'label_distribution': {},
                'collection_duration': 0
            }
        
        # Calculate label distribution
        label_distribution = {}
        for event in self.collected_events:
            label = event.get('label', 'unknown')
            label_distribution[label] = label_distribution.get(label, 0) + 1
        
        return {
            'total_events': len(self.collected_events),
            'labeled_events': self.stats['labeled_events'],
            'label_distribution': label_distribution,
            'collection_duration': self.stats['collection_duration'],
            'collection_rate': len(self.collected_events) / max(self.stats['collection_duration'], 1) if self.stats['collection_duration'] > 0 else 0
        }
