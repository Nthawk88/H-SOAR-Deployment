#!/usr/bin/env python3
"""
Alert Triage System for H-SOAR HIDS
Intelligent alert triage and automated response system
"""

import os
import json
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime

class AlertTriageSystem:
    """
    Alert triage system for HIDS events
    """
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize alert triage system"""
        self.config = config
        self.logger = logging.getLogger('AlertTriage')
        
        # Configuration
        self.enabled = config.get('enabled', True)
        self.alert_categories = config.get('alert_categories', ['benign', 'suspicious', 'malicious'])
        self.auto_response = config.get('auto_response', True)
        self.response_threshold = config.get('response_threshold', 0.9)
        
        # Triage rules
        self.triage_rules = self._load_triage_rules()
        
        # Alert history
        self.alert_history = []
        
        # Statistics
        self.stats = {
            'total_alerts': 0,
            'benign_alerts': 0,
            'suspicious_alerts': 0,
            'malicious_alerts': 0,
            'auto_responses': 0
        }
    
    def _load_triage_rules(self) -> Dict[str, Any]:
        """Load triage rules"""
        return {
            'benign': {
                'conditions': [
                    {'filepath_criticality': {'max': 3}},
                    {'process_suspicious': {'max': 0}},
                    {'action_is_write': {'max': 0}}
                ],
                'threshold': 0.3
            },
            'suspicious': {
                'conditions': [
                    {'filepath_criticality': {'min': 4, 'max': 7}},
                    {'process_suspicious': {'max': 1}},
                    {'action_is_write': {'max': 1}}
                ],
                'threshold': 0.6
            },
            'malicious': {
                'conditions': [
                    {'filepath_criticality': {'min': 8}},
                    {'process_suspicious': {'min': 1}},
                    {'action_is_write': {'min': 1}},
                    {'user_is_root': {'min': 1}}
                ],
                'threshold': 0.8
            }
        }
    
    def triage_alert(self, event: Dict[str, Any], classification: Dict[str, Any]) -> Dict[str, Any]:
        """Triage alert based on event and ML classification"""
        try:
            if not self.enabled:
                return {
                    'success': False,
                    'error': 'Alert triage system disabled',
                    'category': 'unknown'
                }
            
            # Extract features from event
            features = self._extract_triage_features(event)
            
            # Get ML classification
            ml_classification = classification.get('classification', 'unknown')
            ml_confidence = classification.get('confidence', 0.0)
            
            # Apply triage rules
            triage_result = self._apply_triage_rules(features, ml_classification, ml_confidence)
            
            # Determine final category
            final_category = self._determine_final_category(triage_result, ml_classification, ml_confidence)
            
            # Generate alert
            alert = self._generate_alert(event, final_category, triage_result, classification)
            
            # Record alert
            self.alert_history.append(alert)
            self.stats['total_alerts'] += 1
            self.stats[f'{final_category}_alerts'] += 1
            
            # Auto-response if enabled
            response_result = None
            if self.auto_response and final_category == 'malicious':
                response_result = self._execute_auto_response(alert)
                if response_result.get('success'):
                    self.stats['auto_responses'] += 1
            
            return {
                'success': True,
                'category': final_category,
                'confidence': triage_result.get('confidence', 0.0),
                'alert': alert,
                'response': response_result,
                'triage_details': triage_result
            }
        
        except Exception as e:
            self.logger.error(f"Error in alert triage: {e}")
            return {
                'success': False,
                'error': str(e),
                'category': 'unknown'
            }
    
    def _extract_triage_features(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Extract features for triage"""
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
        features['user_is_root'] = 1 if user == '0' or user == 'root' else 0
        
        # File attributes
        features['filepath_suspicious'] = self._is_suspicious_filepath(filepath)
        
        return features
    
    def _apply_triage_rules(self, features: Dict[str, Any], ml_classification: str, ml_confidence: float) -> Dict[str, Any]:
        """Apply triage rules to features"""
        triage_scores = {}
        
        for category, rules in self.triage_rules.items():
            score = 0.0
            total_conditions = len(rules['conditions'])
            
            for condition in rules['conditions']:
                for feature_name, criteria in condition.items():
                    feature_value = features.get(feature_name, 0)
                    
                    # Check criteria
                    if 'min' in criteria and feature_value >= criteria['min']:
                        score += 1.0
                    elif 'max' in criteria and feature_value <= criteria['max']:
                        score += 1.0
                    elif 'equals' in criteria and feature_value == criteria['equals']:
                        score += 1.0
            
            # Normalize score
            triage_scores[category] = score / total_conditions
        
        # Find best matching category
        best_category = max(triage_scores.items(), key=lambda x: x[1])
        
        return {
            'category': best_category[0],
            'confidence': best_category[1],
            'scores': triage_scores,
            'ml_classification': ml_classification,
            'ml_confidence': ml_confidence
        }
    
    def _determine_final_category(self, triage_result: Dict[str, Any], ml_classification: str, ml_confidence: float) -> str:
        """Determine final alert category"""
        triage_category = triage_result.get('category', 'unknown')
        triage_confidence = triage_result.get('confidence', 0.0)
        
        # Combine triage and ML results
        if ml_confidence > self.response_threshold:
            # High confidence ML classification takes precedence
            if ml_classification in self.alert_categories:
                return ml_classification
        
        # Use triage result if ML confidence is low
        if triage_confidence > 0.7:
            return triage_category
        
        # Default to suspicious if uncertain
        return 'suspicious'
    
    def _generate_alert(self, event: Dict[str, Any], category: str, triage_result: Dict[str, Any], classification: Dict[str, Any]) -> Dict[str, Any]:
        """Generate alert record"""
        alert = {
            'alert_id': f"alert_{int(datetime.now().timestamp())}",
            'timestamp': datetime.now().isoformat(),
            'category': category,
            'severity': self._get_severity(category),
            'event': event,
            'triage_result': triage_result,
            'ml_classification': classification,
            'status': 'new',
            'assigned_to': None,
            'response_required': category == 'malicious'
        }
        
        return alert
    
    def _get_severity(self, category: str) -> str:
        """Get severity level for category"""
        severity_mapping = {
            'benign': 'LOW',
            'suspicious': 'MEDIUM',
            'malicious': 'HIGH'
        }
        return severity_mapping.get(category, 'UNKNOWN')
    
    def _execute_auto_response(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Execute automated response for malicious alerts"""
        try:
            if alert.get('category') != 'malicious':
                return {
                    'success': False,
                    'error': 'Auto-response only for malicious alerts'
                }
            
            # Log the alert
            self.logger.warning(f"MALICIOUS ALERT: {alert['alert_id']}")
            self.logger.warning(f"Event: {alert['event']}")
            
            # Mark alert as responded
            alert['status'] = 'responded'
            alert['response_timestamp'] = datetime.now().isoformat()
            
            return {
                'success': True,
                'message': 'Auto-response executed',
                'alert_id': alert['alert_id']
            }
        
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
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
    
    def _is_suspicious_filepath(self, filepath: str) -> int:
        """Check if file path is suspicious"""
        suspicious_patterns = [
            'shell', 'backdoor', 'trojan', 'virus',
            'malware', 'exploit', 'payload',
            'cmd', 'command', 'exec',
            '..', '...', '....'
        ]
        
        filepath_lower = filepath.lower()
        for pattern in suspicious_patterns:
            if pattern in filepath_lower:
                return 1
        
        return 0
    
    def get_alert_summary(self) -> Dict[str, Any]:
        """Get alert summary statistics"""
        return {
            'total_alerts': self.stats['total_alerts'],
            'benign_alerts': self.stats['benign_alerts'],
            'suspicious_alerts': self.stats['suspicious_alerts'],
            'malicious_alerts': self.stats['malicious_alerts'],
            'auto_responses': self.stats['auto_responses'],
            'alert_rate': {
                'benign': self.stats['benign_alerts'] / max(self.stats['total_alerts'], 1),
                'suspicious': self.stats['suspicious_alerts'] / max(self.stats['total_alerts'], 1),
                'malicious': self.stats['malicious_alerts'] / max(self.stats['total_alerts'], 1)
            }
        }
    
    def get_recent_alerts(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent alerts"""
        return self.alert_history[-limit:] if self.alert_history else []
    
    def get_alerts_by_category(self, category: str) -> List[Dict[str, Any]]:
        """Get alerts filtered by category"""
        return [alert for alert in self.alert_history if alert.get('category') == category]
    
    def get_status(self) -> Dict[str, Any]:
        """Get triage system status"""
        return {
            'active': self.enabled,
            'auto_response': self.auto_response,
            'response_threshold': self.response_threshold,
            'alert_categories': self.alert_categories,
            'stats': self.stats,
            'recent_alerts_count': len(self.alert_history)
        }
