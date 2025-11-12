#!/usr/bin/env python3
"""
Feature Extractor for H-SOAR HIDS
Extracts meaningful features from auditd events for ML classification
"""

import os
import json
import logging
from typing import Dict, List, Any, Optional
from pathlib import Path

class HIDSFeatureExtractor:
    """
    Extracts features from auditd events for ML classification
    """
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize feature extractor"""
        self.config = config
        self.logger = logging.getLogger('HIDSFeatureExtractor')
        
        # Feature extraction settings
        self.extract_filepath_criticality = config.get('filepath_criticality', True)
        self.extract_process_analysis = config.get('process_analysis', True)
        self.extract_user_context = config.get('user_context', True)
        self.extract_file_attributes = config.get('file_attributes', True)
        self.extract_temporal_features = config.get('temporal_features', True)
        
        # Criticality scoring for file paths
        self.criticality_scores = {
            '/etc/passwd': 10,
            '/etc/shadow': 10,
            '/etc/sudoers': 10,
            '/etc/hosts': 8,
            '/etc/hostname': 8,
            '/etc/resolv.conf': 8,
            '/etc/ssh/sshd_config': 9,
            '/etc/nginx/nginx.conf': 7,
            '/etc/apache2/apache2.conf': 7,
            '/var/www/html': 6,
            '/bin': 8,
            '/sbin': 8,
            '/usr/bin': 6,
            '/usr/sbin': 6,
            '/tmp': 2,
            '/var/log': 5,
            '/var/tmp': 2,
            '/home': 4,
            '/root': 9
        }
        
        # Suspicious process patterns
        self.suspicious_processes = [
            'nc', 'netcat', 'ncat',
            'wget', 'curl',
            'python', 'python3', 'perl', 'ruby',
            'bash', 'sh', 'zsh', 'csh',
            'ssh', 'scp', 'rsync',
            'nmap', 'masscan',
            'mimikatz', 'metasploit',
            'powershell', 'cmd',
            'base64', 'xxd', 'hexdump'
        ]
        
        # Suspicious file extensions
        self.suspicious_extensions = [
            '.php', '.jsp', '.asp', '.aspx',
            '.sh', '.bat', '.cmd', '.ps1',
            '.exe', '.dll', '.so',
            '.py', '.pl', '.rb',
            '.war', '.jar'
        ]
    
    def extract_features(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Extract features from auditd event"""
        features = {}
        
        try:
            # Basic event features
            features['event_type'] = self._encode_event_type(event.get('event_type', 'unknown'))
            features['action'] = self._encode_action(event.get('action', 'unknown'))
            
            # File path features
            if self.extract_filepath_criticality:
                filepath_features = self._extract_filepath_features(event)
                features.update(filepath_features)
            
            # Process features
            if self.extract_process_analysis:
                process_features = self._extract_process_features(event)
                features.update(process_features)
            
            # User context features
            if self.extract_user_context:
                user_features = self._extract_user_features(event)
                features.update(user_features)
            
            # File attribute features
            if self.extract_file_attributes:
                file_attr_features = self._extract_file_attributes(event)
                features.update(file_attr_features)
            
            # Temporal features
            if self.extract_temporal_features:
                temporal_features = self._extract_temporal_features(event)
                features.update(temporal_features)
            
            return features
        
        except Exception as e:
            self.logger.error(f"Error extracting features: {e}")
            return {}
    
    def _extract_filepath_features(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Extract file path related features"""
        features = {}
        filepath = event.get('filepath', '')
        
        if not filepath:
            features['filepath_criticality'] = 0
            features['filepath_depth'] = 0
            features['filepath_suspicious'] = 0
            features['file_extension_suspicious'] = 0
            return features
        
        # File path criticality score
        features['filepath_criticality'] = self._calculate_filepath_criticality(filepath)
        
        # File path depth
        features['filepath_depth'] = len(Path(filepath).parts)
        
        # Suspicious file path patterns
        features['filepath_suspicious'] = self._is_suspicious_filepath(filepath)
        
        # File extension analysis
        features['file_extension_suspicious'] = self._is_suspicious_extension(filepath)
        
        # Directory analysis
        features['is_system_directory'] = self._is_system_directory(filepath)
        features['is_web_directory'] = self._is_web_directory(filepath)
        features['is_temp_directory'] = self._is_temp_directory(filepath)
        
        return features
    
    def _extract_process_features(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Extract process related features"""
        features = {}
        process = event.get('process', '')
        
        if not process:
            features['process_suspicious'] = 0
            features['process_is_shell'] = 0
            features['process_is_web_server'] = 0
            features['process_is_system'] = 0
            return features
        
        # Process suspiciousness
        features['process_suspicious'] = self._is_suspicious_process(process)
        
        # Process type analysis
        features['process_is_shell'] = self._is_shell_process(process)
        features['process_is_web_server'] = self._is_web_server_process(process)
        features['process_is_system'] = self._is_system_process(process)
        
        # Process name length (suspicious processes often have unusual names)
        features['process_name_length'] = len(process)
        
        return features
    
    def _extract_user_features(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Extract user context features"""
        features = {}
        user = event.get('user', '')
        
        if not user:
            features['user_is_root'] = 0
            features['user_is_system'] = 0
            features['user_is_web'] = 0
            return features
        
        # User type analysis
        features['user_is_root'] = 1 if user == '0' or user == 'root' else 0
        features['user_is_system'] = 1 if user in ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9'] else 0
        features['user_is_web'] = 1 if user in ['www-data', 'apache', 'nginx', 'httpd'] else 0
        
        return features
    
    def _extract_file_attributes(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Extract file attribute features"""
        features = {}
        
        # Action type analysis
        action = event.get('action', '')
        features['action_is_write'] = 1 if action in ['write', 'create', 'modify'] else 0
        features['action_is_delete'] = 1 if action == 'delete' else 0
        features['action_is_execute'] = 1 if action == 'execute' else 0
        features['action_is_attribute'] = 1 if action in ['chmod', 'chown'] else 0
        
        return features
    
    def _extract_temporal_features(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Extract temporal features"""
        features = {}
        
        # For now, we'll use simple features
        # In a real implementation, you might want to analyze patterns over time
        features['hour_of_day'] = 12  # Placeholder - would extract from timestamp
        features['day_of_week'] = 1  # Placeholder - would extract from timestamp
        
        return features
    
    def _calculate_filepath_criticality(self, filepath: str) -> int:
        """Calculate criticality score for file path"""
        # Check exact matches first
        if filepath in self.criticality_scores:
            return self.criticality_scores[filepath]
        
        # Check directory matches
        for critical_path, score in self.criticality_scores.items():
            if filepath.startswith(critical_path + '/'):
                return score
        
        # Default score based on path components
        if '/etc/' in filepath:
            return 7
        elif '/bin/' in filepath or '/sbin/' in filepath:
            return 6
        elif '/usr/bin/' in filepath or '/usr/sbin/' in filepath:
            return 5
        elif '/var/www/' in filepath:
            return 4
        elif '/tmp/' in filepath or '/var/tmp/' in filepath:
            return 1
        else:
            return 3
    
    def _is_suspicious_filepath(self, filepath: str) -> int:
        """Check if file path is suspicious"""
        suspicious_patterns = [
            'shell', 'backdoor', 'trojan', 'virus',
            'malware', 'exploit', 'payload',
            'cmd', 'command', 'exec',
            '..', '...', '....'  # Path traversal
        ]
        
        filepath_lower = filepath.lower()
        for pattern in suspicious_patterns:
            if pattern in filepath_lower:
                return 1
        
        return 0
    
    def _is_suspicious_extension(self, filepath: str) -> int:
        """Check if file extension is suspicious"""
        filepath_lower = filepath.lower()
        for ext in self.suspicious_extensions:
            if filepath_lower.endswith(ext):
                return 1
        return 0
    
    def _is_system_directory(self, filepath: str) -> int:
        """Check if file is in system directory"""
        system_dirs = ['/etc', '/bin', '/sbin', '/usr/bin', '/usr/sbin', '/lib', '/lib64']
        for sys_dir in system_dirs:
            if filepath.startswith(sys_dir):
                return 1
        return 0
    
    def _is_web_directory(self, filepath: str) -> int:
        """Check if file is in web directory"""
        web_dirs = ['/var/www', '/var/www/html', '/var/www/public', '/var/www/web']
        for web_dir in web_dirs:
            if filepath.startswith(web_dir):
                return 1
        return 0
    
    def _is_temp_directory(self, filepath: str) -> int:
        """Check if file is in temporary directory"""
        temp_dirs = ['/tmp', '/var/tmp', '/dev/shm']
        for temp_dir in temp_dirs:
            if filepath.startswith(temp_dir):
                return 1
        return 0
    
    def _is_suspicious_process(self, process: str) -> int:
        """Check if process is suspicious"""
        process_lower = process.lower()
        for suspicious_proc in self.suspicious_processes:
            if suspicious_proc in process_lower:
                return 1
        return 0
    
    def _is_shell_process(self, process: str) -> int:
        """Check if process is a shell"""
        shell_processes = ['bash', 'sh', 'zsh', 'csh', 'ksh', 'fish']
        process_lower = process.lower()
        for shell in shell_processes:
            if shell in process_lower:
                return 1
        return 0
    
    def _is_web_server_process(self, process: str) -> int:
        """Check if process is a web server"""
        web_processes = ['nginx', 'apache2', 'httpd', 'lighttpd', 'php-fpm']
        process_lower = process.lower()
        for web_proc in web_processes:
            if web_proc in process_lower:
                return 1
        return 0
    
    def _is_system_process(self, process: str) -> int:
        """Check if process is a system process"""
        system_processes = ['systemd', 'init', 'kthreadd', 'ksoftirqd', 'migration']
        process_lower = process.lower()
        for sys_proc in system_processes:
            if sys_proc in process_lower:
                return 1
        return 0
    
    def _encode_event_type(self, event_type: str) -> int:
        """Encode event type as integer"""
        event_type_mapping = {
            'file_integrity': 1,
            'process_execution': 2,
            'file_attribute': 3,
            'network': 4,
            'privilege': 5,
            'unknown': 0
        }
        return event_type_mapping.get(event_type, 0)
    
    def _encode_action(self, action: str) -> int:
        """Encode action as integer"""
        action_mapping = {
            'open': 1,
            'write': 2,
            'delete': 3,
            'execute': 4,
            'chmod': 5,
            'chown': 6,
            'rename': 7,
            'truncate': 8,
            'bind': 9,
            'connect': 10,
            'setuid': 11,
            'setgid': 12,
            'unknown': 0
        }
        return action_mapping.get(action, 0)
    
    def get_feature_names(self) -> List[str]:
        """Get list of feature names"""
        return [
            'event_type', 'action',
            'filepath_criticality', 'filepath_depth', 'filepath_suspicious',
            'file_extension_suspicious', 'is_system_directory', 'is_web_directory', 'is_temp_directory',
            'process_suspicious', 'process_is_shell', 'process_is_web_server', 'process_is_system',
            'process_name_length',
            'user_is_root', 'user_is_system', 'user_is_web',
            'action_is_write', 'action_is_delete', 'action_is_execute', 'action_is_attribute',
            'hour_of_day', 'day_of_week'
        ]
    
    def get_feature_importance(self) -> Dict[str, float]:
        """Get feature importance scores (placeholder)"""
        return {
            'filepath_criticality': 0.25,
            'process_suspicious': 0.20,
            'action_is_write': 0.15,
            'user_is_root': 0.10,
            'filepath_suspicious': 0.10,
            'action_is_execute': 0.08,
            'file_extension_suspicious': 0.07,
            'process_is_shell': 0.05
        }
