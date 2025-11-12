#!/usr/bin/env python3
"""
File Integrity Monitor (FIM) for H-SOAR HIDS
Monitors file system changes using auditd and provides FIM capabilities
"""

import os
import json
import logging
import hashlib
import subprocess
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime

class FileIntegrityMonitor:
    """
    File Integrity Monitor using auditd for real-time file system monitoring
    """
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize FIM with configuration"""
        self.config = config
        self.logger = logging.getLogger('FIM')
        self.monitor_paths = config.get('monitor_paths', ['/etc', '/bin', '/sbin'])
        self.exclude_patterns = config.get('exclude_patterns', [])
        self.check_interval = config.get('check_interval', 5)
        self.baseline_hashes = {}
        self.is_monitoring = False
        
        # Setup auditd rules
        self._setup_auditd_rules()
    
    def _setup_auditd_rules(self):
        """Setup auditd rules for file monitoring"""
        try:
            rules_file = "/etc/audit/rules.d/hids.rules"
            rules_content = self._generate_auditd_rules()
            
            # Write rules file
            with open(rules_file, 'w') as f:
                f.write(rules_content)
            
            self.logger.info(f"Auditd rules written to {rules_file}")
            
            # Reload auditd rules
            subprocess.run(['auditctl', '-R', rules_file], check=True)
            self.logger.info("Auditd rules reloaded successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to setup auditd rules: {e}")
    
    def _generate_auditd_rules(self) -> str:
        """Generate auditd rules for monitoring"""
        rules = [
            "# H-SOAR HIDS File Integrity Monitoring Rules",
            "# Monitor critical system directories",
            "",
            "# Monitor /etc directory (system configuration)",
            "-w /etc -p wa -k hids_fim",
            "",
            "# Monitor /bin directory (system binaries)",
            "-w /bin -p wa -k hids_fim",
            "",
            "# Monitor /sbin directory (system administration binaries)",
            "-w /sbin -p wa -k hids_fim",
            "",
            "# Monitor /usr/bin directory (user binaries)",
            "-w /usr/bin -p wa -k hids_fim",
            "",
            "# Monitor web directory (if exists)",
            "-w /var/www/html -p wa -k hids_fim",
            "",
            "# Monitor process execution",
            "-a always,exit -F arch=b64 -S execve -k hids_process",
            "-a always,exit -F arch=b32 -S execve -k hids_process",
            "",
            "# Monitor file attribute changes",
            "-a always,exit -F arch=b64 -S chmod -k hids_attr",
            "-a always,exit -F arch=b64 -S chown -k hids_attr",
            "",
            "# Monitor network connections",
            "-a always,exit -F arch=b64 -S bind -k hids_network",
            "-a always,exit -F arch=b64 -S connect -k hids_network",
            "",
            "# Monitor privilege escalation",
            "-a always,exit -F arch=b64 -S setuid -k hids_priv",
            "-a always,exit -F arch=b64 -S setgid -k hids_priv",
        ]
        
        return "\n".join(rules)
    
    def start_monitoring(self):
        """Start file integrity monitoring"""
        self.logger.info("Starting File Integrity Monitoring...")
        self.is_monitoring = True
        
        # Create baseline hashes for monitored files
        self._create_baseline()
        
        self.logger.info(f"Monitoring {len(self.monitor_paths)} directories")
        self.logger.info(f"Monitor paths: {', '.join(self.monitor_paths)}")
    
    def stop_monitoring(self):
        """Stop file integrity monitoring"""
        self.logger.info("Stopping File Integrity Monitoring...")
        self.is_monitoring = False
    
    def _create_baseline(self):
        """Create baseline hashes for monitored files"""
        self.logger.info("Creating baseline file hashes...")
        
        for monitor_path in self.monitor_paths:
            if os.path.exists(monitor_path):
                self._hash_directory(monitor_path)
        
        self.logger.info(f"Baseline created for {len(self.baseline_hashes)} files")
    
    def _hash_directory(self, directory: str):
        """Recursively hash files in directory"""
        try:
            for root, dirs, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    
                    # Skip excluded patterns
                    if self._should_exclude(file_path):
                        continue
                    
                    try:
                        file_hash = self._calculate_file_hash(file_path)
                        self.baseline_hashes[file_path] = {
                            'hash': file_hash,
                            'size': os.path.getsize(file_path),
                            'mtime': os.path.getmtime(file_path),
                            'timestamp': datetime.now().isoformat()
                        }
                    except Exception as e:
                        self.logger.warning(f"Could not hash {file_path}: {e}")
        
        except Exception as e:
            self.logger.error(f"Error hashing directory {directory}: {e}")
    
    def _should_exclude(self, file_path: str) -> bool:
        """Check if file should be excluded from monitoring"""
        for pattern in self.exclude_patterns:
            if pattern in file_path:
                return True
        return False
    
    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of file"""
        hash_sha256 = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except Exception as e:
            self.logger.warning(f"Could not calculate hash for {file_path}: {e}")
            return ""
    
    def check_integrity(self) -> List[Dict[str, Any]]:
        """Check file integrity against baseline"""
        integrity_violations = []
        
        for file_path, baseline_info in self.baseline_hashes.items():
            if not os.path.exists(file_path):
                # File deleted
                integrity_violations.append({
                    'filepath': file_path,
                    'action': 'deleted',
                    'severity': 'high',
                    'baseline_hash': baseline_info['hash'],
                    'current_hash': None,
                    'timestamp': datetime.now().isoformat()
                })
                continue
            
            try:
                current_hash = self._calculate_file_hash(file_path)
                current_size = os.path.getsize(file_path)
                current_mtime = os.path.getmtime(file_path)
                
                # Check for changes
                if current_hash != baseline_info['hash']:
                    integrity_violations.append({
                        'filepath': file_path,
                        'action': 'modified',
                        'severity': 'high',
                        'baseline_hash': baseline_info['hash'],
                        'current_hash': current_hash,
                        'size_changed': current_size != baseline_info['size'],
                        'mtime_changed': current_mtime != baseline_info['mtime'],
                        'timestamp': datetime.now().isoformat()
                    })
                
            except Exception as e:
                self.logger.warning(f"Could not check integrity for {file_path}: {e}")
        
        return integrity_violations
    
    def add_file_to_baseline(self, file_path: str):
        """Add new file to baseline"""
        try:
            file_hash = self._calculate_file_hash(file_path)
            self.baseline_hashes[file_path] = {
                'hash': file_hash,
                'size': os.path.getsize(file_path),
                'mtime': os.path.getmtime(file_path),
                'timestamp': datetime.now().isoformat()
            }
            self.logger.info(f"Added {file_path} to baseline")
        except Exception as e:
            self.logger.error(f"Could not add {file_path} to baseline: {e}")
    
    def remove_file_from_baseline(self, file_path: str):
        """Remove file from baseline"""
        if file_path in self.baseline_hashes:
            del self.baseline_hashes[file_path]
            self.logger.info(f"Removed {file_path} from baseline")
    
    def get_status(self) -> Dict[str, Any]:
        """Get FIM status"""
        return {
            'active': self.is_monitoring,
            'monitor_paths': self.monitor_paths,
            'baseline_files': len(self.baseline_hashes),
            'exclude_patterns': self.exclude_patterns,
            'check_interval': self.check_interval
        }
    
    def get_baseline_summary(self) -> Dict[str, Any]:
        """Get baseline summary"""
        return {
            'total_files': len(self.baseline_hashes),
            'monitor_paths': self.monitor_paths,
            'last_updated': datetime.now().isoformat(),
            'sample_files': list(self.baseline_hashes.keys())[:10]  # First 10 files
        }
