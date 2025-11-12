"""
Enhanced File-Level Rollback System
Provides granular file-level rollback capabilities
"""

import os
import shutil
import hashlib
import json
import time
from datetime import datetime
from typing import Dict, List, Any, Optional
import logging
import threading
from pathlib import Path

class EnhancedFileRollback:
    """Enhanced file-level rollback with granular control"""
    
    def __init__(self, config_manager):
        self.config_manager = config_manager
        self.logger = logging.getLogger(__name__)
        self.file_lock = threading.Lock()
        
        # File tracking
        self.file_states = {}
        self.file_history = []
        self.integrity_checksums = {}
        
        # Configuration
        self.backup_dir = "backups/file_states"
        self.max_history = 1000
        self.critical_files = [
            "/etc/passwd", "/etc/shadow", "/etc/hosts",
            "/etc/fstab", "/etc/crontab", "/etc/sudoers",
            "C:\\Windows\\System32\\drivers\\etc\\hosts",
            "C:\\Windows\\System32\\config\\SAM",
            "C:\\Windows\\System32\\config\\SYSTEM"
        ]
        
        # Initialize backup directory
        os.makedirs(self.backup_dir, exist_ok=True)
    
    def create_file_backup(self, file_path: str, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create comprehensive file backup"""
        try:
            with self.file_lock:
                file_path = os.path.abspath(file_path)
                
                if not os.path.exists(file_path):
                    return {"success": False, "error": "File does not exist"}
                
                # Get file info
                file_stat = os.stat(file_path)
                file_size = file_stat.st_size
                
                # Calculate checksum
                checksum = self._calculate_checksum(file_path)
                
                # Create backup
                backup_id = f"file_backup_{int(time.time())}_{hashlib.md5(file_path.encode()).hexdigest()[:8]}"
                backup_path = os.path.join(self.backup_dir, f"{backup_id}.backup")
                
                # Copy file
                shutil.copy2(file_path, backup_path)
                
                # Store file state
                file_state = {
                    "file_path": file_path,
                    "backup_path": backup_path,
                    "backup_id": backup_id,
                    "file_size": file_size,
                    "checksum": checksum,
                    "permissions": oct(file_stat.st_mode)[-3:],
                    "owner": file_stat.st_uid,
                    "group": file_stat.st_gid,
                    "modified_time": file_stat.st_mtime,
                    "threat_data": threat_data,
                    "timestamp": datetime.now().isoformat()
                }
                
                self.file_states[file_path] = file_state
                self.integrity_checksums[file_path] = checksum
                
                # Add to history
                self.file_history.append(file_state)
                if len(self.file_history) > self.max_history:
                    self.file_history.pop(0)
                
                # Save to disk
                self._save_file_states()
                
                return {
                    "success": True,
                    "backup_id": backup_id,
                    "file_path": file_path,
                    "backup_path": backup_path,
                    "checksum": checksum,
                    "file_size": file_size
                }
                
        except Exception as e:
            self.logger.error(f"File backup failed for {file_path}: {e}")
            return {"success": False, "error": str(e)}
    
    def rollback_file(self, file_path: str, backup_id: str = None) -> Dict[str, Any]:
        """Rollback file to previous state"""
        try:
            with self.file_lock:
                file_path = os.path.abspath(file_path)
                
                # Find backup
                if backup_id:
                    backup_state = self._find_backup_by_id(backup_id)
                else:
                    backup_state = self.file_states.get(file_path)
                
                if not backup_state:
                    return {"success": False, "error": "No backup found"}
                
                backup_path = backup_state["backup_path"]
                
                if not os.path.exists(backup_path):
                    return {"success": False, "error": "Backup file does not exist"}
                
                # Verify backup integrity
                backup_checksum = self._calculate_checksum(backup_path)
                if backup_checksum != backup_state["checksum"]:
                    return {"success": False, "error": "Backup integrity check failed"}
                
                # Create current file backup before rollback
                current_backup = self.create_file_backup(file_path, {"rollback": True})
                
                # Restore file
                shutil.copy2(backup_path, file_path)
                
                # Restore permissions
                os.chmod(file_path, int(backup_state["permissions"], 8))
                
                # Verify rollback
                rollback_checksum = self._calculate_checksum(file_path)
                if rollback_checksum != backup_state["checksum"]:
                    # Rollback failed, restore current backup
                    if current_backup.get("success"):
                        shutil.copy2(current_backup["backup_path"], file_path)
                    return {"success": False, "error": "Rollback verification failed"}
                
                return {
                    "success": True,
                    "file_path": file_path,
                    "backup_id": backup_state["backup_id"],
                    "rollback_checksum": rollback_checksum,
                    "original_checksum": backup_state["checksum"],
                    "current_backup": current_backup
                }
                
        except Exception as e:
            self.logger.error(f"File rollback failed for {file_path}: {e}")
            return {"success": False, "error": str(e)}
    
    def verify_file_integrity(self, file_path: str) -> Dict[str, Any]:
        """Verify file integrity"""
        try:
            file_path = os.path.abspath(file_path)
            
            if not os.path.exists(file_path):
                return {"success": False, "error": "File does not exist"}
            
            current_checksum = self._calculate_checksum(file_path)
            stored_checksum = self.integrity_checksums.get(file_path)
            
            if stored_checksum and current_checksum != stored_checksum:
                return {
                    "success": False,
                    "integrity_violation": True,
                    "current_checksum": current_checksum,
                    "stored_checksum": stored_checksum,
                    "file_path": file_path
                }
            
            return {
                "success": True,
                "integrity_ok": True,
                "checksum": current_checksum,
                "file_path": file_path
            }
            
        except Exception as e:
            self.logger.error(f"File integrity check failed for {file_path}: {e}")
            return {"success": False, "error": str(e)}
    
    def scan_critical_files(self) -> Dict[str, Any]:
        """Scan critical system files for changes"""
        try:
            violations = []
            scanned_files = []
            
            for file_path in self.critical_files:
                if os.path.exists(file_path):
                    integrity_result = self.verify_file_integrity(file_path)
                    scanned_files.append({
                        "file_path": file_path,
                        "integrity_result": integrity_result
                    })
                    
                    if not integrity_result.get("success") or integrity_result.get("integrity_violation"):
                        violations.append({
                            "file_path": file_path,
                            "violation": integrity_result
                        })
            
            return {
                "success": True,
                "scanned_files": len(scanned_files),
                "violations": len(violations),
                "violation_details": violations,
                "scanned_files_details": scanned_files
            }
            
        except Exception as e:
            self.logger.error(f"Critical files scan failed: {e}")
            return {"success": False, "error": str(e)}
    
    def _calculate_checksum(self, file_path: str) -> str:
        """Calculate file checksum"""
        try:
            hash_md5 = hashlib.md5()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
            return hash_md5.hexdigest()
        except Exception as e:
            self.logger.error(f"Checksum calculation failed for {file_path}: {e}")
            return ""
    
    def _find_backup_by_id(self, backup_id: str) -> Optional[Dict[str, Any]]:
        """Find backup by ID"""
        for state in self.file_history:
            if state["backup_id"] == backup_id:
                return state
        return None
    
    def _save_file_states(self):
        """Save file states to disk"""
        try:
            states_file = os.path.join(self.backup_dir, "file_states.json")
            with open(states_file, 'w') as f:
                json.dump({
                    "file_states": self.file_states,
                    "file_history": self.file_history[-100:],  # Keep last 100
                    "integrity_checksums": self.integrity_checksums
                }, f, indent=2)
        except Exception as e:
            self.logger.error(f"Failed to save file states: {e}")
    
    def load_file_states(self):
        """Load file states from disk"""
        try:
            states_file = os.path.join(self.backup_dir, "file_states.json")
            if os.path.exists(states_file):
                with open(states_file, 'r') as f:
                    data = json.load(f)
                    self.file_states = data.get("file_states", {})
                    self.file_history = data.get("file_history", [])
                    self.integrity_checksums = data.get("integrity_checksums", {})
        except Exception as e:
            self.logger.error(f"Failed to load file states: {e}")
    
    def cleanup_old_backups(self, days: int = 7):
        """Cleanup old backups"""
        try:
            cutoff_time = time.time() - (days * 24 * 60 * 60)
            
            # Cleanup file history
            self.file_history = [
                state for state in self.file_history
                if datetime.fromisoformat(state["timestamp"]).timestamp() > cutoff_time
            ]
            
            # Cleanup backup files
            for backup_file in os.listdir(self.backup_dir):
                if backup_file.endswith('.backup'):
                    file_path = os.path.join(self.backup_dir, backup_file)
                    if os.path.getmtime(file_path) < cutoff_time:
                        os.remove(file_path)
            
            self._save_file_states()
            
        except Exception as e:
            self.logger.error(f"Backup cleanup failed: {e}")
    
    def get_file_statistics(self) -> Dict[str, Any]:
        """Get file rollback statistics"""
        return {
            "total_backups": len(self.file_states),
            "history_entries": len(self.file_history),
            "integrity_checks": len(self.integrity_checksums),
            "critical_files_monitored": len(self.critical_files),
            "backup_directory": self.backup_dir
        }
