"""
Enhanced Registry Rollback System
Provides Windows registry state management and rollback
"""

import os
import json
import time
import threading
from datetime import datetime
from typing import Dict, List, Any, Optional
import logging
import subprocess
import winreg

class EnhancedRegistryRollback:
    """Enhanced Windows registry rollback with state management"""
    
    def __init__(self, config_manager):
        self.config_manager = config_manager
        self.logger = logging.getLogger(__name__)
        self.registry_lock = threading.Lock()
        
        # Registry tracking
        self.registry_states = {}
        self.registry_history = []
        self.critical_keys = {}
        
        # Configuration
        self.backup_dir = "backups/registry_states"
        self.max_history = 500
        
        # Critical registry keys
        self.critical_registry_keys = [
            (winreg.HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"),
            (winreg.HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),
            (winreg.HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"),
            (winreg.HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services"),
            (winreg.HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"),
            (winreg.HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Session Manager"),
            (winreg.HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"),
            (winreg.HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"),
            (winreg.HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced"),
        ]
        
        # Initialize backup directory
        os.makedirs(self.backup_dir, exist_ok=True)
    
    def create_registry_backup(self, key_path: str, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create comprehensive registry backup"""
        try:
            with self.registry_lock:
                # Parse key path
                hkey, subkey = self._parse_key_path(key_path)
                
                try:
                    # Open registry key
                    key = winreg.OpenKey(hkey, subkey, 0, winreg.KEY_READ)
                except FileNotFoundError:
                    return {"success": False, "error": "Registry key does not exist"}
                except PermissionError:
                    return {"success": False, "error": "Access denied to registry key"}
                
                # Get key info
                key_info = self._get_key_info(key)
                
                # Create backup
                backup_id = f"registry_backup_{int(time.time())}_{hashlib.md5(key_path.encode()).hexdigest()[:8]}"
                backup_path = os.path.join(self.backup_dir, f"{backup_id}.reg")
                
                # Export registry key
                export_result = self._export_registry_key(hkey, subkey, backup_path)
                
                if not export_result.get("success"):
                    return export_result
                
                # Store registry state
                registry_state = {
                    "key_path": key_path,
                    "hkey": hkey,
                    "subkey": subkey,
                    "backup_path": backup_path,
                    "backup_id": backup_id,
                    "key_info": key_info,
                    "threat_data": threat_data,
                    "timestamp": datetime.now().isoformat()
                }
                
                self.registry_states[key_path] = registry_state
                
                # Add to history
                self.registry_history.append(registry_state)
                if len(self.registry_history) > self.max_history:
                    self.registry_history.pop(0)
                
                # Save to disk
                self._save_registry_states()
                
                winreg.CloseKey(key)
                
                return {
                    "success": True,
                    "backup_id": backup_id,
                    "key_path": key_path,
                    "backup_path": backup_path,
                    "key_info": key_info
                }
                
        except Exception as e:
            self.logger.error(f"Registry backup failed for {key_path}: {e}")
            return {"success": False, "error": str(e)}
    
    def rollback_registry(self, key_path: str, backup_id: str = None) -> Dict[str, Any]:
        """Rollback registry to previous state"""
        try:
            with self.registry_lock:
                # Find backup
                if backup_id:
                    backup_state = self._find_backup_by_id(backup_id)
                else:
                    backup_state = self.registry_states.get(key_path)
                
                if not backup_state:
                    return {"success": False, "error": "No backup found"}
                
                backup_path = backup_state["backup_path"]
                
                if not os.path.exists(backup_path):
                    return {"success": False, "error": "Backup file does not exist"}
                
                # Create current registry backup before rollback
                current_backup = self.create_registry_backup(key_path, {"rollback": True})
                
                # Import registry key
                import_result = self._import_registry_key(backup_path)
                
                if import_result.get("success"):
                    return {
                        "success": True,
                        "key_path": key_path,
                        "backup_id": backup_state["backup_id"],
                        "import_result": import_result,
                        "current_backup": current_backup
                    }
                else:
                    return {
                        "success": False,
                        "error": import_result.get("error", "Registry import failed"),
                        "current_backup": current_backup
                    }
                
        except Exception as e:
            self.logger.error(f"Registry rollback failed for {key_path}: {e}")
            return {"success": False, "error": str(e)}
    
    def scan_critical_registry_keys(self) -> Dict[str, Any]:
        """Scan critical registry keys for changes"""
        try:
            violations = []
            scanned_keys = []
            
            for hkey, subkey in self.critical_registry_keys:
                key_path = f"{self._hkey_to_string(hkey)}\\{subkey}"
                
                try:
                    # Open registry key
                    key = winreg.OpenKey(hkey, subkey, 0, winreg.KEY_READ)
                    
                    # Get current key info
                    current_info = self._get_key_info(key)
                    
                    # Check against stored state
                    stored_state = self.registry_states.get(key_path)
                    
                    scanned_keys.append({
                        "key_path": key_path,
                        "current_info": current_info,
                        "has_backup": stored_state is not None
                    })
                    
                    if stored_state:
                        stored_info = stored_state["key_info"]
                        if current_info != stored_info:
                            violations.append({
                                "key_path": key_path,
                                "current_info": current_info,
                                "stored_info": stored_info,
                                "changes": self._compare_key_info(current_info, stored_info)
                            })
                    
                    winreg.CloseKey(key)
                    
                except (FileNotFoundError, PermissionError) as e:
                    scanned_keys.append({
                        "key_path": key_path,
                        "error": str(e),
                        "has_backup": False
                    })
            
            return {
                "success": True,
                "scanned_keys": len(scanned_keys),
                "violations": len(violations),
                "violation_details": violations,
                "scanned_keys_details": scanned_keys
            }
            
        except Exception as e:
            self.logger.error(f"Critical registry keys scan failed: {e}")
            return {"success": False, "error": str(e)}
    
    def backup_critical_registry_keys(self, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Backup all critical registry keys"""
        try:
            backup_results = []
            successful_backups = 0
            
            for hkey, subkey in self.critical_registry_keys:
                key_path = f"{self._hkey_to_string(hkey)}\\{subkey}"
                
                backup_result = self.create_registry_backup(key_path, threat_data)
                backup_results.append({
                    "key_path": key_path,
                    "backup_result": backup_result
                })
                
                if backup_result.get("success"):
                    successful_backups += 1
            
            return {
                "success": True,
                "total_keys": len(self.critical_registry_keys),
                "successful_backups": successful_backups,
                "backup_results": backup_results
            }
            
        except Exception as e:
            self.logger.error(f"Critical registry keys backup failed: {e}")
            return {"success": False, "error": str(e)}
    
    def _parse_key_path(self, key_path: str) -> tuple:
        """Parse registry key path"""
        parts = key_path.split("\\", 1)
        hkey_str = parts[0]
        subkey = parts[1] if len(parts) > 1 else ""
        
        hkey_map = {
            "HKEY_LOCAL_MACHINE": winreg.HKEY_LOCAL_MACHINE,
            "HKEY_CURRENT_USER": winreg.HKEY_CURRENT_USER,
            "HKEY_CLASSES_ROOT": winreg.HKEY_CLASSES_ROOT,
            "HKEY_USERS": winreg.HKEY_USERS,
            "HKEY_CURRENT_CONFIG": winreg.HKEY_CURRENT_CONFIG,
            "HKLM": winreg.HKEY_LOCAL_MACHINE,
            "HKCU": winreg.HKEY_CURRENT_USER,
            "HKCR": winreg.HKEY_CLASSES_ROOT,
            "HKU": winreg.HKEY_USERS,
            "HKCC": winreg.HKEY_CURRENT_CONFIG
        }
        
        hkey = hkey_map.get(hkey_str, winreg.HKEY_LOCAL_MACHINE)
        return hkey, subkey
    
    def _hkey_to_string(self, hkey) -> str:
        """Convert HKEY to string"""
        hkey_map = {
            winreg.HKEY_LOCAL_MACHINE: "HKEY_LOCAL_MACHINE",
            winreg.HKEY_CURRENT_USER: "HKEY_CURRENT_USER",
            winreg.HKEY_CLASSES_ROOT: "HKEY_CLASSES_ROOT",
            winreg.HKEY_USERS: "HKEY_USERS",
            winreg.HKEY_CURRENT_CONFIG: "HKEY_CURRENT_CONFIG"
        }
        return hkey_map.get(hkey, "HKEY_LOCAL_MACHINE")
    
    def _get_key_info(self, key) -> Dict[str, Any]:
        """Get registry key information"""
        try:
            key_info = {
                "values": {},
                "subkeys": []
            }
            
            # Get values
            i = 0
            while True:
                try:
                    name, value, reg_type = winreg.EnumValue(key, i)
                    key_info["values"][name] = {
                        "value": value,
                        "type": reg_type
                    }
                    i += 1
                except OSError:
                    break
            
            # Get subkeys
            i = 0
            while True:
                try:
                    subkey_name = winreg.EnumKey(key, i)
                    key_info["subkeys"].append(subkey_name)
                    i += 1
                except OSError:
                    break
            
            return key_info
            
        except Exception as e:
            self.logger.error(f"Failed to get key info: {e}")
            return {"values": {}, "subkeys": []}
    
    def _export_registry_key(self, hkey, subkey: str, backup_path: str) -> Dict[str, Any]:
        """Export registry key to file"""
        try:
            # Use reg.exe to export registry key
            hkey_str = self._hkey_to_string(hkey)
            cmd = f'reg export "{hkey_str}\\{subkey}" "{backup_path}" /y'
            
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode == 0:
                return {"success": True, "backup_path": backup_path}
            else:
                return {"success": False, "error": result.stderr}
                
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def _import_registry_key(self, backup_path: str) -> Dict[str, Any]:
        """Import registry key from file"""
        try:
            # Use reg.exe to import registry key
            cmd = f'reg import "{backup_path}"'
            
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode == 0:
                return {"success": True, "message": "Registry key imported successfully"}
            else:
                return {"success": False, "error": result.stderr}
                
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def _compare_key_info(self, current_info: Dict[str, Any], stored_info: Dict[str, Any]) -> List[str]:
        """Compare registry key info and return changes"""
        changes = []
        
        # Compare values
        current_values = current_info.get("values", {})
        stored_values = stored_info.get("values", {})
        
        # Check for new values
        for name, value_info in current_values.items():
            if name not in stored_values:
                changes.append(f"New value: {name}")
            elif value_info != stored_values[name]:
                changes.append(f"Modified value: {name}")
        
        # Check for deleted values
        for name in stored_values:
            if name not in current_values:
                changes.append(f"Deleted value: {name}")
        
        # Compare subkeys
        current_subkeys = set(current_info.get("subkeys", []))
        stored_subkeys = set(stored_info.get("subkeys", []))
        
        new_subkeys = current_subkeys - stored_subkeys
        deleted_subkeys = stored_subkeys - current_subkeys
        
        for subkey in new_subkeys:
            changes.append(f"New subkey: {subkey}")
        
        for subkey in deleted_subkeys:
            changes.append(f"Deleted subkey: {subkey}")
        
        return changes
    
    def _find_backup_by_id(self, backup_id: str) -> Optional[Dict[str, Any]]:
        """Find backup by ID"""
        for state in self.registry_history:
            if state["backup_id"] == backup_id:
                return state
        return None
    
    def _save_registry_states(self):
        """Save registry states to disk"""
        try:
            states_file = os.path.join(self.backup_dir, "registry_states.json")
            with open(states_file, 'w') as f:
                json.dump({
                    "registry_states": self.registry_states,
                    "registry_history": self.registry_history[-100:],  # Keep last 100
                    "critical_keys": self.critical_keys
                }, f, indent=2)
        except Exception as e:
            self.logger.error(f"Failed to save registry states: {e}")
    
    def load_registry_states(self):
        """Load registry states from disk"""
        try:
            states_file = os.path.join(self.backup_dir, "registry_states.json")
            if os.path.exists(states_file):
                with open(states_file, 'r') as f:
                    data = json.load(f)
                    self.registry_states = data.get("registry_states", {})
                    self.registry_history = data.get("registry_history", [])
                    self.critical_keys = data.get("critical_keys", {})
        except Exception as e:
            self.logger.error(f"Failed to load registry states: {e}")
    
    def cleanup_old_backups(self, days: int = 7):
        """Cleanup old backups"""
        try:
            cutoff_time = time.time() - (days * 24 * 60 * 60)
            
            # Cleanup registry history
            self.registry_history = [
                state for state in self.registry_history
                if datetime.fromisoformat(state["timestamp"]).timestamp() > cutoff_time
            ]
            
            # Cleanup backup files
            for backup_file in os.listdir(self.backup_dir):
                if backup_file.endswith('.reg'):
                    file_path = os.path.join(self.backup_dir, backup_file)
                    if os.path.getmtime(file_path) < cutoff_time:
                        os.remove(file_path)
            
            self._save_registry_states()
            
        except Exception as e:
            self.logger.error(f"Registry backup cleanup failed: {e}")
    
    def get_registry_statistics(self) -> Dict[str, Any]:
        """Get registry rollback statistics"""
        return {
            "total_backups": len(self.registry_states),
            "history_entries": len(self.registry_history),
            "critical_keys_monitored": len(self.critical_registry_keys),
            "backup_directory": self.backup_dir
        }
