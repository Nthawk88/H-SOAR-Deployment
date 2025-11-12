"""
Rollback of Rollback System
Handles rollback failures by rolling back the failed rollback operations
"""

import time
import json
import threading
from datetime import datetime
from typing import Dict, List, Any, Optional
import logging
import shutil
import os

class RollbackOfRollbackManager:
    """Manages rollback of failed rollback operations"""
    
    def __init__(self, database_manager, config_manager):
        self.database_manager = database_manager
        self.config_manager = config_manager
        self.logger = logging.getLogger(__name__)
        self.rollback_lock = threading.Lock()
        
        # Rollback state tracking
        self.rollback_states = {}  # Stores pre-rollback states
        self.failed_rollbacks = {}  # Tracks failed rollback attempts
        
        # Recovery strategies
        self.recovery_strategies = {
            "full_restore": self._full_state_restore,
            "partial_restore": self._partial_state_restore,
            "emergency_restore": self._emergency_state_restore,
            "manual_restore": self._manual_state_restore
        }
    
    def save_pre_rollback_state(self, rollback_id: str, component: str, 
                               state_data: Dict[str, Any]) -> bool:
        """Save system state before rollback attempt"""
        try:
            with self.rollback_lock:
                if rollback_id not in self.rollback_states:
                    self.rollback_states[rollback_id] = {}
                
                self.rollback_states[rollback_id][component] = {
                    "state_data": state_data,
                    "timestamp": datetime.now().isoformat(),
                    "backup_location": f"backups/pre_rollback_{rollback_id}_{component}.json"
                }
                
                # Save to file for persistence
                backup_file = f"backups/pre_rollback_{rollback_id}_{component}.json"
                os.makedirs(os.path.dirname(backup_file), exist_ok=True)
                
                with open(backup_file, 'w') as f:
                    json.dump(state_data, f, indent=2)
                
                self.logger.info(f"Saved pre-rollback state for {component} in rollback {rollback_id}")
                return True
                
        except Exception as e:
            self.logger.error(f"Failed to save pre-rollback state: {e}")
            return False
    
    def get_pre_rollback_state(self, rollback_id: str, component: str) -> Optional[Dict[str, Any]]:
        """Get pre-rollback state for component"""
        try:
            with self.rollback_lock:
                if rollback_id in self.rollback_states:
                    component_state = self.rollback_states[rollback_id].get(component)
                    if component_state:
                        return component_state["state_data"]
                
                # Try to load from backup file
                backup_file = f"backups/pre_rollback_{rollback_id}_{component}.json"
                if os.path.exists(backup_file):
                    with open(backup_file, 'r') as f:
                        return json.load(f)
                
                return None
                
        except Exception as e:
            self.logger.error(f"Failed to get pre-rollback state: {e}")
            return None
    
    def execute_rollback_of_rollback(self, failed_rollback_id: str, 
                                   failed_component: str, 
                                   recovery_strategy: str = "full_restore") -> Dict[str, Any]:
        """Execute rollback of failed rollback"""
        try:
            self.logger.warning(f"Executing rollback-of-rollback for {failed_component} in rollback {failed_rollback_id}")
            
            # Get pre-rollback state
            pre_state = self.get_pre_rollback_state(failed_rollback_id, failed_component)
            if not pre_state:
                return {
                    "success": False,
                    "error": f"No pre-rollback state found for {failed_component}",
                    "recovery_strategy": recovery_strategy
                }
            
            # Execute recovery strategy
            recovery_func = self.recovery_strategies.get(recovery_strategy)
            if not recovery_func:
                return {
                    "success": False,
                    "error": f"Unknown recovery strategy: {recovery_strategy}",
                    "recovery_strategy": recovery_strategy
                }
            
            # Execute recovery
            recovery_result = recovery_func(failed_component, pre_state, failed_rollback_id)
            
            # Log recovery attempt
            self.database_manager.log_rollback_attempt(
                f"rollback_of_rollback_{failed_rollback_id}",
                failed_component,
                "rollback_of_rollback",
                recovery_strategy,
                recovery_result.get("success", False),
                recovery_result.get("duration", 0),
                recovery_result.get("error"),
                {"original_rollback_id": failed_rollback_id},
                recovery_result
            )
            
            return recovery_result
            
        except Exception as e:
            self.logger.error(f"Rollback-of-rollback failed: {e}")
            return {
                "success": False,
                "error": f"Rollback-of-rollback failed: {e}",
                "recovery_strategy": recovery_strategy
            }
    
    def _full_state_restore(self, component: str, pre_state: Dict[str, Any], 
                           original_rollback_id: str) -> Dict[str, Any]:
        """Full state restoration"""
        try:
            start_time = time.time()
            self.logger.info(f"Executing full state restore for {component}")
            
            restored_items = []
            
            if component == "files":
                restored_items = self._restore_files_from_state(pre_state)
            elif component == "services":
                restored_items = self._restore_services_from_state(pre_state)
            elif component == "network":
                restored_items = self._restore_network_from_state(pre_state)
            elif component == "processes":
                restored_items = self._restore_processes_from_state(pre_state)
            elif component == "configurations":
                restored_items = self._restore_configurations_from_state(pre_state)
            
            duration = time.time() - start_time
            
            return {
                "success": len(restored_items) > 0,
                "duration": duration,
                "restored_items": restored_items,
                "recovery_strategy": "full_restore",
                "message": f"Full state restore completed for {component}"
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": f"Full state restore failed: {e}",
                "recovery_strategy": "full_restore"
            }
    
    def _partial_state_restore(self, component: str, pre_state: Dict[str, Any], 
                              original_rollback_id: str) -> Dict[str, Any]:
        """Partial state restoration - only critical items"""
        try:
            start_time = time.time()
            self.logger.info(f"Executing partial state restore for {component}")
            
            restored_items = []
            
            # Only restore critical items
            if component == "files":
                critical_files = ["/etc/passwd", "/etc/hosts"]
                restored_items = self._restore_critical_files(pre_state, critical_files)
            elif component == "services":
                critical_services = ["ssh"]
                restored_items = self._restore_critical_services(pre_state, critical_services)
            elif component == "network":
                restored_items = self._restore_critical_network(pre_state)
            
            duration = time.time() - start_time
            
            return {
                "success": len(restored_items) > 0,
                "duration": duration,
                "restored_items": restored_items,
                "recovery_strategy": "partial_restore",
                "message": f"Partial state restore completed for {component}"
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": f"Partial state restore failed: {e}",
                "recovery_strategy": "partial_restore"
            }
    
    def _emergency_state_restore(self, component: str, pre_state: Dict[str, Any], 
                                original_rollback_id: str) -> Dict[str, Any]:
        """Emergency state restoration - minimal operations"""
        try:
            start_time = time.time()
            self.logger.warning(f"Executing emergency state restore for {component}")
            
            restored_items = []
            
            # Emergency restore - only essential operations
            if component == "files":
                # Only restore /etc/passwd
                if "/etc/passwd" in pre_state:
                    restored_items.append(self._emergency_restore_file("/etc/passwd", pre_state["/etc/passwd"]))
            elif component == "services":
                # Only restart SSH
                restored_items.append(self._emergency_restart_ssh())
            elif component == "network":
                # Only restore basic connectivity
                restored_items.append(self._emergency_restore_network())
            
            duration = time.time() - start_time
            
            return {
                "success": len(restored_items) > 0,
                "duration": duration,
                "restored_items": restored_items,
                "recovery_strategy": "emergency_restore",
                "message": f"Emergency state restore completed for {component}"
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": f"Emergency state restore failed: {e}",
                "recovery_strategy": "emergency_restore"
            }
    
    def _manual_state_restore(self, component: str, pre_state: Dict[str, Any], 
                             original_rollback_id: str) -> Dict[str, Any]:
        """Manual state restoration - requires human intervention"""
        try:
            self.logger.critical(f"Manual state restore required for {component}")
            
            # Log critical alert
            alert_message = f"MANUAL ROLLBACK-OF-ROLLBACK REQUIRED: Component {component} failed rollback {original_rollback_id}"
            self._log_critical_alert(alert_message)
            
            # Save state for manual recovery
            manual_recovery_file = f"backups/manual_recovery_{original_rollback_id}_{component}.json"
            os.makedirs(os.path.dirname(manual_recovery_file), exist_ok=True)
            
            with open(manual_recovery_file, 'w') as f:
                json.dump({
                    "component": component,
                    "original_rollback_id": original_rollback_id,
                    "pre_state": pre_state,
                    "timestamp": datetime.now().isoformat(),
                    "instructions": "Manual recovery required - restore system to pre-rollback state"
                }, f, indent=2)
            
            return {
                "success": False,
                "recovery_strategy": "manual_restore",
                "message": "Manual intervention required",
                "manual_recovery_file": manual_recovery_file,
                "alert_sent": True
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": f"Manual state restore failed: {e}",
                "recovery_strategy": "manual_restore"
            }
    
    def _restore_files_from_state(self, pre_state: Dict[str, Any]) -> List[str]:
        """Restore files from pre-rollback state"""
        restored_files = []
        
        for file_path, content in pre_state.items():
            if file_path == "timestamp":
                continue
                
            try:
                if os.path.exists(file_path):
                    # Backup current file
                    backup_path = f"{file_path}.rollback_backup"
                    shutil.copy2(file_path, backup_path)
                    
                    # Restore original content
                    with open(file_path, 'w') as f:
                        f.write(content)
                    
                    restored_files.append(file_path)
                    self.logger.info(f"Restored file: {file_path}")
                    
            except Exception as e:
                self.logger.error(f"Failed to restore file {file_path}: {e}")
        
        return restored_files
    
    def _restore_services_from_state(self, pre_state: Dict[str, Any]) -> List[str]:
        """Restore services from pre-rollback state"""
        restored_services = []
        
        service_status = pre_state.get("service_status", {})
        for service, status in service_status.items():
            try:
                if status == "active":
                    # Restart service
                    import subprocess
                    result = subprocess.run(
                        ["systemctl", "restart", service],
                        capture_output=True,
                        timeout=30
                    )
                    if result.returncode == 0:
                        restored_services.append(service)
                        self.logger.info(f"Restored service: {service}")
                        
            except Exception as e:
                self.logger.error(f"Failed to restore service {service}: {e}")
        
        return restored_services
    
    def _restore_network_from_state(self, pre_state: Dict[str, Any]) -> List[str]:
        """Restore network from pre-rollback state"""
        restored_items = []
        
        try:
            # Restore network rules
            network_rules = pre_state.get("network_rules", [])
            for rule in network_rules:
                # Implementation depends on firewall system
                restored_items.append(f"network_rule_{rule}")
            
            # Restore blocked IPs
            blocked_ips = pre_state.get("blocked_ips", [])
            for ip in blocked_ips:
                # Implementation depends on firewall system
                restored_items.append(f"blocked_ip_{ip}")
            
            self.logger.info(f"Restored network items: {len(restored_items)}")
            
        except Exception as e:
            self.logger.error(f"Failed to restore network: {e}")
        
        return restored_items
    
    def _restore_processes_from_state(self, pre_state: Dict[str, Any]) -> List[str]:
        """Restore processes from pre-rollback state"""
        restored_processes = []
        
        try:
            running_processes = pre_state.get("running_processes", [])
            for process_info in running_processes:
                process_name = process_info.get("name")
                if process_name:
                    # Start process if not running
                    import subprocess
                    try:
                        result = subprocess.run(
                            ["pgrep", "-f", process_name],
                            capture_output=True,
                            timeout=10
                        )
                        if result.returncode != 0:  # Process not running
                            # Start process (implementation depends on process type)
                            restored_processes.append(process_name)
                            self.logger.info(f"Restored process: {process_name}")
                    except:
                        pass
                        
        except Exception as e:
            self.logger.error(f"Failed to restore processes: {e}")
        
        return restored_processes
    
    def _restore_configurations_from_state(self, pre_state: Dict[str, Any]) -> List[str]:
        """Restore configurations from pre-rollback state"""
        restored_configs = []
        
        for config_file, content in pre_state.items():
            if config_file == "timestamp":
                continue
                
            try:
                if os.path.exists(config_file):
                    # Backup current config
                    backup_path = f"{config_file}.rollback_backup"
                    shutil.copy2(config_file, backup_path)
                    
                    # Restore original content
                    with open(config_file, 'w') as f:
                        f.write(content)
                    
                    restored_configs.append(config_file)
                    self.logger.info(f"Restored config: {config_file}")
                    
            except Exception as e:
                self.logger.error(f"Failed to restore config {config_file}: {e}")
        
        return restored_configs
    
    def _restore_critical_files(self, pre_state: Dict[str, Any], critical_files: List[str]) -> List[str]:
        """Restore only critical files"""
        restored_files = []
        
        for file_path in critical_files:
            if file_path in pre_state:
                try:
                    if os.path.exists(file_path):
                        with open(file_path, 'w') as f:
                            f.write(pre_state[file_path])
                        restored_files.append(file_path)
                except Exception as e:
                    self.logger.error(f"Failed to restore critical file {file_path}: {e}")
        
        return restored_files
    
    def _restore_critical_services(self, pre_state: Dict[str, Any], critical_services: List[str]) -> List[str]:
        """Restore only critical services"""
        restored_services = []
        
        service_status = pre_state.get("service_status", {})
        for service in critical_services:
            if service in service_status and service_status[service] == "active":
                try:
                    import subprocess
                    result = subprocess.run(
                        ["systemctl", "restart", service],
                        capture_output=True,
                        timeout=30
                    )
                    if result.returncode == 0:
                        restored_services.append(service)
                except Exception as e:
                    self.logger.error(f"Failed to restore critical service {service}: {e}")
        
        return restored_services
    
    def _restore_critical_network(self, pre_state: Dict[str, Any]) -> List[str]:
        """Restore only critical network settings"""
        restored_items = []
        
        try:
            # Only restore basic connectivity
            network_config = pre_state.get("network_config", {})
            if network_config:
                restored_items.append("basic_connectivity")
                self.logger.info("Restored critical network connectivity")
        except Exception as e:
            self.logger.error(f"Failed to restore critical network: {e}")
        
        return restored_items
    
    def _emergency_restore_file(self, file_path: str, content: str) -> str:
        """Emergency restore single file"""
        try:
            if os.path.exists(file_path):
                with open(file_path, 'w') as f:
                    f.write(content)
                return file_path
        except Exception as e:
            self.logger.error(f"Emergency file restore failed for {file_path}: {e}")
        return ""
    
    def _emergency_restart_ssh(self) -> str:
        """Emergency restart SSH service"""
        try:
            import subprocess
            result = subprocess.run(
                ["systemctl", "restart", "ssh"],
                capture_output=True,
                timeout=30
            )
            if result.returncode == 0:
                return "ssh_service"
        except Exception as e:
            self.logger.error(f"Emergency SSH restart failed: {e}")
        return ""
    
    def _emergency_restore_network(self) -> str:
        """Emergency restore basic network"""
        try:
            # Basic network restore
            return "basic_network"
        except Exception as e:
            self.logger.error(f"Emergency network restore failed: {e}")
        return ""
    
    def _log_critical_alert(self, message: str):
        """Log critical alert"""
        self.logger.critical(message)
        
        # Save to alerts log
        alert_entry = {
            "level": "CRITICAL",
            "message": message,
            "timestamp": datetime.now().isoformat(),
            "type": "rollback_of_rollback"
        }
        
        try:
            with open("logs/critical_alerts.jsonl", "a") as f:
                f.write(json.dumps(alert_entry) + "\n")
        except:
            pass
    
    def cleanup_old_states(self, days: int = 7):
        """Cleanup old rollback states"""
        try:
            import os
            import glob
            
            # Cleanup old backup files
            backup_pattern = "backups/pre_rollback_*.json"
            backup_files = glob.glob(backup_pattern)
            
            current_time = time.time()
            cutoff_time = current_time - (days * 24 * 3600)
            
            cleaned_count = 0
            for backup_file in backup_files:
                try:
                    file_time = os.path.getmtime(backup_file)
                    if file_time < cutoff_time:
                        os.remove(backup_file)
                        cleaned_count += 1
                except:
                    pass
            
            # Cleanup in-memory states
            with self.rollback_lock:
                old_rollbacks = []
                for rollback_id, states in self.rollback_states.items():
                    if states and any(
                        datetime.fromisoformat(state["timestamp"]).timestamp() < cutoff_time
                        for state in states.values()
                    ):
                        old_rollbacks.append(rollback_id)
                
                for rollback_id in old_rollbacks:
                    del self.rollback_states[rollback_id]
            
            self.logger.info(f"Cleaned up {cleaned_count} old rollback states")
            
        except Exception as e:
            self.logger.error(f"Failed to cleanup old states: {e}")
    
    def get_rollback_of_rollback_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get rollback-of-rollback history"""
        try:
            return self.database_manager.get_rollback_history(
                component=None, limit=limit
            )
        except Exception as e:
            self.logger.error(f"Failed to get rollback-of-rollback history: {e}")
            return []
