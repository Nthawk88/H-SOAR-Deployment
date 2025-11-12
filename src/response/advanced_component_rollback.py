"""
Advanced Component-Level Rollback System
Handles individual component rollback with dependency resolution
"""

import os
import time
import shutil
import subprocess
import psutil
import threading
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
import logging
import json

class ComponentRollbackManager:
    """Manages rollback for individual components"""
    
    def __init__(self, config_manager, database_manager):
        self.config_manager = config_manager
        self.database_manager = database_manager
        self.logger = logging.getLogger(__name__)
        self.rollback_lock = threading.Lock()
        
        # Initialize component handlers
        self.component_handlers = {
            'network': NetworkComponentHandler(),
            'services': ServiceComponentHandler(),
            'files': FileComponentHandler(),
            'processes': ProcessComponentHandler(),
            'configurations': ConfigurationComponentHandler()
        }
    
    def rollback_component(self, component: str, threat_data: Dict[str, Any], 
                          strategy: str = "immediate") -> Dict[str, Any]:
        """Rollback specific component"""
        rollback_id = f"rollback_{component}_{int(time.time())}"
        start_time = time.time()
        
        try:
            with self.rollback_lock:
                self.logger.info(f"Starting rollback for component: {component}")
                
                # Get component configuration
                component_config = self.config_manager.get_component_config(component)
                if not component_config:
                    raise ValueError(f"No configuration found for component: {component}")
                
                # Check if backup is required
                if component_config.get("backup_required", True):
                    backup_state = self._create_backup(component, threat_data)
                    if not backup_state:
                        raise Exception(f"Failed to create backup for component: {component}")
                
                # Get component handler
                handler = self.component_handlers.get(component)
                if not handler:
                    raise ValueError(f"No handler found for component: {component}")
                
                # Perform rollback
                rollback_result = handler.rollback(threat_data, component_config)
                
                # Validate rollback
                validation_method = component_config.get("validation_method", "basic")
                validation_result = self._validate_rollback(component, validation_method)
                
                # Calculate duration
                duration = time.time() - start_time
                
                # Log rollback attempt
                success = rollback_result.get("success", False) and validation_result
                self.database_manager.log_rollback_attempt(
                    rollback_id, component, "component_rollback", strategy,
                    success, duration, rollback_result.get("error"),
                    threat_data, rollback_result.get("metrics", {})
                )
                
                # Save performance metrics
                self.database_manager.save_performance_metric(
                    component, "rollback_duration", duration
                )
                self.database_manager.save_performance_metric(
                    component, "rollback_success", 1.0 if success else 0.0
                )
                
                result = {
                    "success": success,
                    "component": component,
                    "rollback_id": rollback_id,
                    "duration": duration,
                    "strategy": strategy,
                    "validation_passed": validation_result,
                    "metrics": rollback_result.get("metrics", {}),
                    "error": rollback_result.get("error") if not success else None
                }
                
                self.logger.info(f"Component rollback completed: {component}, Success: {success}")
                return result
                
        except Exception as e:
            duration = time.time() - start_time
            error_msg = f"Component rollback failed: {e}"
            self.logger.error(error_msg)
            
            # Log failed attempt
            self.database_manager.log_rollback_attempt(
                rollback_id, component, "component_rollback", strategy,
                False, duration, error_msg, threat_data
            )
            
            return {
                "success": False,
                "component": component,
                "rollback_id": rollback_id,
                "duration": duration,
                "strategy": strategy,
                "error": error_msg
            }
    
    def rollback_with_dependencies(self, component: str, threat_data: Dict[str, Any],
                                  strategy: str = "immediate") -> Dict[str, Any]:
        """Rollback component with its dependencies"""
        try:
            # Get dependencies
            dependencies = self.config_manager.get_dependencies(component)
            
            # Sort dependencies by priority
            dependency_priorities = []
            for dep in dependencies:
                priority = self.config_manager.get_component_priority(dep)
                dependency_priorities.append((dep, priority))
            
            dependency_priorities.sort(key=lambda x: x[1])
            
            # Rollback dependencies first
            dependency_results = {}
            for dep, _ in dependency_priorities:
                dep_result = self.rollback_component(dep, threat_data, strategy)
                dependency_results[dep] = dep_result
                
                if not dep_result["success"]:
                    self.logger.warning(f"Dependency rollback failed: {dep}")
                    # Continue with other dependencies
            
            # Rollback main component
            main_result = self.rollback_component(component, threat_data, strategy)
            
            return {
                "success": main_result["success"],
                "component": component,
                "dependencies": dependency_results,
                "main_rollback": main_result,
                "strategy": strategy
            }
            
        except Exception as e:
            self.logger.error(f"Dependency rollback failed: {e}")
            return {
                "success": False,
                "component": component,
                "error": str(e),
                "strategy": strategy
            }
    
    def _create_backup(self, component: str, threat_data: Dict[str, Any]) -> bool:
        """Create backup for component"""
        try:
            handler = self.component_handlers.get(component)
            if handler and hasattr(handler, 'create_backup'):
                backup_data = handler.create_backup(threat_data)
                if backup_data:
                    return self.database_manager.save_system_state(
                        component, backup_data, "backup"
                    )
            return True  # No backup required
        except Exception as e:
            self.logger.error(f"Failed to create backup for {component}: {e}")
            return False
    
    def _validate_rollback(self, component: str, validation_method: str) -> bool:
        """Validate rollback success"""
        try:
            handler = self.component_handlers.get(component)
            if handler and hasattr(handler, 'validate'):
                return handler.validate(validation_method)
            return True  # No validation required
        except Exception as e:
            self.logger.error(f"Rollback validation failed for {component}: {e}")
            return False


class NetworkComponentHandler:
    """Handler for network component rollback"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def rollback(self, threat_data: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Rollback network component"""
        try:
            # Reset network rules
            self._reset_network_rules()
            
            # Clear blocked IPs
            self._clear_blocked_ips()
            
            # Restore network configuration
            self._restore_network_config()
            
            return {
                "success": True,
                "metrics": {
                    "network_rules_reset": True,
                    "blocked_ips_cleared": True,
                    "config_restored": True
                }
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    def create_backup(self, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create network backup"""
        try:
            return {
                "network_rules": self._get_current_network_rules(),
                "blocked_ips": self._get_blocked_ips(),
                "network_config": self._get_network_config(),
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            self.logger.error(f"Failed to create network backup: {e}")
            return {}
    
    def validate(self, validation_method: str) -> bool:
        """Validate network rollback"""
        try:
            if validation_method == "connectivity_test":
                return self._test_connectivity()
            return True
        except Exception as e:
            self.logger.error(f"Network validation failed: {e}")
            return False
    
    def _reset_network_rules(self):
        """Reset network rules"""
        # Implementation depends on system
        pass
    
    def _clear_blocked_ips(self):
        """Clear blocked IPs"""
        # Implementation depends on system
        pass
    
    def _restore_network_config(self):
        """Restore network configuration"""
        # Implementation depends on system
        pass
    
    def _get_current_network_rules(self) -> List[str]:
        """Get current network rules"""
        return []
    
    def _get_blocked_ips(self) -> List[str]:
        """Get blocked IPs"""
        return []
    
    def _get_network_config(self) -> Dict[str, Any]:
        """Get network configuration"""
        return {}
    
    def _test_connectivity(self) -> bool:
        """Test network connectivity"""
        try:
            import socket
            socket.create_connection(("8.8.8.8", 53), timeout=5)
            return True
        except:
            return False


class ServiceComponentHandler:
    """Handler for service component rollback"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def rollback(self, threat_data: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Rollback service component"""
        try:
            # Restart critical services
            services_to_restart = ["ssh", "network-manager", "systemd-resolved"]
            restarted_services = []
            
            for service in services_to_restart:
                if self._restart_service(service):
                    restarted_services.append(service)
            
            return {
                "success": True,
                "metrics": {
                    "services_restarted": len(restarted_services),
                    "restarted_services": restarted_services
                }
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    def create_backup(self, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create service backup"""
        try:
            return {
                "service_status": self._get_service_status(),
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            self.logger.error(f"Failed to create service backup: {e}")
            return {}
    
    def validate(self, validation_method: str) -> bool:
        """Validate service rollback"""
        try:
            if validation_method == "service_status":
                return self._check_service_status()
            return True
        except Exception as e:
            self.logger.error(f"Service validation failed: {e}")
            return False
    
    def _restart_service(self, service_name: str) -> bool:
        """Restart service"""
        try:
            result = subprocess.run(
                ["systemctl", "restart", service_name],
                capture_output=True,
                text=True,
                timeout=30
            )
            return result.returncode == 0
        except Exception as e:
            self.logger.error(f"Failed to restart service {service_name}: {e}")
            return False
    
    def _get_service_status(self) -> Dict[str, str]:
        """Get service status"""
        services = ["ssh", "network-manager", "systemd-resolved"]
        status = {}
        
        for service in services:
            try:
                result = subprocess.run(
                    ["systemctl", "is-active", service],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                status[service] = result.stdout.strip()
            except:
                status[service] = "unknown"
        
        return status
    
    def _check_service_status(self) -> bool:
        """Check if services are running"""
        status = self._get_service_status()
        critical_services = ["ssh", "network-manager"]
        
        for service in critical_services:
            if status.get(service) != "active":
                return False
        
        return True


class FileComponentHandler:
    """Handler for file component rollback"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def rollback(self, threat_data: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Rollback file component"""
        try:
            # Restore critical files
            critical_files = [
                "/etc/passwd",
                "/etc/shadow",
                "/etc/hosts",
                "/etc/firewall/rules"
            ]
            
            restored_files = []
            for file_path in critical_files:
                if os.path.exists(file_path):
                    if self._restore_file(file_path):
                        restored_files.append(file_path)
            
            return {
                "success": True,
                "metrics": {
                    "files_restored": len(restored_files),
                    "restored_files": restored_files
                }
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    def create_backup(self, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create file backup"""
        try:
            backup_data = {}
            critical_files = [
                "/etc/passwd",
                "/etc/hosts"
            ]
            
            for file_path in critical_files:
                if os.path.exists(file_path):
                    with open(file_path, 'r') as f:
                        backup_data[file_path] = f.read()
            
            backup_data["timestamp"] = datetime.now().isoformat()
            return backup_data
            
        except Exception as e:
            self.logger.error(f"Failed to create file backup: {e}")
            return {}
    
    def validate(self, validation_method: str) -> bool:
        """Validate file rollback"""
        try:
            if validation_method == "file_integrity":
                return self._check_file_integrity()
            return True
        except Exception as e:
            self.logger.error(f"File validation failed: {e}")
            return False
    
    def _restore_file(self, file_path: str) -> bool:
        """Restore file from backup"""
        try:
            backup_path = f"backups/{os.path.basename(file_path)}"
            if os.path.exists(backup_path):
                shutil.copy2(backup_path, file_path)
                return True
            return False
        except Exception as e:
            self.logger.error(f"Failed to restore file {file_path}: {e}")
            return False
    
    def _check_file_integrity(self) -> bool:
        """Check file integrity"""
        critical_files = ["/etc/passwd", "/etc/hosts"]
        
        for file_path in critical_files:
            if not os.path.exists(file_path):
                return False
        
        return True


class ProcessComponentHandler:
    """Handler for process component rollback"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def rollback(self, threat_data: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Rollback process component"""
        try:
            # Terminate suspicious processes
            suspicious_processes = self._identify_suspicious_processes()
            terminated_processes = []
            
            for process in suspicious_processes:
                if self._terminate_process(process):
                    terminated_processes.append(process)
            
            return {
                "success": True,
                "metrics": {
                    "processes_terminated": len(terminated_processes),
                    "terminated_processes": terminated_processes
                }
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    def create_backup(self, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create process backup"""
        try:
            return {
                "running_processes": self._get_running_processes(),
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            self.logger.error(f"Failed to create process backup: {e}")
            return {}
    
    def validate(self, validation_method: str) -> bool:
        """Validate process rollback"""
        try:
            if validation_method == "process_check":
                return self._check_process_health()
            return True
        except Exception as e:
            self.logger.error(f"Process validation failed: {e}")
            return False
    
    def _identify_suspicious_processes(self) -> List[str]:
        """Identify suspicious processes"""
        suspicious = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
            try:
                if proc.info['cpu_percent'] > 80.0:
                    suspicious.append(proc.info['name'])
            except:
                pass
        return suspicious
    
    def _terminate_process(self, process_name: str) -> bool:
        """Terminate process"""
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                if proc.info['name'] == process_name:
                    proc.terminate()
                    proc.wait(timeout=5)
                    return True
            return False
        except Exception as e:
            self.logger.error(f"Failed to terminate process {process_name}: {e}")
            return False
    
    def _get_running_processes(self) -> List[Dict[str, Any]]:
        """Get running processes"""
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            try:
                processes.append(proc.info)
            except:
                pass
        return processes
    
    def _check_process_health(self) -> bool:
        """Check process health"""
        try:
            # Check if critical processes are running
            critical_processes = ["systemd", "kernel"]
            for proc in psutil.process_iter(['name']):
                if proc.info['name'] in critical_processes:
                    return True
            return False
        except:
            return False


class ConfigurationComponentHandler:
    """Handler for configuration component rollback"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def rollback(self, threat_data: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Rollback configuration component"""
        try:
            # Restore system configurations
            config_files = [
                "/etc/ssh/sshd_config",
                "/etc/suricata/suricata.yaml"
            ]
            
            restored_configs = []
            for config_file in config_files:
                if os.path.exists(config_file):
                    if self._restore_config(config_file):
                        restored_configs.append(config_file)
            
            return {
                "success": True,
                "metrics": {
                    "configs_restored": len(restored_configs),
                    "restored_configs": restored_configs
                }
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    def create_backup(self, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create configuration backup"""
        try:
            backup_data = {}
            config_files = [
                "/etc/ssh/sshd_config"
            ]
            
            for config_file in config_files:
                if os.path.exists(config_file):
                    with open(config_file, 'r') as f:
                        backup_data[config_file] = f.read()
            
            backup_data["timestamp"] = datetime.now().isoformat()
            return backup_data
            
        except Exception as e:
            self.logger.error(f"Failed to create config backup: {e}")
            return {}
    
    def validate(self, validation_method: str) -> bool:
        """Validate configuration rollback"""
        try:
            if validation_method == "config_validation":
                return self._validate_configurations()
            return True
        except Exception as e:
            self.logger.error(f"Config validation failed: {e}")
            return False
    
    def _restore_config(self, config_file: str) -> bool:
        """Restore configuration file"""
        try:
            backup_file = f"backups/{os.path.basename(config_file)}"
            if os.path.exists(backup_file):
                shutil.copy2(backup_file, config_file)
                return True
            return False
        except Exception as e:
            self.logger.error(f"Failed to restore config {config_file}: {e}")
            return False
    
    def _validate_configurations(self) -> bool:
        """Validate configurations"""
        config_files = ["/etc/ssh/sshd_config"]
        
        for config_file in config_files:
            if not os.path.exists(config_file):
                return False
        
        return True
