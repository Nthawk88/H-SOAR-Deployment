"""
Advanced Rollback Configuration Management
Handles configuration for advanced rollback strategies and components
"""

import json
import os
from typing import Dict, List, Any, Optional
import logging

class AdvancedRollbackConfig:
    """Configuration management for advanced rollback system"""
    
    def __init__(self, config_path: str = "config/advanced_rollback_config.json"):
        self.config_path = config_path
        self.logger = logging.getLogger(__name__)
        self.config = self._load_config()
    
    def _load_config(self) -> Dict[str, Any]:
        """Load advanced rollback configuration"""
        default_config = {
            "rollback_strategies": {
                "immediate": {
                    "timeout": 30,
                    "retry_count": 3,
                    "retry_delay": 5,
                    "parallel_rollback": False,
                    "validation_required": True
                },
                "gradual": {
                    "timeout": 60,
                    "retry_count": 5,
                    "retry_delay": 10,
                    "parallel_rollback": True,
                    "validation_required": True
                },
                "emergency": {
                    "timeout": 15,
                    "retry_count": 1,
                    "retry_delay": 2,
                    "parallel_rollback": False,
                    "validation_required": False
                },
                "selective": {
                    "timeout": 45,
                    "retry_count": 4,
                    "retry_delay": 7,
                    "parallel_rollback": True,
                    "validation_required": True
                }
            },
            "components": {
                "network": {
                    "priority": 1,
                    "dependencies": [],
                    "rollback_method": "network_reset",
                    "backup_required": True,
                    "validation_method": "connectivity_test"
                },
                "services": {
                    "priority": 2,
                    "dependencies": ["network"],
                    "rollback_method": "service_restart",
                    "backup_required": True,
                    "validation_method": "service_status"
                },
                "files": {
                    "priority": 3,
                    "dependencies": ["services"],
                    "rollback_method": "file_restore",
                    "backup_required": True,
                    "validation_method": "file_integrity"
                },
                "processes": {
                    "priority": 4,
                    "dependencies": ["files"],
                    "rollback_method": "process_termination",
                    "backup_required": False,
                    "validation_method": "process_check"
                },
                "configurations": {
                    "priority": 5,
                    "dependencies": ["processes"],
                    "rollback_method": "config_restore",
                    "backup_required": True,
                    "validation_method": "config_validation"
                }
            },
            "monitoring": {
                "enabled": True,
                "interval": 1,
                "metrics_retention_days": 30,
                "real_time_alerts": True,
                "performance_tracking": True
            },
            "security": {
                "authentication_required": False,
                "authorization_enabled": False,
                "audit_logging": True,
                "integrity_check": True,
                "encryption_enabled": False
            },
            "performance": {
                "max_concurrent_rollbacks": 3,
                "rollback_timeout_multiplier": 1.5,
                "resource_monitoring": True,
                "performance_thresholds": {
                    "max_cpu_usage": 80.0,
                    "max_memory_usage": 85.0,
                    "max_disk_usage": 90.0
                }
            },
            "backup": {
                "enabled": True,
                "backup_interval": 300,  # 5 minutes
                "retention_days": 7,
                "compression_enabled": True,
                "encryption_enabled": False,
                "backup_locations": [
                    "backups/system_state",
                    "backups/configurations",
                    "backups/critical_files"
                ]
            },
            "error_handling": {
                "max_retry_attempts": 3,
                "retry_backoff_factor": 2,
                "circuit_breaker_enabled": True,
                "fallback_strategy": "emergency",
                "error_notification": True
            }
        }
        
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r') as f:
                    user_config = json.load(f)
                # Merge with default config
                config = self._merge_configs(default_config, user_config)
            else:
                config = default_config
                self._save_config(config)
            
            self.logger.info("Advanced rollback configuration loaded successfully")
            return config
            
        except Exception as e:
            self.logger.error(f"Failed to load configuration: {e}")
            return default_config
    
    def _merge_configs(self, default: Dict[str, Any], user: Dict[str, Any]) -> Dict[str, Any]:
        """Merge user config with default config"""
        result = default.copy()
        
        for key, value in user.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._merge_configs(result[key], value)
            else:
                result[key] = value
        
        return result
    
    def _save_config(self, config: Dict[str, Any]) -> bool:
        """Save configuration to file"""
        try:
            os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
            with open(self.config_path, 'w') as f:
                json.dump(config, f, indent=2)
            self.logger.info(f"Configuration saved to {self.config_path}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to save configuration: {e}")
            return False
    
    def get_strategy_config(self, strategy: str) -> Dict[str, Any]:
        """Get configuration for specific strategy"""
        return self.config.get("rollback_strategies", {}).get(strategy, {})
    
    def get_component_config(self, component: str) -> Dict[str, Any]:
        """Get configuration for specific component"""
        return self.config.get("components", {}).get(component, {})
    
    def get_dependencies(self, component: str) -> List[str]:
        """Get dependencies for component"""
        component_config = self.get_component_config(component)
        return component_config.get("dependencies", [])
    
    def get_component_priority(self, component: str) -> int:
        """Get priority for component"""
        component_config = self.get_component_config(component)
        return component_config.get("priority", 999)
    
    def get_rollback_method(self, component: str) -> str:
        """Get rollback method for component"""
        component_config = self.get_component_config(component)
        return component_config.get("rollback_method", "default")
    
    def is_backup_required(self, component: str) -> bool:
        """Check if backup is required for component"""
        component_config = self.get_component_config(component)
        return component_config.get("backup_required", True)
    
    def get_validation_method(self, component: str) -> str:
        """Get validation method for component"""
        component_config = self.get_component_config(component)
        return component_config.get("validation_method", "basic")
    
    def get_monitoring_config(self) -> Dict[str, Any]:
        """Get monitoring configuration"""
        return self.config.get("monitoring", {})
    
    def get_security_config(self) -> Dict[str, Any]:
        """Get security configuration"""
        return self.config.get("security", {})
    
    def get_performance_config(self) -> Dict[str, Any]:
        """Get performance configuration"""
        return self.config.get("performance", {})
    
    def get_backup_config(self) -> Dict[str, Any]:
        """Get backup configuration"""
        return self.config.get("backup", {})
    
    def get_error_handling_config(self) -> Dict[str, Any]:
        """Get error handling configuration"""
        return self.config.get("error_handling", {})
    
    def update_config(self, section: str, key: str, value: Any) -> bool:
        """Update specific configuration value"""
        try:
            if section not in self.config:
                self.config[section] = {}
            
            self.config[section][key] = value
            return self._save_config(self.config)
            
        except Exception as e:
            self.logger.error(f"Failed to update configuration: {e}")
            return False
    
    def reload_config(self) -> bool:
        """Reload configuration from file"""
        try:
            self.config = self._load_config()
            self.logger.info("Configuration reloaded successfully")
            return True
        except Exception as e:
            self.logger.error(f"Failed to reload configuration: {e}")
            return False
    
    def validate_config(self) -> List[str]:
        """Validate configuration"""
        errors = []
        
        try:
            # Validate strategies
            strategies = self.config.get("rollback_strategies", {})
            for strategy_name, strategy_config in strategies.items():
                if not isinstance(strategy_config, dict):
                    errors.append(f"Strategy {strategy_name} must be a dictionary")
                    continue
                
                required_fields = ["timeout", "retry_count", "retry_delay"]
                for field in required_fields:
                    if field not in strategy_config:
                        errors.append(f"Strategy {strategy_name} missing required field: {field}")
            
            # Validate components
            components = self.config.get("components", {})
            for component_name, component_config in components.items():
                if not isinstance(component_config, dict):
                    errors.append(f"Component {component_name} must be a dictionary")
                    continue
                
                required_fields = ["priority", "dependencies", "rollback_method"]
                for field in required_fields:
                    if field not in component_config:
                        errors.append(f"Component {component_name} missing required field: {field}")
            
            # Validate dependencies
            for component_name, component_config in components.items():
                dependencies = component_config.get("dependencies", [])
                for dep in dependencies:
                    if dep not in components:
                        errors.append(f"Component {component_name} has invalid dependency: {dep}")
            
            if errors:
                self.logger.warning(f"Configuration validation found {len(errors)} errors")
            else:
                self.logger.info("Configuration validation passed")
            
            return errors
            
        except Exception as e:
            self.logger.error(f"Configuration validation failed: {e}")
            return [f"Configuration validation error: {e}"]
