"""
Advanced Rollback Engine - Main Integration
Integrates all advanced rollback components into a unified system
"""

import time
import threading
from datetime import datetime
from typing import Dict, List, Any, Optional
import logging
import json
import uuid

# Import all advanced rollback components
from .advanced_rollback_db import AdvancedRollbackDatabase
from .advanced_rollback_config import AdvancedRollbackConfig
from .advanced_component_rollback import ComponentRollbackManager
from .advanced_error_handler import AdvancedErrorHandler
from .advanced_monitoring import RealTimeMonitor
from .rollback_of_rollback import RollbackOfRollbackManager
from .post_rollback_action_manager import PostRollbackActionManager

class AdvancedRollbackEngine:
    """Main advanced rollback engine that integrates all components"""
    
    def __init__(self, config_path: str = "config/advanced_rollback_config.json"):
        self.logger = logging.getLogger(__name__)
        
        # Initialize components
        self.config_manager = AdvancedRollbackConfig(config_path)
        self.database_manager = AdvancedRollbackDatabase()
        self.component_manager = ComponentRollbackManager(self.config_manager, self.database_manager)
        self.error_handler = AdvancedErrorHandler(self.config_manager)
        self.monitor = RealTimeMonitor(self.config_manager, self.database_manager)
        self.rollback_of_rollback = RollbackOfRollbackManager(self.database_manager, self.config_manager)
        self.post_action_manager = PostRollbackActionManager(self.database_manager, self.config_manager)
        
        # System state
        self.is_initialized = False
        self.active_rollbacks = {}
        self.rollback_lock = threading.Lock()
        
        # Performance tracking
        self.total_rollbacks = 0
        self.successful_rollbacks = 0
        self.failed_rollbacks = 0
        
        # Initialize system
        self._initialize_system()
    
    def _initialize_system(self):
        """Initialize the advanced rollback system"""
        try:
            # Validate configuration
            config_errors = self.config_manager.validate_config()
            if config_errors:
                self.logger.warning(f"Configuration validation found {len(config_errors)} errors")
                for error in config_errors:
                    self.logger.warning(f"Config error: {error}")
            
            # Initialize component dependencies
            self._initialize_component_dependencies()
            
            # Start monitoring
            self.monitor.start_monitoring()
            
            # Cleanup old data
            self.database_manager.cleanup_old_data(days=30)
            
            self.is_initialized = True
            self.logger.info("Advanced rollback system initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize advanced rollback system: {e}")
            raise
    
    def _initialize_component_dependencies(self):
        """Initialize component dependencies in database"""
        try:
            components = self.config_manager.config.get("components", {})
            
            for component, config in components.items():
                dependencies = config.get("dependencies", [])
                for dep in dependencies:
                    self.database_manager.save_component_dependency(component, dep)
            
            self.logger.info("Component dependencies initialized")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize component dependencies: {e}")
    
    def perform_advanced_rollback(self, threat_data: Dict[str, Any], 
                                 strategy: str = "immediate",
                                 components: List[str] = None) -> Dict[str, Any]:
        """Perform advanced rollback with all features"""
        if not self.is_initialized:
            return {
                "success": False,
                "error": "Advanced rollback system not initialized"
            }
        
        rollback_id = f"advanced_rollback_{uuid.uuid4().hex[:8]}"
        start_time = time.time()
        
        try:
            self.logger.info(f"Starting advanced rollback: {rollback_id}")
            
            # Determine components to rollback
            if components is None:
                components = self._determine_rollback_components(threat_data)
            
            # Get strategy configuration
            strategy_config = self.config_manager.get_strategy_config(strategy)
            if not strategy_config:
                return {
                    "success": False,
                    "error": f"Unknown rollback strategy: {strategy}"
                }
            
            # Start monitoring this rollback
            self.monitor.start_rollback_monitoring(
                rollback_id, "system", strategy_config.get("timeout", 300)
            )
            
            # Save pre-rollback states for all components
            self._save_pre_rollback_states(rollback_id, components, threat_data)
            
            # Perform rollback with error handling
            rollback_result = self.error_handler.handle_rollback_with_retry(
                self._execute_rollback_components,
                "system",
                threat_data,
                strategy
            )
            
            # Execute component rollbacks
            component_results = self._execute_rollback_components("system", threat_data, strategy)
            
            # Calculate duration
            duration = time.time() - start_time
            
            # Complete monitoring
            success = component_results.get("success", False)
            self.monitor.complete_rollback_monitoring(rollback_id, success)
            
            # Handle rollback-of-rollback if rollback failed
            rollback_of_rollback_result = None
            if not success:
                rollback_of_rollback_result = self._handle_rollback_of_rollback(
                    rollback_id, components, threat_data, component_results
                )
            
            # Execute post rollback-of-rollback actions
            post_action_result = None
            if rollback_of_rollback_result:
                post_action_result = self.post_action_manager.execute_post_rollback_actions(
                    component_results, rollback_of_rollback_result, threat_data
                )
            
            # Update statistics
            self._update_statistics(success)
            
            # Generate comprehensive result
            result = {
                "success": success,
                "rollback_id": rollback_id,
                "strategy": strategy,
                "duration": duration,
                "components_rolled_back": components,
                "component_results": component_results,
                "performance_metrics": self._get_performance_metrics(),
                "error_handling": rollback_result,
                "rollback_of_rollback": rollback_of_rollback_result,
                "post_actions": post_action_result,
                "timestamp": datetime.now().isoformat()
            }
            
            # Log rollback attempt
            self.database_manager.log_rollback_attempt(
                rollback_id, "system", "advanced_rollback", strategy,
                success, duration, component_results.get("error"),
                threat_data, result
            )
            
            self.logger.info(f"Advanced rollback completed: {rollback_id}, Success: {success}")
            return result
            
        except Exception as e:
            duration = time.time() - start_time
            error_msg = f"Advanced rollback failed: {e}"
            self.logger.error(error_msg)
            
            # Complete monitoring with failure
            self.monitor.complete_rollback_monitoring(rollback_id, False)
            
            # Update statistics
            self._update_statistics(False)
            
            return {
                "success": False,
                "rollback_id": rollback_id,
                "strategy": strategy,
                "duration": duration,
                "error": error_msg,
                "timestamp": datetime.now().isoformat()
            }
    
    def _determine_rollback_components(self, threat_data: Dict[str, Any]) -> List[str]:
        """Determine which components need rollback based on threat data"""
        try:
            # Default components
            default_components = ["network", "services", "files", "processes"]
            
            # Analyze threat data to determine affected components
            threat_type = threat_data.get("threat_type", "unknown")
            severity = threat_data.get("severity", "medium")
            
            if threat_type in ["ddos", "network_scan", "brute_force"]:
                return ["network", "services"]
            elif threat_type in ["malware", "ransomware"]:
                return ["processes", "files", "services"]
            elif threat_type in ["system_exploit"]:
                return default_components
            elif severity == "critical":
                return default_components
            else:
                return ["processes"]  # Minimal rollback for low severity
            
        except Exception as e:
            self.logger.error(f"Failed to determine rollback components: {e}")
            return ["processes"]  # Safe default
    
    def _execute_rollback_components(self, component: str, threat_data: Dict[str, Any], 
                                   strategy: str) -> Dict[str, Any]:
        """Execute rollback for all components"""
        try:
            components = self._determine_rollback_components(threat_data)
            strategy_config = self.config_manager.get_strategy_config(strategy)
            
            # Check if parallel rollback is allowed
            parallel_rollback = strategy_config.get("parallel_rollback", False)
            
            if parallel_rollback:
                return self._execute_parallel_rollback(components, threat_data, strategy)
            else:
                return self._execute_sequential_rollback(components, threat_data, strategy)
                
        except Exception as e:
            return {
                "success": False,
                "error": f"Component rollback execution failed: {e}"
            }
    
    def _execute_sequential_rollback(self, components: List[str], threat_data: Dict[str, Any],
                                   strategy: str) -> Dict[str, Any]:
        """Execute rollback sequentially"""
        try:
            results = {}
            overall_success = True
            
            # Sort components by priority
            component_priorities = []
            for component in components:
                priority = self.config_manager.get_component_priority(component)
                component_priorities.append((component, priority))
            
            component_priorities.sort(key=lambda x: x[1])
            
            # Execute rollbacks in priority order
            for component, _ in component_priorities:
                result = self.component_manager.rollback_with_dependencies(
                    component, threat_data, strategy
                )
                results[component] = result
                
                if not result.get("success", False):
                    overall_success = False
                    self.logger.warning(f"Component rollback failed: {component}")
            
            return {
                "success": overall_success,
                "component_results": results,
                "strategy": "sequential"
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": f"Sequential rollback failed: {e}"
            }
    
    def _execute_parallel_rollback(self, components: List[str], threat_data: Dict[str, Any],
                                  strategy: str) -> Dict[str, Any]:
        """Execute rollback in parallel"""
        try:
            import concurrent.futures
            
            results = {}
            overall_success = True
            
            # Execute rollbacks in parallel
            with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
                future_to_component = {
                    executor.submit(
                        self.component_manager.rollback_with_dependencies,
                        component, threat_data, strategy
                    ): component for component in components
                }
                
                for future in concurrent.futures.as_completed(future_to_component):
                    component = future_to_component[future]
                    try:
                        result = future.result()
                        results[component] = result
                        
                        if not result.get("success", False):
                            overall_success = False
                            self.logger.warning(f"Parallel component rollback failed: {component}")
                            
                    except Exception as e:
                        results[component] = {
                            "success": False,
                            "error": f"Parallel rollback failed: {e}"
                        }
                        overall_success = False
            
            return {
                "success": overall_success,
                "component_results": results,
                "strategy": "parallel"
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": f"Parallel rollback failed: {e}"
            }
    
    def _update_statistics(self, success: bool):
        """Update rollback statistics"""
        self.total_rollbacks += 1
        if success:
            self.successful_rollbacks += 1
        else:
            self.failed_rollbacks += 1
    
    def _get_performance_metrics(self) -> Dict[str, Any]:
        """Get current performance metrics"""
        try:
            return {
                "total_rollbacks": self.total_rollbacks,
                "successful_rollbacks": self.successful_rollbacks,
                "failed_rollbacks": self.failed_rollbacks,
                "success_rate": (self.successful_rollbacks / self.total_rollbacks * 100) if self.total_rollbacks > 0 else 0,
                "monitoring_status": self.monitor.get_monitoring_status(),
                "error_statistics": self.error_handler.get_error_statistics()
            }
        except Exception as e:
            self.logger.error(f"Failed to get performance metrics: {e}")
            return {}
    
    def get_system_status(self) -> Dict[str, Any]:
        """Get comprehensive system status"""
        try:
            return {
                "system_initialized": self.is_initialized,
                "monitoring_active": self.monitor.monitoring_active,
                "performance_metrics": self._get_performance_metrics(),
                "monitoring_status": self.monitor.get_monitoring_status(),
                "error_statistics": self.error_handler.get_error_statistics(),
                "configuration_status": {
                    "config_valid": len(self.config_manager.validate_config()) == 0,
                    "strategies_available": list(self.config_manager.config.get("rollback_strategies", {}).keys()),
                    "components_configured": list(self.config_manager.config.get("components", {}).keys())
                },
                "database_status": {
                    "rollback_history_count": len(self.database_manager.get_rollback_history(limit=1000)),
                    "performance_metrics_available": bool(self.database_manager.get_performance_metrics())
                }
            }
        except Exception as e:
            self.logger.error(f"Failed to get system status: {e}")
            return {"error": str(e)}
    
    def get_performance_report(self, hours: int = 24) -> Dict[str, Any]:
        """Get comprehensive performance report"""
        try:
            return self.monitor.get_performance_report(hours)
        except Exception as e:
            self.logger.error(f"Failed to get performance report: {e}")
            return {"error": str(e)}
    
    def get_rollback_history(self, component: str = None, limit: int = 100) -> List[Dict[str, Any]]:
        """Get rollback history"""
        try:
            return self.database_manager.get_rollback_history(component, limit)
        except Exception as e:
            self.logger.error(f"Failed to get rollback history: {e}")
            return []
    
    def _save_pre_rollback_states(self, rollback_id: str, components: List[str], threat_data: Dict[str, Any]):
        """Save pre-rollback states for all components"""
        try:
            for component in components:
                # Get current state of component
                handler = self.component_manager.component_handlers.get(component)
                if handler and hasattr(handler, 'create_backup'):
                    state_data = handler.create_backup(threat_data)
                    if state_data:
                        self.rollback_of_rollback.save_pre_rollback_state(
                            rollback_id, component, state_data
                        )
                        
        except Exception as e:
            self.logger.error(f"Failed to save pre-rollback states: {e}")
    
    def _handle_rollback_of_rollback(self, rollback_id: str, components: List[str], 
                                   threat_data: Dict[str, Any], 
                                   component_results: Dict[str, Any]) -> Dict[str, Any]:
        """Handle rollback-of-rollback for failed components"""
        try:
            self.logger.warning(f"Handling rollback-of-rollback for failed rollback {rollback_id}")
            
            rollback_of_rollback_results = {}
            
            # Determine recovery strategy based on failure severity
            failed_components = []
            for component, result in component_results.get("component_results", {}).items():
                if not result.get("success", False):
                    failed_components.append(component)
            
            if not failed_components:
                return {
                    "success": True,
                    "message": "No failed components to recover",
                    "recovery_strategy": "none"
                }
            
            # Choose recovery strategy
            recovery_strategy = self._determine_recovery_strategy(failed_components, threat_data)
            
            # Execute rollback-of-rollback for each failed component
            for component in failed_components:
                try:
                    recovery_result = self.rollback_of_rollback.execute_rollback_of_rollback(
                        rollback_id, component, recovery_strategy
                    )
                    rollback_of_rollback_results[component] = recovery_result
                    
                except Exception as e:
                    self.logger.error(f"Rollback-of-rollback failed for {component}: {e}")
                    rollback_of_rollback_results[component] = {
                        "success": False,
                        "error": str(e),
                        "recovery_strategy": recovery_strategy
                    }
            
            # Determine overall success
            overall_success = any(
                result.get("success", False) 
                for result in rollback_of_rollback_results.values()
            )
            
            return {
                "success": overall_success,
                "recovery_strategy": recovery_strategy,
                "component_recoveries": rollback_of_rollback_results,
                "failed_components": failed_components,
                "message": f"Rollback-of-rollback completed with {recovery_strategy} strategy"
            }
            
        except Exception as e:
            self.logger.error(f"Failed to handle rollback-of-rollback: {e}")
            return {
                "success": False,
                "error": str(e),
                "recovery_strategy": "failed"
            }
    
    def _determine_recovery_strategy(self, failed_components: List[str], threat_data: Dict[str, Any]) -> str:
        """Determine recovery strategy based on failure context"""
        try:
            threat_level = threat_data.get("threat_level", "MEDIUM")
            severity = threat_data.get("severity", "MEDIUM")
            
            # Critical threats require emergency recovery
            if threat_level in ["CRITICAL", "HIGH"] or severity in ["CRITICAL", "HIGH"]:
                return "emergency_restore"
            
            # Multiple component failures require full recovery
            if len(failed_components) > 2:
                return "full_restore"
            
            # Single component failure can use partial recovery
            if len(failed_components) == 1:
                return "partial_restore"
            
            # Default to manual recovery for complex cases
            return "manual_restore"
            
        except Exception as e:
            self.logger.error(f"Failed to determine recovery strategy: {e}")
            return "manual_restore"
    
    def cleanup_system(self):
        """Cleanup system resources"""
        try:
            # Stop monitoring
            self.monitor.stop_monitoring()
            
            # Cleanup old data
            self.database_manager.cleanup_old_data(days=30)
            
            # Reset error statistics
            self.error_handler.reset_error_statistics()
            
            # Reset metrics
            self.monitor.reset_metrics()
            
            # Cleanup rollback-of-rollback states
            self.rollback_of_rollback.cleanup_old_states(days=7)
            
            # Cleanup post action history
            # (Post action manager handles its own cleanup)
            
            self.logger.info("Advanced rollback system cleanup completed")
            
        except Exception as e:
            self.logger.error(f"System cleanup failed: {e}")
    
    def shutdown(self):
        """Shutdown the advanced rollback system"""
        try:
            self.cleanup_system()
            self.is_initialized = False
            self.logger.info("Advanced rollback system shutdown completed")
        except Exception as e:
            self.logger.error(f"System shutdown failed: {e}")
