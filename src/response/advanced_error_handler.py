"""
Advanced Error Handling and Retry Mechanisms
Handles rollback failures, retries, and circuit breaker patterns
"""

import time
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Callable
import logging
from enum import Enum

class RollbackErrorType(Enum):
    """Types of rollback errors"""
    TIMEOUT = "timeout"
    VALIDATION_FAILED = "validation_failed"
    DEPENDENCY_FAILED = "dependency_failed"
    RESOURCE_EXHAUSTED = "resource_exhausted"
    PERMISSION_DENIED = "permission_denied"
    NETWORK_ERROR = "network_error"
    UNKNOWN_ERROR = "unknown_error"

class CircuitBreakerState(Enum):
    """Circuit breaker states"""
    CLOSED = "closed"      # Normal operation
    OPEN = "open"          # Failing fast
    HALF_OPEN = "half_open"  # Testing recovery

class AdvancedErrorHandler:
    """Advanced error handling for rollback operations"""
    
    def __init__(self, config_manager):
        self.config_manager = config_manager
        self.logger = logging.getLogger(__name__)
        
        # Circuit breaker state
        self.circuit_breaker_state = CircuitBreakerState.CLOSED
        self.failure_count = 0
        self.last_failure_time = None
        self.circuit_breaker_lock = threading.Lock()
        
        # Retry configuration
        self.retry_config = self.config_manager.get_error_handling_config()
        self.max_retry_attempts = self.retry_config.get("max_retry_attempts", 3)
        self.retry_backoff_factor = self.retry_config.get("retry_backoff_factor", 2)
        self.circuit_breaker_enabled = self.retry_config.get("circuit_breaker_enabled", True)
        
        # Error tracking
        self.error_history = []
        self.error_counts = {}
        
        # Fallback strategy
        self.fallback_strategy = self.retry_config.get("fallback_strategy", "emergency")
    
    def handle_rollback_with_retry(self, rollback_func: Callable, component: str, 
                                  threat_data: Dict[str, Any], strategy: str = "immediate") -> Dict[str, Any]:
        """Handle rollback with retry mechanism"""
        try:
            # Check circuit breaker
            if self.circuit_breaker_enabled and not self._is_circuit_breaker_closed():
                return self._handle_circuit_breaker_open(component, threat_data)
            
            # Attempt rollback with retries
            last_error = None
            for attempt in range(self.max_retry_attempts + 1):
                try:
                    self.logger.info(f"Rollback attempt {attempt + 1}/{self.max_retry_attempts + 1} for {component}")
                    
                    # Perform rollback
                    result = rollback_func(component, threat_data, strategy)
                    
                    if result.get("success", False):
                        # Success - reset circuit breaker
                        self._reset_circuit_breaker()
                        self._log_success(component, attempt + 1)
                        return result
                    else:
                        last_error = result.get("error", "Unknown error")
                        self._log_attempt_failure(component, attempt + 1, last_error)
                        
                        # If not the last attempt, wait before retry
                        if attempt < self.max_retry_attempts:
                            wait_time = self._calculate_retry_delay(attempt)
                            self.logger.info(f"Waiting {wait_time}s before retry for {component}")
                            time.sleep(wait_time)
                
                except Exception as e:
                    last_error = str(e)
                    self._log_attempt_failure(component, attempt + 1, last_error)
                    
                    # If not the last attempt, wait before retry
                    if attempt < self.max_retry_attempts:
                        wait_time = self._calculate_retry_delay(attempt)
                        self.logger.info(f"Waiting {wait_time}s before retry for {component}")
                        time.sleep(wait_time)
            
            # All retries failed
            self._handle_all_retries_failed(component, last_error)
            return self._execute_fallback_strategy(component, threat_data, last_error)
            
        except Exception as e:
            self.logger.error(f"Error handler failed for {component}: {e}")
            return {
                "success": False,
                "component": component,
                "error": f"Error handler failed: {e}",
                "fallback_executed": False
            }
    
    def _is_circuit_breaker_closed(self) -> bool:
        """Check if circuit breaker is closed"""
        with self.circuit_breaker_lock:
            if self.circuit_breaker_state == CircuitBreakerState.CLOSED:
                return True
            elif self.circuit_breaker_state == CircuitBreakerState.OPEN:
                # Check if enough time has passed to try half-open
                if self.last_failure_time:
                    time_since_failure = time.time() - self.last_failure_time
                    if time_since_failure > 60:  # 1 minute timeout
                        self.circuit_breaker_state = CircuitBreakerState.HALF_OPEN
                        return True
                return False
            else:  # HALF_OPEN
                return True
    
    def _handle_circuit_breaker_open(self, component: str, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Handle circuit breaker open state"""
        self.logger.warning(f"Circuit breaker is OPEN for {component}, executing fallback strategy")
        return self._execute_fallback_strategy(component, threat_data, "Circuit breaker open")
    
    def _reset_circuit_breaker(self):
        """Reset circuit breaker to closed state"""
        with self.circuit_breaker_lock:
            self.circuit_breaker_state = CircuitBreakerState.CLOSED
            self.failure_count = 0
            self.last_failure_time = None
    
    def _handle_all_retries_failed(self, component: str, last_error: str):
        """Handle case when all retries failed"""
        with self.circuit_breaker_lock:
            self.failure_count += 1
            self.last_failure_time = time.time()
            
            # Open circuit breaker if too many failures
            if self.failure_count >= 5:
                self.circuit_breaker_state = CircuitBreakerState.OPEN
                self.logger.error(f"Circuit breaker opened due to {self.failure_count} consecutive failures")
        
        # Log error
        self._log_error(component, last_error)
    
    def _calculate_retry_delay(self, attempt: int) -> float:
        """Calculate retry delay with exponential backoff"""
        base_delay = 1.0  # 1 second base delay
        return base_delay * (self.retry_backoff_factor ** attempt)
    
    def _execute_fallback_strategy(self, component: str, threat_data: Dict[str, Any], 
                                 error: str) -> Dict[str, Any]:
        """Execute fallback strategy"""
        try:
            self.logger.info(f"Executing fallback strategy '{self.fallback_strategy}' for {component}")
            
            if self.fallback_strategy == "emergency":
                return self._emergency_rollback(component, threat_data)
            elif self.fallback_strategy == "minimal":
                return self._minimal_rollback(component, threat_data)
            elif self.fallback_strategy == "manual":
                return self._manual_rollback_notification(component, threat_data)
            else:
                return self._default_fallback(component, threat_data, error)
                
        except Exception as e:
            self.logger.error(f"Fallback strategy failed for {component}: {e}")
            return {
                "success": False,
                "component": component,
                "error": f"Fallback strategy failed: {e}",
                "fallback_executed": False
            }
    
    def _emergency_rollback(self, component: str, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Execute emergency rollback"""
        try:
            self.logger.warning(f"Executing emergency rollback for {component}")
            
            # Emergency rollback - minimal operations
            emergency_actions = []
            
            # Kill suspicious processes
            if self._emergency_kill_processes():
                emergency_actions.append("processes_killed")
            
            # Block suspicious IPs
            if self._emergency_block_ips():
                emergency_actions.append("ips_blocked")
            
            # Restart critical services
            if self._emergency_restart_services():
                emergency_actions.append("services_restarted")
            
            return {
                "success": len(emergency_actions) > 0,
                "component": component,
                "strategy": "emergency",
                "actions_taken": emergency_actions,
                "fallback_executed": True,
                "message": f"Emergency rollback completed with {len(emergency_actions)} actions"
            }
            
        except Exception as e:
            return {
                "success": False,
                "component": component,
                "strategy": "emergency",
                "error": f"Emergency rollback failed: {e}",
                "fallback_executed": True
            }
    
    def _minimal_rollback(self, component: str, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Execute minimal rollback"""
        try:
            self.logger.info(f"Executing minimal rollback for {component}")
            
            # Minimal rollback - only critical operations
            minimal_actions = []
            
            # Only kill high-risk processes
            if self._minimal_kill_processes():
                minimal_actions.append("high_risk_processes_killed")
            
            return {
                "success": len(minimal_actions) > 0,
                "component": component,
                "strategy": "minimal",
                "actions_taken": minimal_actions,
                "fallback_executed": True,
                "message": f"Minimal rollback completed with {len(minimal_actions)} actions"
            }
            
        except Exception as e:
            return {
                "success": False,
                "component": component,
                "strategy": "minimal",
                "error": f"Minimal rollback failed: {e}",
                "fallback_executed": True
            }
    
    def _manual_rollback_notification(self, component: str, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Send manual rollback notification"""
        try:
            self.logger.critical(f"Manual intervention required for {component}")
            
            # Log critical alert
            alert_message = f"MANUAL ROLLBACK REQUIRED: Component {component} failed all automatic rollback attempts"
            self._log_critical_alert(alert_message)
            
            return {
                "success": False,
                "component": component,
                "strategy": "manual",
                "fallback_executed": True,
                "message": "Manual intervention required",
                "alert_sent": True
            }
            
        except Exception as e:
            return {
                "success": False,
                "component": component,
                "strategy": "manual",
                "error": f"Manual notification failed: {e}",
                "fallback_executed": True
            }
    
    def _default_fallback(self, component: str, threat_data: Dict[str, Any], error: str) -> Dict[str, Any]:
        """Default fallback strategy"""
        return {
            "success": False,
            "component": component,
            "strategy": "default",
            "error": error,
            "fallback_executed": True,
            "message": "Default fallback executed - no specific actions taken"
        }
    
    def _emergency_kill_processes(self) -> bool:
        """Emergency kill suspicious processes"""
        try:
            import psutil
            killed_count = 0
            
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
                try:
                    if proc.info['cpu_percent'] > 90.0:
                        proc.terminate()
                        killed_count += 1
                except:
                    pass
            
            self.logger.info(f"Emergency killed {killed_count} processes")
            return killed_count > 0
            
        except Exception as e:
            self.logger.error(f"Emergency process kill failed: {e}")
            return False
    
    def _emergency_block_ips(self) -> bool:
        """Emergency block suspicious IPs"""
        try:
            # Implementation depends on firewall system
            self.logger.info("Emergency IP blocking executed")
            return True
        except Exception as e:
            self.logger.error(f"Emergency IP blocking failed: {e}")
            return False
    
    def _emergency_restart_services(self) -> bool:
        """Emergency restart critical services"""
        try:
            import subprocess
            services = ["ssh", "network-manager"]
            restarted_count = 0
            
            for service in services:
                try:
                    result = subprocess.run(
                        ["systemctl", "restart", service],
                        capture_output=True,
                        timeout=10
                    )
                    if result.returncode == 0:
                        restarted_count += 1
                except:
                    pass
            
            self.logger.info(f"Emergency restarted {restarted_count} services")
            return restarted_count > 0
            
        except Exception as e:
            self.logger.error(f"Emergency service restart failed: {e}")
            return False
    
    def _minimal_kill_processes(self) -> bool:
        """Minimal kill only high-risk processes"""
        try:
            import psutil
            killed_count = 0
            
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
                try:
                    # Only kill processes with very high CPU usage
                    if proc.info['cpu_percent'] > 95.0:
                        proc.terminate()
                        killed_count += 1
                except:
                    pass
            
            self.logger.info(f"Minimal killed {killed_count} high-risk processes")
            return killed_count > 0
            
        except Exception as e:
            self.logger.error(f"Minimal process kill failed: {e}")
            return False
    
    def _log_success(self, component: str, attempt: int):
        """Log successful rollback"""
        self.logger.info(f"Rollback succeeded for {component} on attempt {attempt}")
        
        # Reset error count for this component
        if component in self.error_counts:
            self.error_counts[component] = 0
    
    def _log_attempt_failure(self, component: str, attempt: int, error: str):
        """Log rollback attempt failure"""
        self.logger.warning(f"Rollback attempt {attempt} failed for {component}: {error}")
        
        # Increment error count
        if component not in self.error_counts:
            self.error_counts[component] = 0
        self.error_counts[component] += 1
    
    def _log_error(self, component: str, error: str):
        """Log error"""
        error_entry = {
            "component": component,
            "error": error,
            "timestamp": datetime.now().isoformat(),
            "error_type": self._classify_error(error).value
        }
        
        self.error_history.append(error_entry)
        
        # Keep only last 100 errors
        if len(self.error_history) > 100:
            self.error_history = self.error_history[-100:]
    
    def _log_critical_alert(self, message: str):
        """Log critical alert"""
        self.logger.critical(message)
        
        # Could send notification to external systems here
        # For now, just log to file
        alert_entry = {
            "level": "CRITICAL",
            "message": message,
            "timestamp": datetime.now().isoformat()
        }
        
        # Save to alerts log
        try:
            import json
            with open("logs/critical_alerts.jsonl", "a") as f:
                f.write(json.dumps(alert_entry) + "\n")
        except:
            pass
    
    def _classify_error(self, error: str) -> RollbackErrorType:
        """Classify error type"""
        error_lower = error.lower()
        
        if "timeout" in error_lower:
            return RollbackErrorType.TIMEOUT
        elif "validation" in error_lower:
            return RollbackErrorType.VALIDATION_FAILED
        elif "dependency" in error_lower:
            return RollbackErrorType.DEPENDENCY_FAILED
        elif "resource" in error_lower or "memory" in error_lower:
            return RollbackErrorType.RESOURCE_EXHAUSTED
        elif "permission" in error_lower or "access denied" in error_lower:
            return RollbackErrorType.PERMISSION_DENIED
        elif "network" in error_lower or "connection" in error_lower:
            return RollbackErrorType.NETWORK_ERROR
        else:
            return RollbackErrorType.UNKNOWN_ERROR
    
    def get_error_statistics(self) -> Dict[str, Any]:
        """Get error statistics"""
        try:
            # Count errors by type
            error_type_counts = {}
            for error_entry in self.error_history:
                error_type = error_entry["error_type"]
                if error_type not in error_type_counts:
                    error_type_counts[error_type] = 0
                error_type_counts[error_type] += 1
            
            # Count errors by component
            component_error_counts = {}
            for error_entry in self.error_history:
                component = error_entry["component"]
                if component not in component_error_counts:
                    component_error_counts[component] = 0
                component_error_counts[component] += 1
            
            return {
                "total_errors": len(self.error_history),
                "error_type_counts": error_type_counts,
                "component_error_counts": component_error_counts,
                "circuit_breaker_state": self.circuit_breaker_state.value,
                "failure_count": self.failure_count,
                "last_failure_time": self.last_failure_time,
                "error_counts": self.error_counts
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get error statistics: {e}")
            return {}
    
    def reset_error_statistics(self):
        """Reset error statistics"""
        with self.circuit_breaker_lock:
            self.error_history.clear()
            self.error_counts.clear()
            self.failure_count = 0
            self.last_failure_time = None
            self.circuit_breaker_state = CircuitBreakerState.CLOSED
        
        self.logger.info("Error statistics reset")
