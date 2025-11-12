"""
Enhanced System Architecture Manager
Provides system-wide architecture improvements and performance optimization
"""

import time
import json
import threading
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Callable
import logging
import os
import psutil
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from queue import Queue, PriorityQueue
import weakref
from dataclasses import dataclass
from enum import Enum

class ComponentStatus(Enum):
    """Component status enumeration"""
    INITIALIZING = "initializing"
    RUNNING = "running"
    STOPPING = "stopping"
    STOPPED = "stopped"
    ERROR = "error"
    MAINTENANCE = "maintenance"

@dataclass
class ComponentInfo:
    """Component information"""
    name: str
    status: ComponentStatus
    start_time: datetime
    last_heartbeat: datetime
    performance_metrics: Dict[str, Any]
    dependencies: List[str]
    priority: int = 0

class EnhancedSystemArchitecture:
    """Enhanced system architecture with performance optimization"""
    
    def __init__(self, config_manager):
        self.config_manager = config_manager
        self.logger = logging.getLogger(__name__)
        self.arch_lock = threading.Lock()
        
        # Component management
        self.components = {}
        self.component_dependencies = {}
        self.component_health = {}
        
        # Performance optimization
        self.thread_pool = ThreadPoolExecutor(max_workers=10)
        self.process_pool = ProcessPoolExecutor(max_workers=4)
        self.task_queue = PriorityQueue()
        self.async_loop = None
        
        # Resource management
        self.resource_monitor = None
        self.performance_cache = {}
        self.cache_ttl = 300  # 5 minutes
        
        # Configuration
        self.max_memory_usage = 80.0  # percent
        self.max_cpu_usage = 80.0  # percent
        self.health_check_interval = 30.0  # seconds
        self.performance_check_interval = 60.0  # seconds
        
        # Initialize architecture
        self._initialize_architecture()
    
    def _initialize_architecture(self):
        """Initialize system architecture"""
        try:
            # Start resource monitoring
            self._start_resource_monitoring()
            
            # Start health checking
            self._start_health_checking()
            
            # Start performance monitoring
            self._start_performance_monitoring()
            
            # Initialize async loop
            self._initialize_async_loop()
            
            self.logger.info("Enhanced system architecture initialized")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize architecture: {e}")
    
    def register_component(self, name: str, component: Any, 
                          dependencies: List[str] = None, priority: int = 0) -> bool:
        """Register a system component"""
        try:
            with self.arch_lock:
                component_info = ComponentInfo(
                    name=name,
                    status=ComponentStatus.INITIALIZING,
                    start_time=datetime.now(),
                    last_heartbeat=datetime.now(),
                    performance_metrics={},
                    dependencies=dependencies or [],
                    priority=priority
                )
                
                self.components[name] = {
                    "info": component_info,
                    "instance": weakref.ref(component),
                    "callbacks": []
                }
                
                self.component_dependencies[name] = dependencies or []
                self.component_health[name] = {
                    "status": "healthy",
                    "last_check": datetime.now(),
                    "error_count": 0,
                    "performance_score": 1.0
                }
                
                self.logger.info(f"Component {name} registered")
                return True
                
        except Exception as e:
            self.logger.error(f"Failed to register component {name}: {e}")
            return False
    
    def unregister_component(self, name: str) -> bool:
        """Unregister a system component"""
        try:
            with self.arch_lock:
                if name in self.components:
                    del self.components[name]
                    del self.component_dependencies[name]
                    del self.component_health[name]
                    
                    self.logger.info(f"Component {name} unregistered")
                    return True
                
                return False
                
        except Exception as e:
            self.logger.error(f"Failed to unregister component {name}: {e}")
            return False
    
    def start_component(self, name: str) -> bool:
        """Start a system component"""
        try:
            with self.arch_lock:
                if name not in self.components:
                    return False
                
                component_data = self.components[name]
                component_info = component_data["info"]
                
                # Check dependencies
                if not self._check_dependencies(name):
                    self.logger.warning(f"Dependencies not met for component {name}")
                    return False
                
                # Update status
                component_info.status = ComponentStatus.RUNNING
                component_info.start_time = datetime.now()
                component_info.last_heartbeat = datetime.now()
                
                self.logger.info(f"Component {name} started")
                return True
                
        except Exception as e:
            self.logger.error(f"Failed to start component {name}: {e}")
            return False
    
    def stop_component(self, name: str) -> bool:
        """Stop a system component"""
        try:
            with self.arch_lock:
                if name not in self.components:
                    return False
                
                component_data = self.components[name]
                component_info = component_data["info"]
                
                # Update status
                component_info.status = ComponentStatus.STOPPING
                
                # Check dependent components
                dependent_components = self._get_dependent_components(name)
                if dependent_components:
                    self.logger.warning(f"Stopping component {name} will affect: {dependent_components}")
                
                component_info.status = ComponentStatus.STOPPED
                
                self.logger.info(f"Component {name} stopped")
                return True
                
        except Exception as e:
            self.logger.error(f"Failed to stop component {name}: {e}")
            return False
    
    def get_component_status(self, name: str) -> Optional[Dict[str, Any]]:
        """Get component status"""
        try:
            with self.arch_lock:
                if name not in self.components:
                    return None
                
                component_data = self.components[name]
                component_info = component_data["info"]
                health = self.component_health[name]
                
                return {
                    "name": name,
                    "status": component_info.status.value,
                    "start_time": component_info.start_time.isoformat(),
                    "last_heartbeat": component_info.last_heartbeat.isoformat(),
                    "uptime": (datetime.now() - component_info.start_time).total_seconds(),
                    "dependencies": component_info.dependencies,
                    "priority": component_info.priority,
                    "health": health["status"],
                    "performance_score": health["performance_score"],
                    "error_count": health["error_count"]
                }
                
        except Exception as e:
            self.logger.error(f"Failed to get component status for {name}: {e}")
            return None
    
    def get_system_status(self) -> Dict[str, Any]:
        """Get overall system status"""
        try:
            with self.arch_lock:
                components_status = {}
                for name in self.components.keys():
                    components_status[name] = self.get_component_status(name)
                
                # Calculate overall health
                healthy_components = sum(1 for status in components_status.values() 
                                      if status and status["health"] == "healthy")
                total_components = len(components_status)
                
                overall_health = "healthy" if healthy_components == total_components else "degraded"
                
                return {
                    "overall_health": overall_health,
                    "total_components": total_components,
                    "healthy_components": healthy_components,
                    "components": components_status,
                    "system_metrics": self._get_system_metrics()
                }
                
        except Exception as e:
            self.logger.error(f"Failed to get system status: {e}")
            return {"error": str(e)}
    
    def execute_async_task(self, task_func: Callable, *args, **kwargs) -> Any:
        """Execute task asynchronously"""
        try:
            if self.async_loop and self.async_loop.is_running():
                return asyncio.run_coroutine_threadsafe(
                    self._async_wrapper(task_func, *args, **kwargs),
                    self.async_loop
                )
            else:
                # Fallback to thread pool
                return self.thread_pool.submit(task_func, *args, **kwargs)
                
        except Exception as e:
            self.logger.error(f"Failed to execute async task: {e}")
            return None
    
    def execute_parallel_tasks(self, tasks: List[Callable], max_workers: int = None) -> List[Any]:
        """Execute multiple tasks in parallel"""
        try:
            max_workers = max_workers or min(len(tasks), 10)
            
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = [executor.submit(task) for task in tasks]
                results = [future.result() for future in futures]
                
            return results
            
        except Exception as e:
            self.logger.error(f"Failed to execute parallel tasks: {e}")
            return []
    
    def cache_result(self, key: str, value: Any, ttl: int = None):
        """Cache a result with TTL"""
        try:
            ttl = ttl or self.cache_ttl
            expire_time = time.time() + ttl
            
            self.performance_cache[key] = {
                "value": value,
                "expire_time": expire_time,
                "created_time": time.time()
            }
            
        except Exception as e:
            self.logger.error(f"Failed to cache result for key {key}: {e}")
    
    def get_cached_result(self, key: str) -> Optional[Any]:
        """Get cached result"""
        try:
            if key not in self.performance_cache:
                return None
            
            cached_data = self.performance_cache[key]
            
            if time.time() > cached_data["expire_time"]:
                del self.performance_cache[key]
                return None
            
            return cached_data["value"]
            
        except Exception as e:
            self.logger.error(f"Failed to get cached result for key {key}: {e}")
            return None
    
    def optimize_performance(self) -> Dict[str, Any]:
        """Optimize system performance"""
        try:
            optimization_results = {}
            
            # Memory optimization
            memory_result = self._optimize_memory()
            optimization_results["memory"] = memory_result
            
            # CPU optimization
            cpu_result = self._optimize_cpu()
            optimization_results["cpu"] = cpu_result
            
            # Cache optimization
            cache_result = self._optimize_cache()
            optimization_results["cache"] = cache_result
            
            # Component optimization
            component_result = self._optimize_components()
            optimization_results["components"] = component_result
            
            return {
                "success": True,
                "optimization_results": optimization_results,
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Performance optimization failed: {e}")
            return {"success": False, "error": str(e)}
    
    def _check_dependencies(self, component_name: str) -> bool:
        """Check if component dependencies are met"""
        try:
            dependencies = self.component_dependencies.get(component_name, [])
            
            for dep in dependencies:
                if dep not in self.components:
                    return False
                
                dep_status = self.components[dep]["info"].status
                if dep_status != ComponentStatus.RUNNING:
                    return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to check dependencies for {component_name}: {e}")
            return False
    
    def _get_dependent_components(self, component_name: str) -> List[str]:
        """Get components that depend on the given component"""
        try:
            dependent_components = []
            
            for name, dependencies in self.component_dependencies.items():
                if component_name in dependencies:
                    dependent_components.append(name)
            
            return dependent_components
            
        except Exception as e:
            self.logger.error(f"Failed to get dependent components for {component_name}: {e}")
            return []
    
    def _get_system_metrics(self) -> Dict[str, Any]:
        """Get system performance metrics"""
        try:
            # CPU metrics
            cpu_percent = psutil.cpu_percent(interval=1)
            cpu_count = psutil.cpu_count()
            
            # Memory metrics
            memory = psutil.virtual_memory()
            
            # Disk metrics
            disk = psutil.disk_usage('/')
            
            # Process metrics
            process_count = len(psutil.pids())
            
            return {
                "cpu": {
                    "usage_percent": cpu_percent,
                    "count": cpu_count,
                    "load_average": os.getloadavg() if hasattr(os, 'getloadavg') else [0, 0, 0]
                },
                "memory": {
                    "usage_percent": memory.percent,
                    "total": memory.total,
                    "available": memory.available,
                    "used": memory.used
                },
                "disk": {
                    "usage_percent": (disk.used / disk.total) * 100,
                    "total": disk.total,
                    "used": disk.used,
                    "free": disk.free
                },
                "processes": {
                    "count": process_count
                },
                "thread_pool": {
                    "active_threads": self.thread_pool._threads.__len__() if hasattr(self.thread_pool, '_threads') else 0,
                    "max_workers": self.thread_pool._max_workers
                }
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get system metrics: {e}")
            return {}
    
    def _start_resource_monitoring(self):
        """Start resource monitoring"""
        try:
            def monitor_resources():
                while True:
                    try:
                        metrics = self._get_system_metrics()
                        
                        # Check memory usage
                        memory_usage = metrics.get("memory", {}).get("usage_percent", 0)
                        if memory_usage > self.max_memory_usage:
                            self.logger.warning(f"High memory usage: {memory_usage}%")
                            self._handle_high_memory_usage()
                        
                        # Check CPU usage
                        cpu_usage = metrics.get("cpu", {}).get("usage_percent", 0)
                        if cpu_usage > self.max_cpu_usage:
                            self.logger.warning(f"High CPU usage: {cpu_usage}%")
                            self._handle_high_cpu_usage()
                        
                        time.sleep(30)  # Check every 30 seconds
                        
                    except Exception as e:
                        self.logger.error(f"Resource monitoring error: {e}")
                        time.sleep(30)
            
            monitor_thread = threading.Thread(target=monitor_resources, daemon=True)
            monitor_thread.start()
            
        except Exception as e:
            self.logger.error(f"Failed to start resource monitoring: {e}")
    
    def _start_health_checking(self):
        """Start component health checking"""
        try:
            def check_health():
                while True:
                    try:
                        with self.arch_lock:
                            for name, component_data in self.components.items():
                                component_info = component_data["info"]
                                
                                # Update heartbeat
                                component_info.last_heartbeat = datetime.now()
                                
                                # Check component health
                                health_status = self._check_component_health(name)
                                self.component_health[name]["status"] = health_status
                                self.component_health[name]["last_check"] = datetime.now()
                        
                        time.sleep(self.health_check_interval)
                        
                    except Exception as e:
                        self.logger.error(f"Health checking error: {e}")
                        time.sleep(self.health_check_interval)
            
            health_thread = threading.Thread(target=check_health, daemon=True)
            health_thread.start()
            
        except Exception as e:
            self.logger.error(f"Failed to start health checking: {e}")
    
    def _start_performance_monitoring(self):
        """Start performance monitoring"""
        try:
            def monitor_performance():
                while True:
                    try:
                        # Update component performance metrics
                        with self.arch_lock:
                            for name, component_data in self.components.items():
                                performance_score = self._calculate_performance_score(name)
                                self.component_health[name]["performance_score"] = performance_score
                        
                        time.sleep(self.performance_check_interval)
                        
                    except Exception as e:
                        self.logger.error(f"Performance monitoring error: {e}")
                        time.sleep(self.performance_check_interval)
            
            performance_thread = threading.Thread(target=monitor_performance, daemon=True)
            performance_thread.start()
            
        except Exception as e:
            self.logger.error(f"Failed to start performance monitoring: {e}")
    
    def _initialize_async_loop(self):
        """Initialize async event loop"""
        try:
            def run_async_loop():
                self.async_loop = asyncio.new_event_loop()
                asyncio.set_event_loop(self.async_loop)
                self.async_loop.run_forever()
            
            async_thread = threading.Thread(target=run_async_loop, daemon=True)
            async_thread.start()
            
        except Exception as e:
            self.logger.error(f"Failed to initialize async loop: {e}")
    
    async def _async_wrapper(self, task_func: Callable, *args, **kwargs):
        """Wrapper for async task execution"""
        try:
            if asyncio.iscoroutinefunction(task_func):
                return await task_func(*args, **kwargs)
            else:
                # Run sync function in thread pool
                loop = asyncio.get_event_loop()
                return await loop.run_in_executor(self.thread_pool, task_func, *args, **kwargs)
                
        except Exception as e:
            self.logger.error(f"Async wrapper error: {e}")
            return None
    
    def _check_component_health(self, name: str) -> str:
        """Check component health"""
        try:
            component_data = self.components[name]
            component_info = component_data["info"]
            
            # Check if component is running
            if component_info.status != ComponentStatus.RUNNING:
                return "unhealthy"
            
            # Check heartbeat
            time_since_heartbeat = (datetime.now() - component_info.last_heartbeat).total_seconds()
            if time_since_heartbeat > 300:  # 5 minutes
                return "unhealthy"
            
            # Check error count
            error_count = self.component_health[name]["error_count"]
            if error_count > 10:
                return "unhealthy"
            
            return "healthy"
            
        except Exception as e:
            self.logger.error(f"Failed to check health for component {name}: {e}")
            return "unhealthy"
    
    def _calculate_performance_score(self, name: str) -> float:
        """Calculate component performance score"""
        try:
            # Base score
            score = 1.0
            
            # Deduct for errors
            error_count = self.component_health[name]["error_count"]
            score -= min(error_count * 0.1, 0.5)
            
            # Deduct for high resource usage
            metrics = self._get_system_metrics()
            cpu_usage = metrics.get("cpu", {}).get("usage_percent", 0)
            memory_usage = metrics.get("memory", {}).get("usage_percent", 0)
            
            if cpu_usage > 80:
                score -= 0.2
            if memory_usage > 80:
                score -= 0.2
            
            return max(score, 0.0)
            
        except Exception as e:
            self.logger.error(f"Failed to calculate performance score for {name}: {e}")
            return 0.0
    
    def _handle_high_memory_usage(self):
        """Handle high memory usage"""
        try:
            # Clear cache
            self._clear_old_cache()
            
            # Reduce thread pool size
            if hasattr(self.thread_pool, '_max_workers'):
                self.thread_pool._max_workers = max(5, self.thread_pool._max_workers - 2)
            
            self.logger.info("Applied memory optimization measures")
            
        except Exception as e:
            self.logger.error(f"Failed to handle high memory usage: {e}")
    
    def _handle_high_cpu_usage(self):
        """Handle high CPU usage"""
        try:
            # Reduce thread pool size
            if hasattr(self.thread_pool, '_max_workers'):
                self.thread_pool._max_workers = max(3, self.thread_pool._max_workers - 1)
            
            # Clear cache
            self._clear_old_cache()
            
            self.logger.info("Applied CPU optimization measures")
            
        except Exception as e:
            self.logger.error(f"Failed to handle high CPU usage: {e}")
    
    def _clear_old_cache(self):
        """Clear old cache entries"""
        try:
            current_time = time.time()
            expired_keys = []
            
            for key, cached_data in self.performance_cache.items():
                if current_time > cached_data["expire_time"]:
                    expired_keys.append(key)
            
            for key in expired_keys:
                del self.performance_cache[key]
            
            if expired_keys:
                self.logger.info(f"Cleared {len(expired_keys)} expired cache entries")
            
        except Exception as e:
            self.logger.error(f"Failed to clear old cache: {e}")
    
    def _optimize_memory(self) -> Dict[str, Any]:
        """Optimize memory usage"""
        try:
            # Clear cache
            self._clear_old_cache()
            
            # Force garbage collection
            import gc
            gc.collect()
            
            # Get memory info
            memory = psutil.virtual_memory()
            
            return {
                "success": True,
                "memory_usage_before": memory.percent,
                "cache_cleared": True,
                "garbage_collected": True
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def _optimize_cpu(self) -> Dict[str, Any]:
        """Optimize CPU usage"""
        try:
            # Adjust thread pool size
            current_cpu = psutil.cpu_percent(interval=1)
            
            if current_cpu > 80:
                # Reduce thread pool size
                if hasattr(self.thread_pool, '_max_workers'):
                    self.thread_pool._max_workers = max(3, self.thread_pool._max_workers - 2)
            
            return {
                "success": True,
                "cpu_usage": current_cpu,
                "thread_pool_adjusted": True
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def _optimize_cache(self) -> Dict[str, Any]:
        """Optimize cache usage"""
        try:
            cache_size_before = len(self.performance_cache)
            self._clear_old_cache()
            cache_size_after = len(self.performance_cache)
            
            return {
                "success": True,
                "cache_size_before": cache_size_before,
                "cache_size_after": cache_size_after,
                "entries_cleared": cache_size_before - cache_size_after
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def _optimize_components(self) -> Dict[str, Any]:
        """Optimize component performance"""
        try:
            optimized_components = []
            
            with self.arch_lock:
                for name, component_data in self.components.items():
                    component_info = component_data["info"]
                    
                    # Reset error count for healthy components
                    if self.component_health[name]["status"] == "healthy":
                        self.component_health[name]["error_count"] = 0
                        optimized_components.append(name)
            
            return {
                "success": True,
                "optimized_components": optimized_components,
                "count": len(optimized_components)
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def shutdown(self):
        """Shutdown system architecture"""
        try:
            self.logger.info("Shutting down enhanced system architecture...")
            
            # Stop all components
            with self.arch_lock:
                for name in list(self.components.keys()):
                    self.stop_component(name)
            
            # Shutdown thread pools
            self.thread_pool.shutdown(wait=True)
            self.process_pool.shutdown(wait=True)
            
            # Stop async loop
            if self.async_loop and self.async_loop.is_running():
                self.async_loop.stop()
            
            self.logger.info("System architecture shutdown completed")
            
        except Exception as e:
            self.logger.error(f"Failed to shutdown system architecture: {e}")
