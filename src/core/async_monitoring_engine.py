"""
Async Monitoring Engine
High-performance asynchronous monitoring system with parallel processing
"""

import asyncio
import aiofiles
import aiohttp
import time
import json
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional, Callable
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
import threading
from dataclasses import dataclass
from queue import Queue, PriorityQueue
import psutil
import numpy as np


@dataclass
class MonitoringTask:
    """Monitoring task with priority and metadata"""
    task_id: str
    priority: int
    task_type: str
    data: Dict[str, Any]
    callback: Optional[Callable] = None
    timestamp: float = 0.0
    
    def __post_init__(self):
        if self.timestamp == 0.0:
            self.timestamp = time.time()


class AsyncMonitoringEngine:
    """
    High-performance async monitoring engine with:
    - Parallel data collection
    - Async model inference
    - Smart caching
    - Dynamic intervals
    - Resource optimization
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Async infrastructure
        self.loop = None
        self.executor = ThreadPoolExecutor(max_workers=8)
        self.process_executor = ProcessPoolExecutor(max_workers=4)
        
        # Task management
        self.task_queue = PriorityQueue()
        self.active_tasks = {}
        self.task_results = {}
        
        # Performance optimization
        self.cache = {}
        self.cache_ttl = config.get('cache_ttl', 300)  # 5 minutes
        self.batch_size = config.get('batch_size', 10)
        self.max_concurrent = config.get('max_concurrent', 5)
        
        # Dynamic intervals
        self.base_interval = config.get('monitoring_interval', 30)
        self.current_interval = self.base_interval
        self.interval_multiplier = config.get('interval_multiplier', 2.0)
        self.min_interval = config.get('min_interval', 5)
        self.max_interval = config.get('max_interval', 300)
        
        # Performance tracking
        self.performance_metrics = {
            'avg_response_time': 0.0,
            'throughput': 0.0,
            'error_rate': 0.0,
            'cache_hit_rate': 0.0
        }
        
        # Resource monitoring
        self.resource_thresholds = {
            'cpu_threshold': 80.0,
            'memory_threshold': 85.0,
            'disk_threshold': 90.0
        }
        
        # Initialize
        self._initialize_async_engine()
    
    def _initialize_async_engine(self):
        """Initialize async monitoring engine"""
        try:
            # Start async loop in background thread
            self.loop_thread = threading.Thread(target=self._run_async_loop, daemon=True)
            self.loop_thread.start()
            
            # Start performance monitoring
            self._start_performance_monitoring()
            
            # Start resource monitoring
            self._start_resource_monitoring()
            
            self.logger.info("[ASYNC-ENGINE] Async monitoring engine initialized")
            
        except Exception as e:
            self.logger.error(f"[ASYNC-ENGINE] Error initializing: {e}")
            raise
    
    def _run_async_loop(self):
        """Run async event loop in background thread"""
        try:
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)
            self.loop.run_forever()
        except Exception as e:
            self.logger.error(f"[ASYNC-ENGINE] Async loop error: {e}")
    
    async def collect_metrics_async(self, metrics_config: Dict[str, Any]) -> Dict[str, Any]:
        """Async metrics collection with parallel processing"""
        try:
            start_time = time.time()
            
            # Create tasks for parallel collection
            tasks = []
            
            # Host metrics
            if metrics_config.get('host_enabled', True):
                tasks.append(self._collect_host_metrics_async())
            
            # Network metrics
            if metrics_config.get('network_enabled', True):
                tasks.append(self._collect_network_metrics_async())
            
            # Process metrics
            if metrics_config.get('process_enabled', True):
                tasks.append(self._collect_process_metrics_async())
            
            # Execute all tasks in parallel
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Combine results
            combined_metrics = {}
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    self.logger.warning(f"[ASYNC-ENGINE] Task {i} failed: {result}")
                    continue
                combined_metrics.update(result)
            
            # Add metadata
            combined_metrics['collection_time'] = time.time() - start_time
            combined_metrics['timestamp'] = datetime.now().isoformat()
            
            return combined_metrics
            
        except Exception as e:
            self.logger.error(f"[ASYNC-ENGINE] Error collecting metrics: {e}")
            return {}
    
    async def _collect_host_metrics_async(self) -> Dict[str, Any]:
        """Async host metrics collection"""
        try:
            # Run CPU-intensive operations in thread pool
            loop = asyncio.get_event_loop()
            
            # CPU metrics
            cpu_percent = await loop.run_in_executor(
                self.executor, psutil.cpu_percent, 1.0
            )
            cpu_count = await loop.run_in_executor(
                self.executor, psutil.cpu_count
            )
            
            # Memory metrics
            memory = await loop.run_in_executor(
                self.executor, psutil.virtual_memory
            )
            
            # Disk metrics
            disk = await loop.run_in_executor(
                self.executor, psutil.disk_usage, '/'
            )
            
            return {
                'host_metrics': {
                    'cpu': {
                        'percent': cpu_percent,
                        'count': cpu_count,
                        'load_avg': psutil.getloadavg()[0] if hasattr(psutil, 'getloadavg') else 0.0
                    },
                    'memory': {
                        'total': memory.total,
                        'available': memory.available,
                        'percent': memory.percent,
                        'used': memory.used
                    },
                    'disk': {
                        'total': disk.total,
                        'used': disk.used,
                        'free': disk.free,
                        'percent': (disk.used / disk.total) * 100
                    }
                }
            }
            
        except Exception as e:
            self.logger.error(f"[ASYNC-ENGINE] Error collecting host metrics: {e}")
            return {}
    
    async def _collect_network_metrics_async(self) -> Dict[str, Any]:
        """Async network metrics collection"""
        try:
            loop = asyncio.get_event_loop()
            
            # Network I/O
            net_io = await loop.run_in_executor(
                self.executor, psutil.net_io_counters
            )
            
            # Network connections
            connections = await loop.run_in_executor(
                self.executor, psutil.net_connections
            )
            
            return {
                'network_metrics': {
                    'bytes_sent': net_io.bytes_sent,
                    'bytes_recv': net_io.bytes_recv,
                    'packets_sent': net_io.packets_sent,
                    'packets_recv': net_io.packets_recv,
                    'connection_count': len(connections),
                    'foreign_connections': len([c for c in connections if c.raddr and c.raddr[0] not in ['127.0.0.1', '::1']])
                }
            }
            
        except Exception as e:
            self.logger.error(f"[ASYNC-ENGINE] Error collecting network metrics: {e}")
            return {}
    
    async def _collect_process_metrics_async(self) -> Dict[str, Any]:
        """Async process metrics collection"""
        try:
            loop = asyncio.get_event_loop()
            
            # Process list
            processes = await loop.run_in_executor(
                self.executor, psutil.process_iter, ['pid', 'name', 'cpu_percent', 'memory_percent']
            )
            
            process_list = []
            suspicious_processes = []
            
            for proc in processes:
                try:
                    proc_info = proc.info
                    process_list.append(proc_info)
                    
                    # Check for suspicious processes
                    if proc_info['name'].lower() in ['nc', 'netcat', 'ncat', 'mimikatz', 'mshta']:
                        suspicious_processes.append(proc_info)
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            return {
                'process_metrics': {
                    'total_processes': len(process_list),
                    'suspicious_processes': len(suspicious_processes),
                    'process_list': process_list[:50],  # Limit to first 50
                    'suspicious_list': suspicious_processes
                }
            }
            
        except Exception as e:
            self.logger.error(f"[ASYNC-ENGINE] Error collecting process metrics: {e}")
            return {}
    
    async def run_model_inference_async(self, models: Dict[str, Any], features: List[float]) -> Dict[str, Any]:
        """Async model inference with parallel processing"""
        try:
            start_time = time.time()
            
            # Create tasks for each model
            tasks = []
            for model_name, model in models.items():
                task = self._run_single_model_async(model_name, model, features)
                tasks.append(task)
            
            # Execute all models in parallel
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Combine results
            inference_results = {}
            for i, result in enumerate(results):
                model_name = list(models.keys())[i]
                if isinstance(result, Exception):
                    self.logger.warning(f"[ASYNC-ENGINE] Model {model_name} inference failed: {result}")
                    inference_results[model_name] = {'error': str(result), 'score': 0.0}
                else:
                    inference_results[model_name] = result
            
            # Add metadata
            inference_results['inference_time'] = time.time() - start_time
            inference_results['model_count'] = len(models)
            
            return inference_results
            
        except Exception as e:
            self.logger.error(f"[ASYNC-ENGINE] Error in model inference: {e}")
            return {}
    
    async def _run_single_model_async(self, model_name: str, model: Any, features: List[float]) -> Dict[str, Any]:
        """Run single model inference asynchronously"""
        try:
            loop = asyncio.get_event_loop()
            
            # Run model inference in thread pool
            result = await loop.run_in_executor(
                self.executor, self._run_model_inference, model, features
            )
            
            return {
                'model_name': model_name,
                'score': result.get('score', 0.0),
                'prediction': result.get('prediction', False),
                'confidence': result.get('confidence', 0.0)
            }
            
        except Exception as e:
            self.logger.error(f"[ASYNC-ENGINE] Error running model {model_name}: {e}")
            return {'error': str(e), 'score': 0.0}
    
    def _run_model_inference(self, model: Any, features: List[float]) -> Dict[str, Any]:
        """Run model inference (sync wrapper for async)"""
        try:
            if hasattr(model, 'predict'):
                prediction = model.predict([features])[0]
                score = float(prediction) if isinstance(prediction, (int, float)) else 0.0
            elif hasattr(model, 'decision_function'):
                score = float(model.decision_function([features])[0])
                prediction = score > 0.5
            else:
                score = 0.0
                prediction = False
            
            return {
                'score': score,
                'prediction': prediction,
                'confidence': abs(score)
            }
            
        except Exception as e:
            self.logger.error(f"[ASYNC-ENGINE] Model inference error: {e}")
            return {'score': 0.0, 'prediction': False, 'confidence': 0.0}
    
    def get_cached_result(self, cache_key: str) -> Optional[Dict[str, Any]]:
        """Get cached result if still valid"""
        try:
            if cache_key in self.cache:
                cached_data = self.cache[cache_key]
                if time.time() - cached_data['timestamp'] < self.cache_ttl:
                    self.performance_metrics['cache_hit_rate'] += 1
                    return cached_data['data']
                else:
                    # Remove expired cache
                    del self.cache[cache_key]
            
            return None
            
        except Exception as e:
            self.logger.error(f"[ASYNC-ENGINE] Cache error: {e}")
            return None
    
    def cache_result(self, cache_key: str, data: Dict[str, Any]):
        """Cache result with timestamp"""
        try:
            self.cache[cache_key] = {
                'data': data,
                'timestamp': time.time()
            }
            
            # Limit cache size
            if len(self.cache) > 1000:
                # Remove oldest entries
                oldest_key = min(self.cache.keys(), key=lambda k: self.cache[k]['timestamp'])
                del self.cache[oldest_key]
                
        except Exception as e:
            self.logger.error(f"[ASYNC-ENGINE] Cache error: {e}")
    
    def adjust_monitoring_interval(self, anomaly_score: float, threat_level: str):
        """Dynamically adjust monitoring interval based on system state"""
        try:
            # Calculate new interval based on threat level and anomaly score
            if threat_level in ['HIGH', 'CRITICAL'] or anomaly_score > 80:
                # High threat - monitor more frequently
                new_interval = max(self.min_interval, self.current_interval / self.interval_multiplier)
            elif threat_level == 'LOW' and anomaly_score < 30:
                # Low threat - monitor less frequently
                new_interval = min(self.max_interval, self.current_interval * self.interval_multiplier)
            else:
                # Medium threat - use base interval
                new_interval = self.base_interval
            
            # Smooth transition
            self.current_interval = (self.current_interval + new_interval) / 2
            
            self.logger.debug(f"[ASYNC-ENGINE] Adjusted interval: {self.current_interval:.1f}s")
            
        except Exception as e:
            self.logger.error(f"[ASYNC-ENGINE] Error adjusting interval: {e}")
    
    def _start_performance_monitoring(self):
        """Start performance monitoring"""
        try:
            def monitor_performance():
                while True:
                    try:
                        # Calculate performance metrics
                        total_requests = len(self.task_results)
                        if total_requests > 0:
                            successful_requests = len([r for r in self.task_results.values() if not r.get('error')])
                            self.performance_metrics['error_rate'] = (total_requests - successful_requests) / total_requests
                        
                        # Log performance metrics
                        self.logger.debug(f"[ASYNC-ENGINE] Performance: {self.performance_metrics}")
                        
                        time.sleep(60)  # Monitor every minute
                        
                    except Exception as e:
                        self.logger.error(f"[ASYNC-ENGINE] Performance monitoring error: {e}")
                        time.sleep(60)
            
            # Start in background thread
            perf_thread = threading.Thread(target=monitor_performance, daemon=True)
            perf_thread.start()
            
        except Exception as e:
            self.logger.error(f"[ASYNC-ENGINE] Error starting performance monitoring: {e}")
    
    def _start_resource_monitoring(self):
        """Start resource monitoring"""
        try:
            def monitor_resources():
                while True:
                    try:
                        # Check system resources
                        cpu_percent = psutil.cpu_percent(interval=1)
                        memory_percent = psutil.virtual_memory().percent
                        
                        # Adjust concurrency based on resources
                        if cpu_percent > self.resource_thresholds['cpu_threshold']:
                            self.max_concurrent = max(1, self.max_concurrent - 1)
                        elif cpu_percent < 50:
                            self.max_concurrent = min(10, self.max_concurrent + 1)
                        
                        if memory_percent > self.resource_thresholds['memory_threshold']:
                            # Clear cache if memory is high
                            if len(self.cache) > 100:
                                self.cache.clear()
                        
                        time.sleep(30)  # Check every 30 seconds
                        
                    except Exception as e:
                        self.logger.error(f"[ASYNC-ENGINE] Resource monitoring error: {e}")
                        time.sleep(30)
            
            # Start in background thread
            resource_thread = threading.Thread(target=monitor_resources, daemon=True)
            resource_thread.start()
            
        except Exception as e:
            self.logger.error(f"[ASYNC-ENGINE] Error starting resource monitoring: {e}")
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get current performance metrics"""
        return {
            **self.performance_metrics,
            'current_interval': self.current_interval,
            'cache_size': len(self.cache),
            'active_tasks': len(self.active_tasks),
            'max_concurrent': self.max_concurrent
        }
    
    def shutdown(self):
        """Shutdown async engine"""
        try:
            if self.loop and self.loop.is_running():
                self.loop.call_soon_threadsafe(self.loop.stop)
            
            self.executor.shutdown(wait=True)
            self.process_executor.shutdown(wait=True)
            
            self.logger.info("[ASYNC-ENGINE] Async monitoring engine shutdown")
            
        except Exception as e:
            self.logger.error(f"[ASYNC-ENGINE] Error during shutdown: {e}")
