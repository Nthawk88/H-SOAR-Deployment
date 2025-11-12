"""
Enhanced Performance Monitoring System
Simplified version with performance optimizations
"""

import time
import logging
import threading
from typing import Dict, List, Any, Optional
from datetime import datetime
import json
import os


class EnhancedPerformanceMonitor:
    """
    Enhanced performance monitoring with:
    - Async processing simulation
    - Smart caching
    - Dynamic intervals
    - Performance metrics
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Performance optimization
        self.cache = {}
        self.cache_ttl = config.get('cache_ttl', 300)
        self.base_interval = config.get('monitoring_interval', 30)
        self.current_interval = self.base_interval
        self.min_interval = config.get('min_interval', 5)
        self.max_interval = config.get('max_interval', 300)
        
        # Performance tracking
        self.performance_metrics = {
            'total_cycles': 0,
            'cache_hits': 0,
            'cache_misses': 0,
            'average_response_time': 0.0,
            'interval_adjustments': 0,
            'start_time': time.time()
        }
        
        # Threading
        self.running = False
        self.monitor_thread = None
        
        self.logger.info("[ENHANCED-PERF] Enhanced performance monitor initialized")
    
    def start_monitoring(self):
        """Start enhanced monitoring"""
        try:
            self.running = True
            self.monitor_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
            self.monitor_thread.start()
            
            self.logger.info("[ENHANCED-PERF] Enhanced monitoring started")
            
        except Exception as e:
            self.logger.error(f"[ENHANCED-PERF] Error starting monitoring: {e}")
    
    def stop_monitoring(self):
        """Stop enhanced monitoring"""
        try:
            self.running = False
            if self.monitor_thread:
                self.monitor_thread.join(timeout=5.0)
            
            self.logger.info("[ENHANCED-PERF] Enhanced monitoring stopped")
            
        except Exception as e:
            self.logger.error(f"[ENHANCED-PERF] Error stopping monitoring: {e}")
    
    def _monitoring_loop(self):
        """Main monitoring loop with performance optimizations"""
        try:
            while self.running:
                start_time = time.time()
                
                # Simulate monitoring cycle
                self._perform_monitoring_cycle()
                
                # Calculate response time
                response_time = time.time() - start_time
                self._update_performance_metrics(response_time)
                
                # Adjust interval based on performance
                self._adjust_monitoring_interval(response_time)
                
                # Wait for next cycle
                time.sleep(self.current_interval)
                
        except Exception as e:
            self.logger.error(f"[ENHANCED-PERF] Error in monitoring loop: {e}")
    
    def _perform_monitoring_cycle(self):
        """Perform one monitoring cycle"""
        try:
            self.performance_metrics['total_cycles'] += 1
            
            # Simulate data collection
            data = self._collect_system_data()
            
            # Check cache first
            cache_key = self._generate_cache_key(data)
            cached_result = self._get_cached_result(cache_key)
            
            if cached_result:
                self.performance_metrics['cache_hits'] += 1
                self.logger.debug("[ENHANCED-PERF] Using cached result")
            else:
                self.performance_metrics['cache_misses'] += 1
                # Simulate processing
                result = self._process_data(data)
                self._cache_result(cache_key, result)
            
            # Log monitoring info
            self.logger.info(f"[ENHANCED-PERF] Cycle {self.performance_metrics['total_cycles']} - "
                           f"Interval: {self.current_interval:.1f}s - "
                           f"Cache Hit Rate: {self._get_cache_hit_rate():.1%}")
            
        except Exception as e:
            self.logger.error(f"[ENHANCED-PERF] Error in monitoring cycle: {e}")
    
    def _collect_system_data(self) -> Dict[str, Any]:
        """Collect system data"""
        try:
            import psutil
            
            return {
                'timestamp': datetime.now().isoformat(),
                'cpu_percent': psutil.cpu_percent(interval=1),
                'memory_percent': psutil.virtual_memory().percent,
                'disk_percent': psutil.disk_usage('/').percent if os.name != 'nt' else psutil.disk_usage('C:').percent,
                'process_count': len(psutil.pids())
            }
            
        except Exception as e:
            self.logger.error(f"[ENHANCED-PERF] Error collecting system data: {e}")
            return {'timestamp': datetime.now().isoformat(), 'error': str(e)}
    
    def _process_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Process collected data"""
        try:
            # Simulate processing time
            time.sleep(0.1)
            
            # Calculate some metrics
            result = {
                'processed_at': datetime.now().isoformat(),
                'cpu_status': 'HIGH' if data.get('cpu_percent', 0) > 80 else 'NORMAL',
                'memory_status': 'HIGH' if data.get('memory_percent', 0) > 85 else 'NORMAL',
                'disk_status': 'HIGH' if data.get('disk_percent', 0) > 90 else 'NORMAL',
                'overall_status': 'WARNING' if any([
                    data.get('cpu_percent', 0) > 80,
                    data.get('memory_percent', 0) > 85,
                    data.get('disk_percent', 0) > 90
                ]) else 'NORMAL'
            }
            
            return result
            
        except Exception as e:
            self.logger.error(f"[ENHANCED-PERF] Error processing data: {e}")
            return {'error': str(e)}
    
    def _generate_cache_key(self, data: Dict[str, Any]) -> str:
        """Generate cache key from data"""
        try:
            # Simple hash based on key metrics
            key_data = {
                'cpu': round(data.get('cpu_percent', 0), 1),
                'memory': round(data.get('memory_percent', 0), 1),
                'disk': round(data.get('disk_percent', 0), 1)
            }
            return str(hash(str(key_data)))
            
        except Exception as e:
            self.logger.error(f"[ENHANCED-PERF] Error generating cache key: {e}")
            return str(time.time())
    
    def _get_cached_result(self, cache_key: str) -> Optional[Dict[str, Any]]:
        """Get cached result if still valid"""
        try:
            if cache_key in self.cache:
                cached_data = self.cache[cache_key]
                if time.time() - cached_data['timestamp'] < self.cache_ttl:
                    return cached_data['data']
                else:
                    # Remove expired cache
                    del self.cache[cache_key]
            
            return None
            
        except Exception as e:
            self.logger.error(f"[ENHANCED-PERF] Error getting cached result: {e}")
            return None
    
    def _cache_result(self, cache_key: str, data: Dict[str, Any]):
        """Cache result with timestamp"""
        try:
            self.cache[cache_key] = {
                'data': data,
                'timestamp': time.time()
            }
            
            # Limit cache size
            if len(self.cache) > 100:
                # Remove oldest entries
                oldest_key = min(self.cache.keys(), key=lambda k: self.cache[k]['timestamp'])
                del self.cache[oldest_key]
                
        except Exception as e:
            self.logger.error(f"[ENHANCED-PERF] Error caching result: {e}")
    
    def _update_performance_metrics(self, response_time: float):
        """Update performance metrics"""
        try:
            total_cycles = self.performance_metrics['total_cycles']
            current_avg = self.performance_metrics['average_response_time']
            
            # Calculate running average
            self.performance_metrics['average_response_time'] = (
                (current_avg * (total_cycles - 1) + response_time) / total_cycles
            )
            
        except Exception as e:
            self.logger.error(f"[ENHANCED-PERF] Error updating performance metrics: {e}")
    
    def _adjust_monitoring_interval(self, response_time: float):
        """Adjust monitoring interval based on performance"""
        try:
            # If response time is high, reduce interval for more frequent monitoring
            if response_time > 1.0:  # More than 1 second
                new_interval = max(self.min_interval, self.current_interval * 0.8)
            elif response_time < 0.1:  # Less than 100ms
                new_interval = min(self.max_interval, self.current_interval * 1.2)
            else:
                new_interval = self.base_interval
            
            # Smooth transition
            if abs(new_interval - self.current_interval) > 1.0:
                self.current_interval = (self.current_interval + new_interval) / 2
                self.performance_metrics['interval_adjustments'] += 1
                
                self.logger.debug(f"[ENHANCED-PERF] Adjusted interval to {self.current_interval:.1f}s")
            
        except Exception as e:
            self.logger.error(f"[ENHANCED-PERF] Error adjusting interval: {e}")
    
    def _get_cache_hit_rate(self) -> float:
        """Get cache hit rate"""
        try:
            total_requests = self.performance_metrics['cache_hits'] + self.performance_metrics['cache_misses']
            if total_requests > 0:
                return self.performance_metrics['cache_hits'] / total_requests
            return 0.0
            
        except Exception as e:
            self.logger.error(f"[ENHANCED-PERF] Error calculating cache hit rate: {e}")
            return 0.0
    
    def get_performance_stats(self) -> Dict[str, Any]:
        """Get performance statistics"""
        try:
            uptime = time.time() - self.performance_metrics['start_time']
            
            return {
                **self.performance_metrics,
                'uptime_seconds': uptime,
                'uptime_minutes': uptime / 60,
                'cache_hit_rate': self._get_cache_hit_rate(),
                'cache_size': len(self.cache),
                'current_interval': self.current_interval,
                'base_interval': self.base_interval,
                'throughput': self.performance_metrics['total_cycles'] / max(1, uptime)
            }
            
        except Exception as e:
            self.logger.error(f"[ENHANCED-PERF] Error getting performance stats: {e}")
            return {}
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        try:
            return {
                'cache_size': len(self.cache),
                'cache_hits': self.performance_metrics['cache_hits'],
                'cache_misses': self.performance_metrics['cache_misses'],
                'cache_hit_rate': self._get_cache_hit_rate(),
                'cache_ttl': self.cache_ttl
            }
            
        except Exception as e:
            self.logger.error(f"[ENHANCED-PERF] Error getting cache stats: {e}")
            return {}
    
    def clear_cache(self):
        """Clear cache"""
        try:
            self.cache.clear()
            self.logger.info("[ENHANCED-PERF] Cache cleared")
            
        except Exception as e:
            self.logger.error(f"[ENHANCED-PERF] Error clearing cache: {e}")
    
    def optimize_performance(self):
        """Optimize performance based on metrics"""
        try:
            stats = self.get_performance_stats()
            
            # If cache hit rate is low, increase TTL
            if stats['cache_hit_rate'] < 0.3:
                self.cache_ttl = min(600, self.cache_ttl * 1.5)
                self.logger.info(f"[ENHANCED-PERF] Increased cache TTL to {self.cache_ttl}s")
            
            # If response time is high, reduce interval
            if stats['average_response_time'] > 0.5:
                self.current_interval = max(self.min_interval, self.current_interval * 0.9)
                self.logger.info(f"[ENHANCED-PERF] Reduced monitoring interval to {self.current_interval:.1f}s")
            
            self.logger.info("[ENHANCED-PERF] Performance optimization completed")
            
        except Exception as e:
            self.logger.error(f"[ENHANCED-PERF] Error optimizing performance: {e}")
