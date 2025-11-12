"""
Real-Time Monitoring and Performance Metrics for Advanced Rollback
Handles live monitoring, metrics collection, and performance analysis
"""

import time
import threading
import psutil
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Callable
import logging
import json
from collections import deque
import statistics

class PerformanceMetrics:
    """Performance metrics collector"""
    
    def __init__(self, max_samples: int = 1000):
        self.max_samples = max_samples
        self.metrics = {
            'rollback_duration': deque(maxlen=max_samples),
            'rollback_success_rate': deque(maxlen=max_samples),
            'cpu_usage': deque(maxlen=max_samples),
            'memory_usage': deque(maxlen=max_samples),
            'disk_usage': deque(maxlen=max_samples),
            'network_usage': deque(maxlen=max_samples),
            'error_count': deque(maxlen=max_samples),
            'retry_count': deque(maxlen=max_samples)
        }
        self.lock = threading.Lock()
    
    def add_metric(self, metric_name: str, value: float, timestamp: float = None):
        """Add metric value"""
        if timestamp is None:
            timestamp = time.time()
        
        with self.lock:
            if metric_name in self.metrics:
                self.metrics[metric_name].append((timestamp, value))
    
    def get_metric_stats(self, metric_name: str, hours: int = 24) -> Dict[str, Any]:
        """Get metric statistics"""
        with self.lock:
            if metric_name not in self.metrics:
                return {}
            
            cutoff_time = time.time() - (hours * 3600)
            recent_values = [
                value for timestamp, value in self.metrics[metric_name]
                if timestamp >= cutoff_time
            ]
            
            if not recent_values:
                return {}
            
            return {
                'count': len(recent_values),
                'average': statistics.mean(recent_values),
                'median': statistics.median(recent_values),
                'min': min(recent_values),
                'max': max(recent_values),
                'std_dev': statistics.stdev(recent_values) if len(recent_values) > 1 else 0,
                'latest': recent_values[-1] if recent_values else None
            }
    
    def get_all_metrics_stats(self, hours: int = 24) -> Dict[str, Dict[str, Any]]:
        """Get statistics for all metrics"""
        stats = {}
        for metric_name in self.metrics.keys():
            stats[metric_name] = self.get_metric_stats(metric_name, hours)
        return stats

class RealTimeMonitor:
    """Real-time monitoring for rollback operations"""
    
    def __init__(self, config_manager, database_manager):
        self.config_manager = config_manager
        self.database_manager = database_manager
        self.logger = logging.getLogger(__name__)
        
        # Monitoring state
        self.monitoring_active = False
        self.monitor_thread = None
        self.monitor_lock = threading.Lock()
        
        # Performance metrics
        self.metrics = PerformanceMetrics()
        
        # Monitoring configuration
        self.monitor_config = self.config_manager.get_monitoring_config()
        self.monitor_interval = self.monitor_config.get("interval", 1)
        self.real_time_alerts = self.monitor_config.get("real_time_alerts", True)
        self.performance_tracking = self.monitor_config.get("performance_tracking", True)
        # Honor global main config toggle to silence performance alerts entirely
        try:
            import json as _json
            with open('config/main_config.json', 'r') as _f:
                _main_cfg = _json.load(_f)
                if _main_cfg.get('performance_alerts_enabled', True) is False:
                    self.real_time_alerts = False
                    self.logger.info("Performance alerts disabled by main_config.json")
        except Exception:
            pass
        
        # Alert thresholds
        self.alert_thresholds = {
            'cpu_usage': 80.0,
            'memory_usage': 85.0,
            'disk_usage': 90.0,
            'rollback_duration': 60.0,
            'error_rate': 0.5
        }
        
        # Active rollbacks tracking
        self.active_rollbacks = {}
        self.rollback_lock = threading.Lock()
    
    def start_monitoring(self):
        """Start real-time monitoring"""
        with self.monitor_lock:
            if not self.monitoring_active:
                self.monitoring_active = True
                self.monitor_thread = threading.Thread(target=self._monitor_loop)
                self.monitor_thread.daemon = True
                self.monitor_thread.start()
                self.logger.info("Real-time monitoring started")
    
    def stop_monitoring(self):
        """Stop real-time monitoring"""
        with self.monitor_lock:
            if self.monitoring_active:
                self.monitoring_active = False
                if self.monitor_thread:
                    self.monitor_thread.join(timeout=5)
                self.logger.info("Real-time monitoring stopped")
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.monitoring_active:
            try:
                # Collect system metrics
                self._collect_system_metrics()
                
                # Monitor active rollbacks
                self._monitor_active_rollbacks()
                
                # Check for alerts
                if self.real_time_alerts:
                    self._check_alerts()
                
                # Save metrics to database
                if self.performance_tracking:
                    self._save_metrics_to_database()
                
                time.sleep(self.monitor_interval)
                
            except Exception as e:
                self.logger.error(f"Monitoring loop error: {e}")
                time.sleep(self.monitor_interval)
    
    def _collect_system_metrics(self):
        """Collect system performance metrics"""
        try:
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=0.1)
            self.metrics.add_metric('cpu_usage', cpu_percent)
            
            # Memory usage
            memory = psutil.virtual_memory()
            self.metrics.add_metric('memory_usage', memory.percent)
            
            # Disk usage
            disk = psutil.disk_usage('/')
            disk_percent = (disk.used / disk.total) * 100
            self.metrics.add_metric('disk_usage', disk_percent)
            
            # Network usage
            network = psutil.net_io_counters()
            network_usage = network.bytes_sent + network.bytes_recv
            self.metrics.add_metric('network_usage', network_usage)
            
        except Exception as e:
            self.logger.error(f"Failed to collect system metrics: {e}")
    
    def _monitor_active_rollbacks(self):
        """Monitor active rollback operations"""
        with self.rollback_lock:
            current_time = time.time()
            completed_rollbacks = []
            
            for rollback_id, rollback_info in self.active_rollbacks.items():
                start_time = rollback_info['start_time']
                duration = current_time - start_time
                
                # Check for timeout
                timeout = rollback_info.get('timeout', 300)  # 5 minutes default
                if duration > timeout:
                    self.logger.warning(f"Rollback {rollback_id} exceeded timeout ({timeout}s)")
                    completed_rollbacks.append(rollback_id)
                elif rollback_info.get('completed', False):
                    completed_rollbacks.append(rollback_id)
            
            # Remove completed rollbacks
            for rollback_id in completed_rollbacks:
                rollback_info = self.active_rollbacks.pop(rollback_id)
                duration = current_time - rollback_info['start_time']
                
                # Record metrics
                self.metrics.add_metric('rollback_duration', duration)
                self.metrics.add_metric('rollback_success_rate', 
                                       1.0 if rollback_info.get('success', False) else 0.0)
    
    def _check_alerts(self):
        """Check for alert conditions"""
        try:
            if not self.real_time_alerts:
                return
            # Get recent metrics
            recent_stats = self.metrics.get_all_metrics_stats(hours=1)
            
            alerts = []
            
            # Check CPU usage
            cpu_stats = recent_stats.get('cpu_usage', {})
            if cpu_stats.get('latest', 0) > self.alert_thresholds['cpu_usage']:
                alerts.append(f"High CPU usage: {cpu_stats['latest']:.1f}%")
            
            # Check memory usage
            memory_stats = recent_stats.get('memory_usage', {})
            if memory_stats.get('latest', 0) > self.alert_thresholds['memory_usage']:
                alerts.append(f"High memory usage: {memory_stats['latest']:.1f}%")
            
            # Check disk usage
            disk_stats = recent_stats.get('disk_usage', {})
            if disk_stats.get('latest', 0) > self.alert_thresholds['disk_usage']:
                alerts.append(f"High disk usage: {disk_stats['latest']:.1f}%")
            
            # Check rollback duration
            duration_stats = recent_stats.get('rollback_duration', {})
            if duration_stats.get('latest', 0) > self.alert_thresholds['rollback_duration']:
                alerts.append(f"Long rollback duration: {duration_stats['latest']:.1f}s")
            
            # Check error rate
            error_stats = recent_stats.get('error_count', {})
            success_stats = recent_stats.get('rollback_success_rate', {})
            if success_stats.get('average', 1.0) < (1.0 - self.alert_thresholds['error_rate']):
                alerts.append(f"High error rate: {(1.0 - success_stats['average']) * 100:.1f}%")
            
            # Send alerts
            for alert in alerts:
                self._send_alert(alert)
                
        except Exception as e:
            self.logger.error(f"Alert checking failed: {e}")
    
    def _send_alert(self, message: str):
        """Send alert notification"""
        try:
            alert_entry = {
                "level": "WARNING",
                "message": message,
                "timestamp": datetime.now().isoformat(),
                "component": "rollback_monitor"
            }
            
            # Log alert
            self.logger.warning(f"ALERT: {message}")
            
            # Save to alerts log
            with open("logs/rollback_alerts.jsonl", "a") as f:
                f.write(json.dumps(alert_entry) + "\n")
            
            # Could send to external notification systems here
            
        except Exception as e:
            self.logger.error(f"Failed to send alert: {e}")
    
    def _save_metrics_to_database(self):
        """Save metrics to database"""
        try:
            recent_stats = self.metrics.get_all_metrics_stats(hours=1)
            
            for metric_name, stats in recent_stats.items():
                if stats.get('latest') is not None:
                    self.database_manager.save_performance_metric(
                        "system", metric_name, stats['latest']
                    )
                    
        except Exception as e:
            self.logger.error(f"Failed to save metrics to database: {e}")
    
    def start_rollback_monitoring(self, rollback_id: str, component: str, 
                                 timeout: int = 300) -> bool:
        """Start monitoring a rollback operation"""
        try:
            with self.rollback_lock:
                self.active_rollbacks[rollback_id] = {
                    'component': component,
                    'start_time': time.time(),
                    'timeout': timeout,
                    'completed': False,
                    'success': False
                }
            
            self.logger.info(f"Started monitoring rollback: {rollback_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start rollback monitoring: {e}")
            return False
    
    def complete_rollback_monitoring(self, rollback_id: str, success: bool = True) -> bool:
        """Complete monitoring a rollback operation"""
        try:
            with self.rollback_lock:
                if rollback_id in self.active_rollbacks:
                    self.active_rollbacks[rollback_id]['completed'] = True
                    self.active_rollbacks[rollback_id]['success'] = success
                    
                    # Record metrics
                    duration = time.time() - self.active_rollbacks[rollback_id]['start_time']
                    self.metrics.add_metric('rollback_duration', duration)
                    self.metrics.add_metric('rollback_success_rate', 1.0 if success else 0.0)
                    
                    self.logger.info(f"Completed monitoring rollback: {rollback_id}, Success: {success}")
                    return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Failed to complete rollback monitoring: {e}")
            return False
    
    def get_monitoring_status(self) -> Dict[str, Any]:
        """Get current monitoring status"""
        try:
            with self.monitor_lock:
                monitoring_status = {
                    "monitoring_active": self.monitoring_active,
                    "monitor_interval": self.monitor_interval,
                    "real_time_alerts": self.real_time_alerts,
                    "performance_tracking": self.performance_tracking
                }
            
            with self.rollback_lock:
                active_rollbacks_count = len(self.active_rollbacks)
                monitoring_status["active_rollbacks"] = active_rollbacks_count
            
            # Get recent performance stats
            recent_stats = self.metrics.get_all_metrics_stats(hours=1)
            monitoring_status["recent_performance"] = recent_stats
            
            # Get alert thresholds
            monitoring_status["alert_thresholds"] = self.alert_thresholds
            
            return monitoring_status
            
        except Exception as e:
            self.logger.error(f"Failed to get monitoring status: {e}")
            return {}
    
    def get_performance_report(self, hours: int = 24) -> Dict[str, Any]:
        """Get comprehensive performance report"""
        try:
            # Get metrics statistics
            metrics_stats = self.metrics.get_all_metrics_stats(hours)
            
            # Get database metrics
            db_metrics = self.database_manager.get_performance_metrics(hours=hours)
            
            # Calculate performance indicators
            rollback_duration_stats = metrics_stats.get('rollback_duration', {})
            success_rate_stats = metrics_stats.get('rollback_success_rate', {})
            
            # Performance summary
            performance_summary = {
                "total_rollbacks": rollback_duration_stats.get('count', 0),
                "average_duration": rollback_duration_stats.get('average', 0),
                "success_rate": success_rate_stats.get('average', 0) * 100,
                "max_duration": rollback_duration_stats.get('max', 0),
                "min_duration": rollback_duration_stats.get('min', 0)
            }
            
            # System resource usage
            system_resources = {
                "cpu_usage": metrics_stats.get('cpu_usage', {}),
                "memory_usage": metrics_stats.get('memory_usage', {}),
                "disk_usage": metrics_stats.get('disk_usage', {}),
                "network_usage": metrics_stats.get('network_usage', {})
            }
            
            # Alert summary
            alert_summary = self._get_alert_summary(hours)
            
            report = {
                "report_period_hours": hours,
                "generated_at": datetime.now().isoformat(),
                "performance_summary": performance_summary,
                "system_resources": system_resources,
                "alert_summary": alert_summary,
                "detailed_metrics": metrics_stats,
                "database_metrics": db_metrics
            }
            
            return report
            
        except Exception as e:
            self.logger.error(f"Failed to generate performance report: {e}")
            return {}
    
    def _get_alert_summary(self, hours: int) -> Dict[str, Any]:
        """Get alert summary for the period"""
        try:
            # Read alerts from log file
            alerts = []
            try:
                with open("logs/rollback_alerts.jsonl", "r") as f:
                    for line in f:
                        try:
                            alert = json.loads(line.strip())
                            alert_time = datetime.fromisoformat(alert['timestamp'])
                            if alert_time >= datetime.now() - timedelta(hours=hours):
                                alerts.append(alert)
                        except:
                            pass
            except FileNotFoundError:
                pass
            
            # Count alerts by level
            alert_counts = {}
            for alert in alerts:
                level = alert.get('level', 'UNKNOWN')
                alert_counts[level] = alert_counts.get(level, 0) + 1
            
            return {
                "total_alerts": len(alerts),
                "alert_counts": alert_counts,
                "recent_alerts": alerts[-10:] if alerts else []  # Last 10 alerts
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get alert summary: {e}")
            return {}
    
    def update_alert_threshold(self, metric: str, threshold: float) -> bool:
        """Update alert threshold"""
        try:
            if metric in self.alert_thresholds:
                self.alert_thresholds[metric] = threshold
                self.logger.info(f"Updated alert threshold for {metric}: {threshold}")
                return True
            return False
        except Exception as e:
            self.logger.error(f"Failed to update alert threshold: {e}")
            return False
    
    def reset_metrics(self):
        """Reset all metrics"""
        try:
            self.metrics = PerformanceMetrics()
            self.logger.info("Metrics reset")
        except Exception as e:
            self.logger.error(f"Failed to reset metrics: {e}")
