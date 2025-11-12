"""
Enhanced Real-Time Monitoring System
Provides comprehensive real-time monitoring capabilities
"""

import psutil
import time
import json
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import logging
import os
import hashlib
from collections import deque
import statistics

class EnhancedRealTimeMonitor:
    """Enhanced real-time monitoring with comprehensive metrics"""
    
    def __init__(self, config_manager):
        self.config_manager = config_manager
        self.logger = logging.getLogger(__name__)
        self.monitor_lock = threading.Lock()
        
        # Monitoring data
        self.metrics_history = deque(maxlen=1000)
        self.alert_thresholds = {}
        self.baseline_metrics = {}
        self.anomaly_scores = deque(maxlen=100)
        
        # Configuration
        self.monitor_interval = 1.0  # seconds
        self.alert_cooldown = 60.0  # seconds
        self.last_alerts = {}
        
        # Enhanced monitoring components
        self.file_monitor = None
        self.process_monitor = None
        self.network_monitor = None
        self.performance_monitor = None
        
        # Initialize monitoring
        self._initialize_monitoring()
    
    def _initialize_monitoring(self):
        """Initialize monitoring components"""
        try:
            # Set up alert thresholds
            self.alert_thresholds = {
                "cpu_usage": 80.0,
                "memory_usage": 80.0,
                "disk_usage": 85.0,
                "network_bandwidth": 80.0,
                "process_count": 200,
                "file_changes": 10,
                "network_connections": 1000,
                "response_time": 5.0
            }
            
            # Initialize baseline metrics
            self._establish_baseline()
            
            self.logger.info("Enhanced real-time monitoring initialized")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize monitoring: {e}")
    
    def start_enhanced_monitoring(self) -> Dict[str, Any]:
        """Start enhanced monitoring"""
        try:
            self.logger.info("Starting enhanced real-time monitoring...")
            
            # Start monitoring thread
            monitor_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
            monitor_thread.start()
            
            return {
                "success": True,
                "message": "Enhanced monitoring started",
                "monitor_interval": self.monitor_interval,
                "alert_thresholds": self.alert_thresholds
            }
            
        except Exception as e:
            self.logger.error(f"Failed to start enhanced monitoring: {e}")
            return {"success": False, "error": str(e)}
    
    def _monitoring_loop(self):
        """Main monitoring loop"""
        while True:
            try:
                start_time = time.time()
                
                # Collect comprehensive metrics
                metrics = self._collect_comprehensive_metrics()
                
                # Analyze metrics
                analysis_result = self._analyze_metrics(metrics)
                
                # Check for alerts
                alerts = self._check_alerts(metrics, analysis_result)
                
                # Store metrics
                with self.monitor_lock:
                    self.metrics_history.append({
                        "timestamp": datetime.now().isoformat(),
                        "metrics": metrics,
                        "analysis": analysis_result,
                        "alerts": alerts
                    })
                
                # Process alerts
                if alerts:
                    self._process_alerts(alerts)
                
                # Calculate sleep time
                elapsed = time.time() - start_time
                sleep_time = max(0, self.monitor_interval - elapsed)
                time.sleep(sleep_time)
                
            except Exception as e:
                self.logger.error(f"Monitoring loop error: {e}")
                time.sleep(self.monitor_interval)
    
    def _collect_comprehensive_metrics(self) -> Dict[str, Any]:
        """Collect comprehensive system metrics"""
        try:
            metrics = {
                "timestamp": datetime.now().isoformat(),
                "system": self._get_system_metrics(),
                "performance": self._get_performance_metrics(),
                "network": self._get_network_metrics(),
                "processes": self._get_process_metrics(),
                "files": self._get_file_metrics(),
                "security": self._get_security_metrics()
            }
            
            return metrics
            
        except Exception as e:
            self.logger.error(f"Failed to collect metrics: {e}")
            return {}
    
    def _get_system_metrics(self) -> Dict[str, Any]:
        """Get system-level metrics"""
        try:
            # CPU metrics
            cpu_percent = psutil.cpu_percent(interval=0.1)
            cpu_count = psutil.cpu_count()
            cpu_freq = psutil.cpu_freq()
            
            # Memory metrics
            memory = psutil.virtual_memory()
            swap = psutil.swap_memory()
            
            # Disk metrics
            disk_usage = psutil.disk_usage('/')
            disk_io = psutil.disk_io_counters()
            
            # Boot time
            boot_time = psutil.boot_time()
            
            return {
                "cpu": {
                    "percent": cpu_percent,
                    "count": cpu_count,
                    "frequency": cpu_freq.current if cpu_freq else 0,
                    "load_avg": os.getloadavg() if hasattr(os, 'getloadavg') else [0, 0, 0]
                },
                "memory": {
                    "total": memory.total,
                    "available": memory.available,
                    "percent": memory.percent,
                    "used": memory.used,
                    "free": memory.free,
                    "swap_total": swap.total,
                    "swap_used": swap.used,
                    "swap_percent": swap.percent
                },
                "disk": {
                    "total": disk_usage.total,
                    "used": disk_usage.used,
                    "free": disk_usage.free,
                    "percent": (disk_usage.used / disk_usage.total) * 100,
                    "read_bytes": disk_io.read_bytes if disk_io else 0,
                    "write_bytes": disk_io.write_bytes if disk_io else 0
                },
                "boot_time": boot_time,
                "uptime": time.time() - boot_time
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get system metrics: {e}")
            return {}
    
    def _get_performance_metrics(self) -> Dict[str, Any]:
        """Get performance metrics"""
        try:
            # Process performance
            processes = list(psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']))
            
            total_cpu = sum(p.info['cpu_percent'] for p in processes)
            total_memory = sum(p.info['memory_percent'] for p in processes)
            
            # Top processes by CPU
            top_cpu_processes = sorted(processes, key=lambda x: x.info['cpu_percent'], reverse=True)[:5]
            
            # Top processes by memory
            top_memory_processes = sorted(processes, key=lambda x: x.info['memory_percent'], reverse=True)[:5]
            
            return {
                "total_processes": len(processes),
                "total_cpu_percent": total_cpu,
                "total_memory_percent": total_memory,
                "top_cpu_processes": [
                    {
                        "pid": p.info['pid'],
                        "name": p.info['name'],
                        "cpu_percent": p.info['cpu_percent']
                    } for p in top_cpu_processes
                ],
                "top_memory_processes": [
                    {
                        "pid": p.info['pid'],
                        "name": p.info['name'],
                        "memory_percent": p.info['memory_percent']
                    } for p in top_memory_processes
                ]
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get performance metrics: {e}")
            return {}
    
    def _get_network_metrics(self) -> Dict[str, Any]:
        """Get network metrics"""
        try:
            # Network I/O
            net_io = psutil.net_io_counters()
            
            # Network connections
            connections = psutil.net_connections()
            
            # Network interfaces
            interfaces = psutil.net_if_addrs()
            interface_stats = psutil.net_if_stats()
            
            # Calculate network usage
            network_usage = {}
            for interface, addrs in interfaces.items():
                if interface in interface_stats:
                    stats = interface_stats[interface]
                    network_usage[interface] = {
                        "is_up": stats.isup,
                        "duplex": stats.duplex,
                        "speed": stats.speed,
                        "mtu": stats.mtu
                    }
            
            return {
                "bytes_sent": net_io.bytes_sent,
                "bytes_recv": net_io.bytes_recv,
                "packets_sent": net_io.packets_sent,
                "packets_recv": net_io.packets_recv,
                "connections": len(connections),
                "interfaces": network_usage,
                "active_connections": [
                    {
                        "fd": conn.fd,
                        "family": conn.family,
                        "type": conn.type,
                        "laddr": conn.laddr,
                        "raddr": conn.raddr,
                        "status": conn.status
                    } for conn in connections[:10]  # Limit for performance
                ]
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get network metrics: {e}")
            return {}
    
    def _get_process_metrics(self) -> Dict[str, Any]:
        """Get process metrics"""
        try:
            processes = list(psutil.process_iter(['pid', 'name', 'status', 'create_time', 'cpu_percent', 'memory_percent']))
            
            # Process status distribution
            status_counts = {}
            for process in processes:
                status = process.info['status']
                status_counts[status] = status_counts.get(status, 0) + 1
            
            # Process creation rate
            current_time = time.time()
            recent_processes = [
                p for p in processes 
                if current_time - p.info['create_time'] < 60  # Last minute
            ]
            
            return {
                "total_processes": len(processes),
                "status_distribution": status_counts,
                "recent_processes": len(recent_processes),
                "process_details": [
                    {
                        "pid": p.info['pid'],
                        "name": p.info['name'],
                        "status": p.info['status'],
                        "cpu_percent": p.info['cpu_percent'],
                        "memory_percent": p.info['memory_percent'],
                        "create_time": p.info['create_time']
                    } for p in processes[:20]  # Limit for performance
                ]
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get process metrics: {e}")
            return {}
    
    def _get_file_metrics(self) -> Dict[str, Any]:
        """Get file system metrics"""
        try:
            # File system usage
            partitions = psutil.disk_partitions()
            partition_usage = {}
            
            for partition in partitions:
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    partition_usage[partition.device] = {
                        "mountpoint": partition.mountpoint,
                        "fstype": partition.fstype,
                        "total": usage.total,
                        "used": usage.used,
                        "free": usage.free,
                        "percent": (usage.used / usage.total) * 100
                    }
                except PermissionError:
                    continue
            
            # Open files count
            open_files_count = 0
            try:
                for process in psutil.process_iter(['pid']):
                    try:
                        open_files_count += len(process.open_files())
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
            except Exception:
                pass
            
            return {
                "partitions": partition_usage,
                "open_files_count": open_files_count,
                "total_partitions": len(partitions)
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get file metrics: {e}")
            return {}
    
    def _get_security_metrics(self) -> Dict[str, Any]:
        """Get security-related metrics"""
        try:
            # User sessions
            users = psutil.users()
            
            # System load
            load_avg = os.getloadavg() if hasattr(os, 'getloadavg') else [0, 0, 0]
            
            # Process anomalies
            processes = list(psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']))
            
            # Calculate anomaly scores
            cpu_scores = [p.info['cpu_percent'] for p in processes if p.info['cpu_percent'] > 0]
            memory_scores = [p.info['memory_percent'] for p in processes if p.info['memory_percent'] > 0]
            
            high_cpu_processes = len([p for p in processes if p.info['cpu_percent'] > 50])
            high_memory_processes = len([p for p in processes if p.info['memory_percent'] > 50])
            
            return {
                "active_users": len(users),
                "user_sessions": [
                    {
                        "name": user.name,
                        "terminal": user.terminal,
                        "host": user.host,
                        "started": user.started
                    } for user in users
                ],
                "load_average": load_avg,
                "high_cpu_processes": high_cpu_processes,
                "high_memory_processes": high_memory_processes,
                "cpu_anomaly_score": statistics.mean(cpu_scores) if cpu_scores else 0,
                "memory_anomaly_score": statistics.mean(memory_scores) if memory_scores else 0
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get security metrics: {e}")
            return {}
    
    def _analyze_metrics(self, metrics: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze metrics for anomalies"""
        try:
            analysis = {
                "timestamp": datetime.now().isoformat(),
                "anomalies": [],
                "trends": {},
                "alerts": []
            }
            
            # Analyze system metrics
            system_metrics = metrics.get("system", {})
            if system_metrics:
                # CPU analysis
                cpu_percent = system_metrics.get("cpu", {}).get("percent", 0)
                if cpu_percent > self.alert_thresholds["cpu_usage"]:
                    analysis["anomalies"].append({
                        "type": "high_cpu",
                        "value": cpu_percent,
                        "threshold": self.alert_thresholds["cpu_usage"]
                    })
                
                # Memory analysis
                memory_percent = system_metrics.get("memory", {}).get("percent", 0)
                if memory_percent > self.alert_thresholds["memory_usage"]:
                    analysis["anomalies"].append({
                        "type": "high_memory",
                        "value": memory_percent,
                        "threshold": self.alert_thresholds["memory_usage"]
                    })
                
                # Disk analysis
                disk_percent = system_metrics.get("disk", {}).get("percent", 0)
                if disk_percent > self.alert_thresholds["disk_usage"]:
                    analysis["anomalies"].append({
                        "type": "high_disk",
                        "value": disk_percent,
                        "threshold": self.alert_thresholds["disk_usage"]
                    })
            
            # Analyze network metrics
            network_metrics = metrics.get("network", {})
            if network_metrics:
                connections = network_metrics.get("connections", 0)
                if connections > self.alert_thresholds["network_connections"]:
                    analysis["anomalies"].append({
                        "type": "high_connections",
                        "value": connections,
                        "threshold": self.alert_thresholds["network_connections"]
                    })
            
            # Analyze process metrics
            process_metrics = metrics.get("processes", {})
            if process_metrics:
                total_processes = process_metrics.get("total_processes", 0)
                if total_processes > self.alert_thresholds["process_count"]:
                    analysis["anomalies"].append({
                        "type": "high_process_count",
                        "value": total_processes,
                        "threshold": self.alert_thresholds["process_count"]
                    })
            
            # Calculate overall anomaly score
            anomaly_count = len(analysis["anomalies"])
            analysis["anomaly_score"] = min(anomaly_count / 5.0, 1.0)  # Normalize to 0-1
            
            # Store anomaly score
            self.anomaly_scores.append(analysis["anomaly_score"])
            
            return analysis
            
        except Exception as e:
            self.logger.error(f"Failed to analyze metrics: {e}")
            return {"anomalies": [], "anomaly_score": 0.0}
    
    def _check_alerts(self, metrics: Dict[str, Any], analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for alert conditions"""
        try:
            alerts = []
            current_time = time.time()
            
            # Check each anomaly for alerts
            for anomaly in analysis.get("anomalies", []):
                alert_type = anomaly["type"]
                
                # Check cooldown
                last_alert_time = self.last_alerts.get(alert_type, 0)
                if current_time - last_alert_time < self.alert_cooldown:
                    continue
                
                # Create alert
                alert = {
                    "type": alert_type,
                    "severity": self._determine_alert_severity(anomaly),
                    "value": anomaly["value"],
                    "threshold": anomaly["threshold"],
                    "timestamp": datetime.now().isoformat(),
                    "metrics": metrics
                }
                
                alerts.append(alert)
                self.last_alerts[alert_type] = current_time
            
            return alerts
            
        except Exception as e:
            self.logger.error(f"Failed to check alerts: {e}")
            return []
    
    def _determine_alert_severity(self, anomaly: Dict[str, Any]) -> str:
        """Determine alert severity"""
        value = anomaly["value"]
        threshold = anomaly["threshold"]
        
        if value > threshold * 1.5:
            return "CRITICAL"
        elif value > threshold * 1.2:
            return "HIGH"
        elif value > threshold:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _process_alerts(self, alerts: List[Dict[str, Any]]):
        """Process alerts"""
        try:
            for alert in alerts:
                self.logger.warning(f"ALERT: {alert['type']} - {alert['severity']} - Value: {alert['value']}")
                
                # Log alert
                self._log_alert(alert)
                
                # Trigger response if needed
                if alert["severity"] in ["CRITICAL", "HIGH"]:
                    self._trigger_alert_response(alert)
                    
        except Exception as e:
            self.logger.error(f"Failed to process alerts: {e}")
    
    def _trigger_alert_response(self, alert: Dict[str, Any]):
        """Trigger response for critical alerts"""
        try:
            self.logger.critical(f"Triggering response for {alert['type']} alert")
            
            # This would integrate with the main system's response mechanisms
            # For now, just log the alert
            
        except Exception as e:
            self.logger.error(f"Failed to trigger alert response: {e}")
    
    def _log_alert(self, alert: Dict[str, Any]):
        """Log alert to file"""
        try:
            alert_file = "logs/enhanced_monitoring_alerts.jsonl"
            with open(alert_file, 'a') as f:
                f.write(json.dumps(alert) + '\n')
        except Exception as e:
            self.logger.error(f"Failed to log alert: {e}")
    
    def _establish_baseline(self):
        """Establish baseline metrics"""
        try:
            # Collect metrics for baseline
            baseline_metrics = []
            for _ in range(10):  # Collect 10 samples
                metrics = self._collect_comprehensive_metrics()
                if metrics:
                    baseline_metrics.append(metrics)
                time.sleep(1)
            
            if baseline_metrics:
                # Calculate baseline averages
                self.baseline_metrics = self._calculate_baseline_averages(baseline_metrics)
                self.logger.info("Baseline metrics established")
            
        except Exception as e:
            self.logger.error(f"Failed to establish baseline: {e}")
    
    def _calculate_baseline_averages(self, metrics_list: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate baseline averages from metrics"""
        try:
            baseline = {}
            
            # CPU baseline
            cpu_values = [m.get("system", {}).get("cpu", {}).get("percent", 0) for m in metrics_list]
            baseline["cpu_avg"] = statistics.mean(cpu_values) if cpu_values else 0
            
            # Memory baseline
            memory_values = [m.get("system", {}).get("memory", {}).get("percent", 0) for m in metrics_list]
            baseline["memory_avg"] = statistics.mean(memory_values) if memory_values else 0
            
            # Process count baseline
            process_counts = [m.get("processes", {}).get("total_processes", 0) for m in metrics_list]
            baseline["process_count_avg"] = statistics.mean(process_counts) if process_counts else 0
            
            # Network connections baseline
            connection_counts = [m.get("network", {}).get("connections", 0) for m in metrics_list]
            baseline["connections_avg"] = statistics.mean(connection_counts) if connection_counts else 0
            
            return baseline
            
        except Exception as e:
            self.logger.error(f"Failed to calculate baseline: {e}")
            return {}
    
    def get_monitoring_status(self) -> Dict[str, Any]:
        """Get monitoring status"""
        try:
            with self.monitor_lock:
                recent_metrics = list(self.metrics_history)[-10:] if self.metrics_history else []
                recent_anomaly_scores = list(self.anomaly_scores)[-10:] if self.anomaly_scores else []
                
                return {
                    "monitoring_active": True,
                    "metrics_collected": len(self.metrics_history),
                    "anomaly_scores": len(self.anomaly_scores),
                    "baseline_established": bool(self.baseline_metrics),
                    "alert_thresholds": self.alert_thresholds,
                    "baseline_metrics": self.baseline_metrics,
                    "recent_anomaly_score": statistics.mean(recent_anomaly_scores) if recent_anomaly_scores else 0,
                    "last_metrics": recent_metrics[-1] if recent_metrics else None
                }
                
        except Exception as e:
            self.logger.error(f"Failed to get monitoring status: {e}")
            return {"monitoring_active": False, "error": str(e)}
    
    def get_metrics_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get metrics history"""
        try:
            with self.monitor_lock:
                return list(self.metrics_history)[-limit:] if self.metrics_history else []
        except Exception as e:
            self.logger.error(f"Failed to get metrics history: {e}")
            return []
    
    def stop_monitoring(self):
        """Stop monitoring"""
        try:
            self.logger.info("Stopping enhanced monitoring...")
            # Monitoring will stop when the thread exits
        except Exception as e:
            self.logger.error(f"Failed to stop monitoring: {e}")
