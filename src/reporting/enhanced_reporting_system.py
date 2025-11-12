"""
Enhanced Reporting and Analytics System
Provides comprehensive reporting and analytics capabilities
"""

import json
import time
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import logging
import os
import pandas as pd
import numpy as np
from collections import defaultdict, deque
import statistics
import matplotlib.pyplot as plt
import seaborn as sns
from dataclasses import dataclass
from enum import Enum

class ReportType(Enum):
    """Report type enumeration"""
    PERFORMANCE = "performance"
    SECURITY = "security"
    SYSTEM_HEALTH = "system_health"
    ANOMALY_ANALYSIS = "anomaly_analysis"
    ROLLBACK_ANALYSIS = "rollback_analysis"
    NETWORK_ANALYSIS = "network_analysis"
    COMPREHENSIVE = "comprehensive"

@dataclass
class ReportConfig:
    """Report configuration"""
    report_type: ReportType
    time_range: str  # "1h", "24h", "7d", "30d"
    include_charts: bool = True
    include_recommendations: bool = True
    format: str = "json"  # "json", "html", "pdf"
    detail_level: str = "detailed"  # "summary", "detailed", "comprehensive"

class EnhancedReportingSystem:
    """Enhanced reporting and analytics system"""
    
    def __init__(self, config_manager):
        self.config_manager = config_manager
        self.logger = logging.getLogger(__name__)
        self.report_lock = threading.Lock()
        
        # Data storage
        self.performance_data = deque(maxlen=10000)
        self.security_data = deque(maxlen=5000)
        self.anomaly_data = deque(maxlen=5000)
        self.rollback_data = deque(maxlen=2000)
        self.network_data = deque(maxlen=5000)
        
        # Report templates
        self.report_templates = {}
        self.report_history = deque(maxlen=1000)
        
        # Analytics
        self.analytics_cache = {}
        self.trend_analysis = {}
        self.correlation_analysis = {}
        
        # Configuration
        self.reports_dir = "reports"
        self.charts_dir = "reports/charts"
        self.cache_ttl = 3600  # 1 hour
        
        # Initialize reporting system
        self._initialize_reporting_system()
    
    def _initialize_reporting_system(self):
        """Initialize reporting system"""
        try:
            # Create directories
            os.makedirs(self.reports_dir, exist_ok=True)
            os.makedirs(self.charts_dir, exist_ok=True)
            
            # Initialize report templates
            self._initialize_report_templates()
            
            # Start data collection
            self._start_data_collection()
            
            self.logger.info("Enhanced reporting system initialized")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize reporting system: {e}")
    
    def generate_report(self, config: ReportConfig) -> Dict[str, Any]:
        """Generate comprehensive report"""
        try:
            report_id = f"report_{int(time.time())}"
            
            # Collect data
            data = self._collect_report_data(config)
            
            # Generate analytics
            analytics = self._generate_analytics(data, config)
            
            # Generate recommendations
            recommendations = self._generate_recommendations(analytics, config)
            
            # Create report
            report = {
                "report_id": report_id,
                "report_type": config.report_type.value,
                "time_range": config.time_range,
                "generated_at": datetime.now().isoformat(),
                "data": data,
                "analytics": analytics,
                "recommendations": recommendations,
                "summary": self._generate_summary(analytics),
                "metadata": {
                    "data_points": len(data.get("performance_data", [])),
                    "anomalies_detected": len(data.get("anomaly_data", [])),
                    "rollbacks_performed": len(data.get("rollback_data", [])),
                    "network_events": len(data.get("network_data", []))
                }
            }
            
            # Generate charts if requested
            if config.include_charts:
                charts = self._generate_charts(data, analytics, report_id)
                report["charts"] = charts
            
            # Save report
            self._save_report(report, config)
            
            # Store in history
            with self.report_lock:
                self.report_history.append(report)
            
            return report
            
        except Exception as e:
            self.logger.error(f"Report generation failed: {e}")
            return {"error": str(e)}
    
    def get_performance_report(self, hours: int = 24) -> Dict[str, Any]:
        """Get performance report"""
        try:
            config = ReportConfig(
                report_type=ReportType.PERFORMANCE,
                time_range=f"{hours}h",
                include_charts=True,
                include_recommendations=True
            )
            
            return self.generate_report(config)
            
        except Exception as e:
            self.logger.error(f"Performance report generation failed: {e}")
            return {"error": str(e)}
    
    def get_security_report(self, hours: int = 24) -> Dict[str, Any]:
        """Get security report"""
        try:
            config = ReportConfig(
                report_type=ReportType.SECURITY,
                time_range=f"{hours}h",
                include_charts=True,
                include_recommendations=True
            )
            
            return self.generate_report(config)
            
        except Exception as e:
            self.logger.error(f"Security report generation failed: {e}")
            return {"error": str(e)}
    
    def get_anomaly_analysis_report(self, hours: int = 24) -> Dict[str, Any]:
        """Get anomaly analysis report"""
        try:
            config = ReportConfig(
                report_type=ReportType.ANOMALY_ANALYSIS,
                time_range=f"{hours}h",
                include_charts=True,
                include_recommendations=True
            )
            
            return self.generate_report(config)
            
        except Exception as e:
            self.logger.error(f"Anomaly analysis report generation failed: {e}")
            return {"error": str(e)}
    
    def get_rollback_analysis_report(self, hours: int = 24) -> Dict[str, Any]:
        """Get rollback analysis report"""
        try:
            config = ReportConfig(
                report_type=ReportType.ROLLBACK_ANALYSIS,
                time_range=f"{hours}h",
                include_charts=True,
                include_recommendations=True
            )
            
            return self.generate_report(config)
            
        except Exception as e:
            self.logger.error(f"Rollback analysis report generation failed: {e}")
            return {"error": str(e)}
    
    def get_comprehensive_report(self, hours: int = 24) -> Dict[str, Any]:
        """Get comprehensive system report"""
        try:
            config = ReportConfig(
                report_type=ReportType.COMPREHENSIVE,
                time_range=f"{hours}h",
                include_charts=True,
                include_recommendations=True,
                detail_level="comprehensive"
            )
            
            return self.generate_report(config)
            
        except Exception as e:
            self.logger.error(f"Comprehensive report generation failed: {e}")
            return {"error": str(e)}
    
    def add_performance_data(self, data: Dict[str, Any]):
        """Add performance data"""
        try:
            with self.report_lock:
                self.performance_data.append({
                    "timestamp": datetime.now().isoformat(),
                    "data": data
                })
        except Exception as e:
            self.logger.error(f"Failed to add performance data: {e}")
    
    def add_security_data(self, data: Dict[str, Any]):
        """Add security data"""
        try:
            with self.report_lock:
                self.security_data.append({
                    "timestamp": datetime.now().isoformat(),
                    "data": data
                })
        except Exception as e:
            self.logger.error(f"Failed to add security data: {e}")
    
    def add_anomaly_data(self, data: Dict[str, Any]):
        """Add anomaly data"""
        try:
            with self.report_lock:
                self.anomaly_data.append({
                    "timestamp": datetime.now().isoformat(),
                    "data": data
                })
        except Exception as e:
            self.logger.error(f"Failed to add anomaly data: {e}")
    
    def add_rollback_data(self, data: Dict[str, Any]):
        """Add rollback data"""
        try:
            with self.report_lock:
                self.rollback_data.append({
                    "timestamp": datetime.now().isoformat(),
                    "data": data
                })
        except Exception as e:
            self.logger.error(f"Failed to add rollback data: {e}")
    
    def add_network_data(self, data: Dict[str, Any]):
        """Add network data"""
        try:
            with self.report_lock:
                self.network_data.append({
                    "timestamp": datetime.now().isoformat(),
                    "data": data
                })
        except Exception as e:
            self.logger.error(f"Failed to add network data: {e}")
    
    def _collect_report_data(self, config: ReportConfig) -> Dict[str, Any]:
        """Collect data for report"""
        try:
            # Calculate time range
            time_range = self._parse_time_range(config.time_range)
            cutoff_time = datetime.now() - time_range
            
            # Filter data by time range
            performance_data = [
                entry for entry in self.performance_data
                if datetime.fromisoformat(entry["timestamp"]) >= cutoff_time
            ]
            
            security_data = [
                entry for entry in self.security_data
                if datetime.fromisoformat(entry["timestamp"]) >= cutoff_time
            ]
            
            anomaly_data = [
                entry for entry in self.anomaly_data
                if datetime.fromisoformat(entry["timestamp"]) >= cutoff_time
            ]
            
            rollback_data = [
                entry for entry in self.rollback_data
                if datetime.fromisoformat(entry["timestamp"]) >= cutoff_time
            ]
            
            network_data = [
                entry for entry in self.network_data
                if datetime.fromisoformat(entry["timestamp"]) >= cutoff_time
            ]
            
            return {
                "performance_data": performance_data,
                "security_data": security_data,
                "anomaly_data": anomaly_data,
                "rollback_data": rollback_data,
                "network_data": network_data,
                "time_range": config.time_range,
                "data_points": len(performance_data) + len(security_data) + len(anomaly_data) + len(rollback_data) + len(network_data)
            }
            
        except Exception as e:
            self.logger.error(f"Data collection failed: {e}")
            return {}
    
    def _generate_analytics(self, data: Dict[str, Any], config: ReportConfig) -> Dict[str, Any]:
        """Generate analytics from data"""
        try:
            analytics = {}
            
            # Performance analytics
            if data.get("performance_data"):
                analytics["performance"] = self._analyze_performance_data(data["performance_data"])
            
            # Security analytics
            if data.get("security_data"):
                analytics["security"] = self._analyze_security_data(data["security_data"])
            
            # Anomaly analytics
            if data.get("anomaly_data"):
                analytics["anomaly"] = self._analyze_anomaly_data(data["anomaly_data"])
            
            # Rollback analytics
            if data.get("rollback_data"):
                analytics["rollback"] = self._analyze_rollback_data(data["rollback_data"])
            
            # Network analytics
            if data.get("network_data"):
                analytics["network"] = self._analyze_network_data(data["network_data"])
            
            # Trend analysis
            analytics["trends"] = self._analyze_trends(data)
            
            # Correlation analysis
            analytics["correlations"] = self._analyze_correlations(data)
            
            return analytics
            
        except Exception as e:
            self.logger.error(f"Analytics generation failed: {e}")
            return {}
    
    def _analyze_performance_data(self, performance_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze performance data"""
        try:
            if not performance_data:
                return {"error": "No performance data available"}
            
            # Extract metrics
            cpu_values = []
            memory_values = []
            disk_values = []
            network_values = []
            
            for entry in performance_data:
                data = entry.get("data", {})
                cpu_values.append(data.get("cpu_usage", 0))
                memory_values.append(data.get("memory_usage", 0))
                disk_values.append(data.get("disk_usage", 0))
                network_values.append(data.get("network_bandwidth", 0))
            
            # Calculate statistics
            analysis = {
                "cpu": {
                    "mean": statistics.mean(cpu_values) if cpu_values else 0,
                    "median": statistics.median(cpu_values) if cpu_values else 0,
                    "max": max(cpu_values) if cpu_values else 0,
                    "min": min(cpu_values) if cpu_values else 0,
                    "std": statistics.stdev(cpu_values) if len(cpu_values) > 1 else 0
                },
                "memory": {
                    "mean": statistics.mean(memory_values) if memory_values else 0,
                    "median": statistics.median(memory_values) if memory_values else 0,
                    "max": max(memory_values) if memory_values else 0,
                    "min": min(memory_values) if memory_values else 0,
                    "std": statistics.stdev(memory_values) if len(memory_values) > 1 else 0
                },
                "disk": {
                    "mean": statistics.mean(disk_values) if disk_values else 0,
                    "median": statistics.median(disk_values) if disk_values else 0,
                    "max": max(disk_values) if disk_values else 0,
                    "min": min(disk_values) if disk_values else 0,
                    "std": statistics.stdev(disk_values) if len(disk_values) > 1 else 0
                },
                "network": {
                    "mean": statistics.mean(network_values) if network_values else 0,
                    "median": statistics.median(network_values) if network_values else 0,
                    "max": max(network_values) if network_values else 0,
                    "min": min(network_values) if network_values else 0,
                    "std": statistics.stdev(network_values) if len(network_values) > 1 else 0
                }
            }
            
            # Performance score
            cpu_score = 1.0 - (analysis["cpu"]["mean"] / 100.0)
            memory_score = 1.0 - (analysis["memory"]["mean"] / 100.0)
            disk_score = 1.0 - (analysis["disk"]["mean"] / 100.0)
            
            analysis["performance_score"] = (cpu_score + memory_score + disk_score) / 3.0
            
            return analysis
            
        except Exception as e:
            self.logger.error(f"Performance analysis failed: {e}")
            return {"error": str(e)}
    
    def _analyze_security_data(self, security_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze security data"""
        try:
            if not security_data:
                return {"error": "No security data available"}
            
            # Count security events
            threat_levels = defaultdict(int)
            security_events = 0
            
            for entry in security_data:
                data = entry.get("data", {})
                threat_level = data.get("threat_level", "UNKNOWN")
                threat_levels[threat_level] += 1
                security_events += 1
            
            analysis = {
                "total_events": security_events,
                "threat_level_distribution": dict(threat_levels),
                "critical_threats": threat_levels.get("CRITICAL", 0),
                "high_threats": threat_levels.get("HIGH", 0),
                "medium_threats": threat_levels.get("MEDIUM", 0),
                "low_threats": threat_levels.get("LOW", 0)
            }
            
            # Security score
            if security_events > 0:
                critical_ratio = analysis["critical_threats"] / security_events
                high_ratio = analysis["high_threats"] / security_events
                security_score = 1.0 - (critical_ratio * 0.5 + high_ratio * 0.3)
            else:
                security_score = 1.0
            
            analysis["security_score"] = max(security_score, 0.0)
            
            return analysis
            
        except Exception as e:
            self.logger.error(f"Security analysis failed: {e}")
            return {"error": str(e)}
    
    def _analyze_anomaly_data(self, anomaly_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze anomaly data"""
        try:
            if not anomaly_data:
                return {"error": "No anomaly data available"}
            
            # Analyze anomaly patterns
            anomaly_scores = []
            threat_levels = defaultdict(int)
            pattern_types = defaultdict(int)
            
            for entry in anomaly_data:
                data = entry.get("data", {})
                anomaly_scores.append(data.get("anomaly_score", 0))
                threat_levels[data.get("threat_level", "UNKNOWN")] += 1
                pattern_types[data.get("pattern_type", "unknown")] += 1
            
            analysis = {
                "total_anomalies": len(anomaly_data),
                "mean_anomaly_score": statistics.mean(anomaly_scores) if anomaly_scores else 0,
                "max_anomaly_score": max(anomaly_scores) if anomaly_scores else 0,
                "threat_level_distribution": dict(threat_levels),
                "pattern_type_distribution": dict(pattern_types),
                "anomaly_frequency": len(anomaly_data) / max(len(anomaly_data), 1)
            }
            
            return analysis
            
        except Exception as e:
            self.logger.error(f"Anomaly analysis failed: {e}")
            return {"error": str(e)}
    
    def _analyze_rollback_data(self, rollback_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze rollback data"""
        try:
            if not rollback_data:
                return {"error": "No rollback data available"}
            
            # Analyze rollback patterns
            successful_rollbacks = 0
            failed_rollbacks = 0
            rollback_durations = []
            strategies = defaultdict(int)
            
            for entry in rollback_data:
                data = entry.get("data", {})
                if data.get("success", False):
                    successful_rollbacks += 1
                else:
                    failed_rollbacks += 1
                
                duration = data.get("duration", 0)
                if duration > 0:
                    rollback_durations.append(duration)
                
                strategy = data.get("strategy", "unknown")
                strategies[strategy] += 1
            
            analysis = {
                "total_rollbacks": len(rollback_data),
                "successful_rollbacks": successful_rollbacks,
                "failed_rollbacks": failed_rollbacks,
                "success_rate": successful_rollbacks / max(len(rollback_data), 1),
                "mean_duration": statistics.mean(rollback_durations) if rollback_durations else 0,
                "strategy_distribution": dict(strategies)
            }
            
            # Rollback efficiency score
            if len(rollback_data) > 0:
                efficiency_score = analysis["success_rate"] * (1.0 - min(analysis["mean_duration"] / 60.0, 1.0))
            else:
                efficiency_score = 1.0
            
            analysis["efficiency_score"] = max(efficiency_score, 0.0)
            
            return analysis
            
        except Exception as e:
            self.logger.error(f"Rollback analysis failed: {e}")
            return {"error": str(e)}
    
    def _analyze_network_data(self, network_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze network data"""
        try:
            if not network_data:
                return {"error": "No network data available"}
            
            # Analyze network patterns
            bandwidth_values = []
            connection_counts = []
            suspicious_events = 0
            
            for entry in network_data:
                data = entry.get("data", {})
                bandwidth_values.append(data.get("total_bandwidth_per_sec", 0))
                connection_counts.append(data.get("total_connections", 0))
                
                if data.get("total_suspicious", 0) > 0:
                    suspicious_events += 1
            
            analysis = {
                "total_events": len(network_data),
                "mean_bandwidth": statistics.mean(bandwidth_values) if bandwidth_values else 0,
                "max_bandwidth": max(bandwidth_values) if bandwidth_values else 0,
                "mean_connections": statistics.mean(connection_counts) if connection_counts else 0,
                "max_connections": max(connection_counts) if connection_counts else 0,
                "suspicious_events": suspicious_events,
                "suspicious_ratio": suspicious_events / max(len(network_data), 1)
            }
            
            return analysis
            
        except Exception as e:
            self.logger.error(f"Network analysis failed: {e}")
            return {"error": str(e)}
    
    def _analyze_trends(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze trends in data"""
        try:
            trends = {}
            
            # Performance trends
            if data.get("performance_data"):
                trends["performance"] = self._calculate_trend(data["performance_data"], "cpu_usage")
            
            # Anomaly trends
            if data.get("anomaly_data"):
                trends["anomaly"] = self._calculate_trend(data["anomaly_data"], "anomaly_score")
            
            # Security trends
            if data.get("security_data"):
                trends["security"] = self._calculate_trend(data["security_data"], "threat_level")
            
            return trends
            
        except Exception as e:
            self.logger.error(f"Trend analysis failed: {e}")
            return {}
    
    def _analyze_correlations(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze correlations between different metrics"""
        try:
            correlations = {}
            
            # Extract time series data
            timestamps = []
            cpu_values = []
            memory_values = []
            anomaly_scores = []
            
            # Collect data points
            for entry in data.get("performance_data", []):
                timestamps.append(datetime.fromisoformat(entry["timestamp"]))
                cpu_values.append(entry["data"].get("cpu_usage", 0))
                memory_values.append(entry["data"].get("memory_usage", 0))
            
            for entry in data.get("anomaly_data", []):
                anomaly_scores.append(entry["data"].get("anomaly_score", 0))
            
            # Calculate correlations
            if len(cpu_values) > 1 and len(memory_values) > 1:
                correlations["cpu_memory"] = np.corrcoef(cpu_values, memory_values)[0, 1]
            
            if len(cpu_values) > 1 and len(anomaly_scores) > 1:
                correlations["cpu_anomaly"] = np.corrcoef(cpu_values, anomaly_scores)[0, 1]
            
            if len(memory_values) > 1 and len(anomaly_scores) > 1:
                correlations["memory_anomaly"] = np.corrcoef(memory_values, anomaly_scores)[0, 1]
            
            return correlations
            
        except Exception as e:
            self.logger.error(f"Correlation analysis failed: {e}")
            return {}
    
    def _calculate_trend(self, data: List[Dict[str, Any]], metric: str) -> str:
        """Calculate trend for a metric"""
        try:
            if len(data) < 3:
                return "insufficient_data"
            
            values = []
            for entry in data:
                value = entry.get("data", {}).get(metric, 0)
                if isinstance(value, str):
                    # Convert threat levels to numeric values
                    threat_map = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
                    value = threat_map.get(value, 0)
                values.append(value)
            
            if len(values) < 3:
                return "insufficient_data"
            
            # Calculate linear trend
            x = np.arange(len(values))
            y = np.array(values)
            slope = np.polyfit(x, y, 1)[0]
            
            if slope > 0.1:
                return "increasing"
            elif slope < -0.1:
                return "decreasing"
            else:
                return "stable"
                
        except Exception as e:
            self.logger.error(f"Trend calculation failed: {e}")
            return "unknown"
    
    def _generate_recommendations(self, analytics: Dict[str, Any], config: ReportConfig) -> List[Dict[str, Any]]:
        """Generate recommendations based on analytics"""
        try:
            recommendations = []
            
            # Performance recommendations
            if analytics.get("performance"):
                perf_analytics = analytics["performance"]
                perf_score = perf_analytics.get("performance_score", 1.0)
                
                if perf_score < 0.7:
                    recommendations.append({
                        "category": "performance",
                        "priority": "high",
                        "title": "System Performance Optimization",
                        "description": "System performance is below optimal levels",
                        "actions": [
                            "Optimize resource usage",
                            "Check for resource leaks",
                            "Consider hardware upgrades"
                        ]
                    })
            
            # Security recommendations
            if analytics.get("security"):
                sec_analytics = analytics["security"]
                sec_score = sec_analytics.get("security_score", 1.0)
                
                if sec_score < 0.8:
                    recommendations.append({
                        "category": "security",
                        "priority": "high",
                        "title": "Security Enhancement",
                        "description": "Security events detected, system hardening recommended",
                        "actions": [
                            "Review security policies",
                            "Update threat detection rules",
                            "Implement additional security measures"
                        ]
                    })
            
            # Rollback recommendations
            if analytics.get("rollback"):
                rollback_analytics = analytics["rollback"]
                efficiency_score = rollback_analytics.get("efficiency_score", 1.0)
                
                if efficiency_score < 0.8:
                    recommendations.append({
                        "category": "rollback",
                        "priority": "medium",
                        "title": "Rollback System Optimization",
                        "description": "Rollback system efficiency can be improved",
                        "actions": [
                            "Optimize rollback strategies",
                            "Improve error handling",
                            "Reduce rollback duration"
                        ]
                    })
            
            return recommendations
            
        except Exception as e:
            self.logger.error(f"Recommendation generation failed: {e}")
            return []
    
    def _generate_summary(self, analytics: Dict[str, Any]) -> Dict[str, Any]:
        """Generate report summary"""
        try:
            summary = {
                "overall_health": "healthy",
                "key_metrics": {},
                "alerts": [],
                "insights": []
            }
            
            # Overall health assessment
            health_scores = []
            
            if analytics.get("performance"):
                health_scores.append(analytics["performance"].get("performance_score", 1.0))
            
            if analytics.get("security"):
                health_scores.append(analytics["security"].get("security_score", 1.0))
            
            if analytics.get("rollback"):
                health_scores.append(analytics["rollback"].get("efficiency_score", 1.0))
            
            if health_scores:
                overall_score = statistics.mean(health_scores)
                if overall_score > 0.8:
                    summary["overall_health"] = "healthy"
                elif overall_score > 0.6:
                    summary["overall_health"] = "warning"
                else:
                    summary["overall_health"] = "critical"
            
            # Key metrics
            if analytics.get("performance"):
                summary["key_metrics"]["performance_score"] = analytics["performance"].get("performance_score", 0)
            
            if analytics.get("security"):
                summary["key_metrics"]["security_score"] = analytics["security"].get("security_score", 0)
            
            if analytics.get("rollback"):
                summary["key_metrics"]["rollback_efficiency"] = analytics["rollback"].get("efficiency_score", 0)
            
            return summary
            
        except Exception as e:
            self.logger.error(f"Summary generation failed: {e}")
            return {"overall_health": "unknown"}
    
    def _generate_charts(self, data: Dict[str, Any], analytics: Dict[str, Any], report_id: str) -> Dict[str, Any]:
        """Generate charts for the report"""
        try:
            charts = {}
            
            # Performance chart
            if data.get("performance_data"):
                charts["performance"] = self._create_performance_chart(data["performance_data"], report_id)
            
            # Anomaly chart
            if data.get("anomaly_data"):
                charts["anomaly"] = self._create_anomaly_chart(data["anomaly_data"], report_id)
            
            # Security chart
            if data.get("security_data"):
                charts["security"] = self._create_security_chart(data["security_data"], report_id)
            
            return charts
            
        except Exception as e:
            self.logger.error(f"Chart generation failed: {e}")
            return {}
    
    def _create_performance_chart(self, performance_data: List[Dict[str, Any]], report_id: str) -> str:
        """Create performance chart"""
        try:
            timestamps = []
            cpu_values = []
            memory_values = []
            
            for entry in performance_data:
                timestamps.append(datetime.fromisoformat(entry["timestamp"]))
                cpu_values.append(entry["data"].get("cpu_usage", 0))
                memory_values.append(entry["data"].get("memory_usage", 0))
            
            plt.figure(figsize=(12, 6))
            plt.plot(timestamps, cpu_values, label='CPU Usage', color='blue')
            plt.plot(timestamps, memory_values, label='Memory Usage', color='red')
            plt.xlabel('Time')
            plt.ylabel('Usage (%)')
            plt.title('System Performance Over Time')
            plt.legend()
            plt.xticks(rotation=45)
            plt.tight_layout()
            
            chart_path = os.path.join(self.charts_dir, f"performance_{report_id}.png")
            plt.savefig(chart_path, dpi=300, bbox_inches='tight')
            plt.close()
            
            return chart_path
            
        except Exception as e:
            self.logger.error(f"Performance chart creation failed: {e}")
            return ""
    
    def _create_anomaly_chart(self, anomaly_data: List[Dict[str, Any]], report_id: str) -> str:
        """Create anomaly chart"""
        try:
            timestamps = []
            anomaly_scores = []
            
            for entry in anomaly_data:
                timestamps.append(datetime.fromisoformat(entry["timestamp"]))
                anomaly_scores.append(entry["data"].get("anomaly_score", 0))
            
            plt.figure(figsize=(12, 6))
            plt.plot(timestamps, anomaly_scores, label='Anomaly Score', color='orange')
            plt.axhline(y=0.5, color='red', linestyle='--', label='Threshold')
            plt.xlabel('Time')
            plt.ylabel('Anomaly Score')
            plt.title('Anomaly Detection Over Time')
            plt.legend()
            plt.xticks(rotation=45)
            plt.tight_layout()
            
            chart_path = os.path.join(self.charts_dir, f"anomaly_{report_id}.png")
            plt.savefig(chart_path, dpi=300, bbox_inches='tight')
            plt.close()
            
            return chart_path
            
        except Exception as e:
            self.logger.error(f"Anomaly chart creation failed: {e}")
            return ""
    
    def _create_security_chart(self, security_data: List[Dict[str, Any]], report_id: str) -> str:
        """Create security chart"""
        try:
            threat_levels = defaultdict(int)
            
            for entry in security_data:
                threat_level = entry["data"].get("threat_level", "UNKNOWN")
                threat_levels[threat_level] += 1
            
            plt.figure(figsize=(10, 6))
            levels = list(threat_levels.keys())
            counts = list(threat_levels.values())
            
            plt.bar(levels, counts, color=['green', 'yellow', 'orange', 'red'])
            plt.xlabel('Threat Level')
            plt.ylabel('Count')
            plt.title('Security Events by Threat Level')
            plt.tight_layout()
            
            chart_path = os.path.join(self.charts_dir, f"security_{report_id}.png")
            plt.savefig(chart_path, dpi=300, bbox_inches='tight')
            plt.close()
            
            return chart_path
            
        except Exception as e:
            self.logger.error(f"Security chart creation failed: {e}")
            return ""
    
    def _parse_time_range(self, time_range: str) -> timedelta:
        """Parse time range string"""
        try:
            if time_range.endswith('h'):
                hours = int(time_range[:-1])
                return timedelta(hours=hours)
            elif time_range.endswith('d'):
                days = int(time_range[:-1])
                return timedelta(days=days)
            elif time_range.endswith('m'):
                minutes = int(time_range[:-1])
                return timedelta(minutes=minutes)
            else:
                return timedelta(hours=24)  # Default to 24 hours
                
        except Exception as e:
            self.logger.error(f"Time range parsing failed: {e}")
            return timedelta(hours=24)
    
    def _save_report(self, report: Dict[str, Any], config: ReportConfig):
        """Save report to file"""
        try:
            report_filename = f"report_{report['report_id']}.json"
            report_path = os.path.join(self.reports_dir, report_filename)
            
            with open(report_path, 'w') as f:
                json.dump(report, f, indent=2)
            
            self.logger.info(f"Report saved: {report_path}")
            
        except Exception as e:
            self.logger.error(f"Report saving failed: {e}")
    
    def _initialize_report_templates(self):
        """Initialize report templates"""
        try:
            self.report_templates = {
                ReportType.PERFORMANCE: {
                    "title": "Performance Report",
                    "sections": ["performance", "trends", "recommendations"]
                },
                ReportType.SECURITY: {
                    "title": "Security Report",
                    "sections": ["security", "anomaly", "recommendations"]
                },
                ReportType.ANOMALY_ANALYSIS: {
                    "title": "Anomaly Analysis Report",
                    "sections": ["anomaly", "correlations", "recommendations"]
                },
                ReportType.ROLLBACK_ANALYSIS: {
                    "title": "Rollback Analysis Report",
                    "sections": ["rollback", "performance", "recommendations"]
                },
                ReportType.COMPREHENSIVE: {
                    "title": "Comprehensive System Report",
                    "sections": ["performance", "security", "anomaly", "rollback", "network", "trends", "correlations", "recommendations"]
                }
            }
            
        except Exception as e:
            self.logger.error(f"Report template initialization failed: {e}")
    
    def _start_data_collection(self):
        """Start data collection"""
        try:
            def collect_data():
                while True:
                    try:
                        # Collect system metrics
                        system_metrics = self._collect_system_metrics()
                        self.add_performance_data(system_metrics)
                        
                        time.sleep(60)  # Collect every minute
                        
                    except Exception as e:
                        self.logger.error(f"Data collection error: {e}")
                        time.sleep(60)
            
            collection_thread = threading.Thread(target=collect_data, daemon=True)
            collection_thread.start()
            
        except Exception as e:
            self.logger.error(f"Failed to start data collection: {e}")
    
    def _collect_system_metrics(self) -> Dict[str, Any]:
        """Collect system metrics"""
        try:
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            
            # Memory usage
            memory = psutil.virtual_memory()
            
            # Disk usage
            disk = psutil.disk_usage('/')
            
            # Network I/O
            net_io = psutil.net_io_counters()
            
            return {
                "cpu_usage": cpu_percent,
                "memory_usage": memory.percent,
                "disk_usage": (disk.used / disk.total) * 100,
                "network_bandwidth": net_io.bytes_sent + net_io.bytes_recv,
                "process_count": len(psutil.pids())
            }
            
        except Exception as e:
            self.logger.error(f"System metrics collection failed: {e}")
            return {}
    
    def get_report_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get report history"""
        try:
            with self.report_lock:
                return list(self.report_history)[-limit:] if self.report_history else []
        except Exception as e:
            self.logger.error(f"Failed to get report history: {e}")
            return []
    
    def cleanup_old_reports(self, days: int = 30):
        """Cleanup old reports"""
        try:
            cutoff_time = datetime.now() - timedelta(days=days)
            
            # Cleanup report files
            for filename in os.listdir(self.reports_dir):
                if filename.startswith("report_") and filename.endswith(".json"):
                    file_path = os.path.join(self.reports_dir, filename)
                    file_time = datetime.fromtimestamp(os.path.getmtime(file_path))
                    
                    if file_time < cutoff_time:
                        os.remove(file_path)
            
            # Cleanup chart files
            for filename in os.listdir(self.charts_dir):
                if filename.endswith(".png"):
                    file_path = os.path.join(self.charts_dir, filename)
                    file_time = datetime.fromtimestamp(os.path.getmtime(file_path))
                    
                    if file_time < cutoff_time:
                        os.remove(file_path)
            
            self.logger.info(f"Cleaned up reports older than {days} days")
            
        except Exception as e:
            self.logger.error(f"Report cleanup failed: {e}")
