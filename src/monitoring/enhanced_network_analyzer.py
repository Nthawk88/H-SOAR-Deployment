"""
Enhanced Network Analysis System
Provides comprehensive network monitoring and analysis
"""

import psutil
import time
import json
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import logging
import socket
import subprocess
from collections import defaultdict, deque
import statistics

class EnhancedNetworkAnalyzer:
    """Enhanced network analysis with deep packet inspection simulation"""
    
    def __init__(self, config_manager):
        self.config_manager = config_manager
        self.logger = logging.getLogger(__name__)
        self.network_lock = threading.Lock()
        
        # Network data
        self.connection_history = deque(maxlen=1000)
        self.traffic_patterns = defaultdict(list)
        self.suspicious_connections = deque(maxlen=100)
        self.network_baseline = {}
        
        # Configuration
        self.analysis_interval = 5.0  # seconds
        self.traffic_threshold = 1000000  # bytes per second
        self.connection_threshold = 100  # connections per minute
        self.suspicious_ports = [22, 23, 135, 139, 445, 1433, 3389, 5900, 8080]
        self.malicious_ips = set()  # Would be populated from threat intelligence
        
        # Network monitoring
        self.last_net_io = None
        self.last_connections = set()
        
    def start_network_analysis(self) -> Dict[str, Any]:
        """Start comprehensive network analysis"""
        try:
            self.logger.info("Starting enhanced network analysis...")
            
            # Establish baseline
            self._establish_network_baseline()
            
            # Start analysis thread
            analysis_thread = threading.Thread(target=self._network_analysis_loop, daemon=True)
            analysis_thread.start()
            
            return {
                "success": True,
                "message": "Network analysis started",
                "analysis_interval": self.analysis_interval,
                "monitored_ports": self.suspicious_ports
            }
            
        except Exception as e:
            self.logger.error(f"Failed to start network analysis: {e}")
            return {"success": False, "error": str(e)}
    
    def _network_analysis_loop(self):
        """Main network analysis loop"""
        while True:
            try:
                start_time = time.time()
                
                # Collect network data
                network_data = self._collect_network_data()
                
                # Analyze network patterns
                analysis_result = self._analyze_network_patterns(network_data)
                
                # Detect anomalies
                anomalies = self._detect_network_anomalies(network_data, analysis_result)
                
                # Store results
                with self.network_lock:
                    self.connection_history.append({
                        "timestamp": datetime.now().isoformat(),
                        "network_data": network_data,
                        "analysis": analysis_result,
                        "anomalies": anomalies
                    })
                
                # Process anomalies
                if anomalies:
                    self._process_network_anomalies(anomalies)
                
                # Calculate sleep time
                elapsed = time.time() - start_time
                sleep_time = max(0, self.analysis_interval - elapsed)
                time.sleep(sleep_time)
                
            except Exception as e:
                self.logger.error(f"Network analysis loop error: {e}")
                time.sleep(self.analysis_interval)
    
    def _collect_network_data(self) -> Dict[str, Any]:
        """Collect comprehensive network data"""
        try:
            # Network I/O statistics
            net_io = psutil.net_io_counters()
            
            # Network connections
            connections = psutil.net_connections()
            
            # Network interfaces
            interfaces = psutil.net_if_addrs()
            interface_stats = psutil.net_if_stats()
            
            # Calculate traffic rates
            traffic_rates = self._calculate_traffic_rates(net_io)
            
            # Analyze connections
            connection_analysis = self._analyze_connections(connections)
            
            # Interface analysis
            interface_analysis = self._analyze_interfaces(interfaces, interface_stats)
            
            return {
                "timestamp": datetime.now().isoformat(),
                "net_io": {
                    "bytes_sent": net_io.bytes_sent,
                    "bytes_recv": net_io.bytes_recv,
                    "packets_sent": net_io.packets_sent,
                    "packets_recv": net_io.packets_recv,
                    "errin": net_io.errin,
                    "errout": net_io.errout,
                    "dropin": net_io.dropin,
                    "dropout": net_io.dropout
                },
                "traffic_rates": traffic_rates,
                "connections": connection_analysis,
                "interfaces": interface_analysis,
                "total_connections": len(connections)
            }
            
        except Exception as e:
            self.logger.error(f"Failed to collect network data: {e}")
            return {}
    
    def _calculate_traffic_rates(self, net_io) -> Dict[str, Any]:
        """Calculate network traffic rates"""
        try:
            current_time = time.time()
            
            if self.last_net_io is None:
                self.last_net_io = {
                    "net_io": net_io,
                    "timestamp": current_time
                }
                return {
                    "bytes_sent_per_sec": 0,
                    "bytes_recv_per_sec": 0,
                    "packets_sent_per_sec": 0,
                    "packets_recv_per_sec": 0
                }
            
            # Calculate rates
            time_diff = current_time - self.last_net_io["timestamp"]
            if time_diff == 0:
                time_diff = 1
            
            bytes_sent_rate = (net_io.bytes_sent - self.last_net_io["net_io"].bytes_sent) / time_diff
            bytes_recv_rate = (net_io.bytes_recv - self.last_net_io["net_io"].bytes_recv) / time_diff
            packets_sent_rate = (net_io.packets_sent - self.last_net_io["net_io"].packets_sent) / time_diff
            packets_recv_rate = (net_io.packets_recv - self.last_net_io["net_io"].packets_recv) / time_diff
            
            # Update last values
            self.last_net_io = {
                "net_io": net_io,
                "timestamp": current_time
            }
            
            return {
                "bytes_sent_per_sec": bytes_sent_rate,
                "bytes_recv_per_sec": bytes_recv_rate,
                "packets_sent_per_sec": packets_sent_rate,
                "packets_recv_per_sec": packets_recv_rate,
                "total_bandwidth_per_sec": bytes_sent_rate + bytes_recv_rate
            }
            
        except Exception as e:
            self.logger.error(f"Failed to calculate traffic rates: {e}")
            return {}
    
    def _analyze_connections(self, connections) -> Dict[str, Any]:
        """Analyze network connections"""
        try:
            # Group connections by status
            status_counts = defaultdict(int)
            port_counts = defaultdict(int)
            remote_addresses = defaultdict(int)
            local_addresses = defaultdict(int)
            
            suspicious_connections = []
            established_connections = []
            
            for conn in connections:
                # Count by status
                status_counts[conn.status] += 1
                
                # Count by port
                if conn.laddr:
                    port_counts[conn.laddr.port] += 1
                
                # Count remote addresses
                if conn.raddr:
                    remote_addresses[conn.raddr.ip] += 1
                
                # Count local addresses
                if conn.laddr:
                    local_addresses[conn.laddr.ip] += 1
                
                # Check for suspicious connections
                if self._is_suspicious_connection(conn):
                    suspicious_connections.append({
                        "fd": conn.fd,
                        "family": conn.family,
                        "type": conn.type,
                        "laddr": conn.laddr,
                        "raddr": conn.raddr,
                        "status": conn.status,
                        "pid": conn.pid,
                        "reason": self._get_suspicious_reason(conn)
                    })
                
                # Collect established connections
                if conn.status == "ESTABLISHED":
                    established_connections.append({
                        "fd": conn.fd,
                        "laddr": conn.laddr,
                        "raddr": conn.raddr,
                        "pid": conn.pid
                    })
            
            return {
                "status_distribution": dict(status_counts),
                "port_distribution": dict(port_counts),
                "remote_addresses": dict(remote_addresses),
                "local_addresses": dict(local_addresses),
                "suspicious_connections": suspicious_connections,
                "established_connections": established_connections,
                "total_suspicious": len(suspicious_connections)
            }
            
        except Exception as e:
            self.logger.error(f"Failed to analyze connections: {e}")
            return {}
    
    def _analyze_interfaces(self, interfaces, interface_stats) -> Dict[str, Any]:
        """Analyze network interfaces"""
        try:
            interface_analysis = {}
            
            for interface, addrs in interfaces.items():
                if interface in interface_stats:
                    stats = interface_stats[interface]
                    
                    interface_analysis[interface] = {
                        "is_up": stats.isup,
                        "duplex": stats.duplex,
                        "speed": stats.speed,
                        "mtu": stats.mtu,
                        "addresses": [
                            {
                                "family": addr.family.name,
                                "address": addr.address,
                                "netmask": addr.netmask,
                                "broadcast": addr.broadcast
                            } for addr in addrs
                        ]
                    }
            
            return interface_analysis
            
        except Exception as e:
            self.logger.error(f"Failed to analyze interfaces: {e}")
            return {}
    
    def _is_suspicious_connection(self, conn) -> bool:
        """Check if connection is suspicious"""
        try:
            # Check for suspicious ports
            if conn.laddr and conn.laddr.port in self.suspicious_ports:
                return True
            
            # Check for malicious IPs
            if conn.raddr and conn.raddr.ip in self.malicious_ips:
                return True
            
            # Check for unusual connection patterns
            if conn.status in ["SYN_SENT", "SYN_RECV"] and conn.raddr:
                # Check for port scanning patterns
                if self._is_port_scanning_pattern(conn):
                    return True
            
            # Check for high connection count from single IP
            if conn.raddr:
                recent_connections = [
                    c for c in self.connection_history
                    if c.get("network_data", {}).get("connections", {}).get("remote_addresses", {}).get(conn.raddr.ip, 0) > 10
                ]
                if len(recent_connections) > 5:
                    return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Failed to check suspicious connection: {e}")
            return False
    
    def _get_suspicious_reason(self, conn) -> str:
        """Get reason why connection is suspicious"""
        try:
            reasons = []
            
            if conn.laddr and conn.laddr.port in self.suspicious_ports:
                reasons.append(f"Suspicious port: {conn.laddr.port}")
            
            if conn.raddr and conn.raddr.ip in self.malicious_ips:
                reasons.append(f"Malicious IP: {conn.raddr.ip}")
            
            if conn.status in ["SYN_SENT", "SYN_RECV"]:
                reasons.append("Unusual connection state")
            
            return "; ".join(reasons) if reasons else "Unknown"
            
        except Exception as e:
            self.logger.error(f"Failed to get suspicious reason: {e}")
            return "Error"
    
    def _is_port_scanning_pattern(self, conn) -> bool:
        """Detect port scanning patterns"""
        try:
            # This is a simplified port scanning detection
            # In reality, this would require more sophisticated analysis
            
            if not conn.raddr:
                return False
            
            # Check for multiple connection attempts from same IP
            recent_connections = list(self.connection_history)[-10:]  # Last 10 analysis cycles
            
            same_ip_connections = 0
            for analysis in recent_connections:
                connections_data = analysis.get("network_data", {}).get("connections", {})
                remote_addresses = connections_data.get("remote_addresses", {})
                same_ip_connections += remote_addresses.get(conn.raddr.ip, 0)
            
            # If more than 5 connections from same IP in recent history
            return same_ip_connections > 5
            
        except Exception as e:
            self.logger.error(f"Failed to detect port scanning: {e}")
            return False
    
    def _analyze_network_patterns(self, network_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze network patterns"""
        try:
            analysis = {
                "timestamp": datetime.now().isoformat(),
                "traffic_analysis": {},
                "connection_analysis": {},
                "anomaly_indicators": []
            }
            
            # Analyze traffic patterns
            traffic_rates = network_data.get("traffic_rates", {})
            if traffic_rates:
                total_bandwidth = traffic_rates.get("total_bandwidth_per_sec", 0)
                
                analysis["traffic_analysis"] = {
                    "total_bandwidth": total_bandwidth,
                    "bandwidth_level": self._classify_bandwidth_level(total_bandwidth),
                    "traffic_trend": self._analyze_traffic_trend(total_bandwidth)
                }
                
                # Check for bandwidth anomalies
                if total_bandwidth > self.traffic_threshold:
                    analysis["anomaly_indicators"].append({
                        "type": "high_bandwidth",
                        "value": total_bandwidth,
                        "threshold": self.traffic_threshold
                    })
            
            # Analyze connection patterns
            connections = network_data.get("connections", {})
            if connections:
                total_connections = network_data.get("total_connections", 0)
                suspicious_count = connections.get("total_suspicious", 0)
                
                analysis["connection_analysis"] = {
                    "total_connections": total_connections,
                    "suspicious_connections": suspicious_count,
                    "connection_level": self._classify_connection_level(total_connections),
                    "suspicious_ratio": suspicious_count / max(total_connections, 1)
                }
                
                # Check for connection anomalies
                if total_connections > self.connection_threshold:
                    analysis["anomaly_indicators"].append({
                        "type": "high_connections",
                        "value": total_connections,
                        "threshold": self.connection_threshold
                    })
                
                if suspicious_count > 5:
                    analysis["anomaly_indicators"].append({
                        "type": "high_suspicious_connections",
                        "value": suspicious_count,
                        "threshold": 5
                    })
            
            return analysis
            
        except Exception as e:
            self.logger.error(f"Failed to analyze network patterns: {e}")
            return {}
    
    def _detect_network_anomalies(self, network_data: Dict[str, Any], analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect network anomalies"""
        try:
            anomalies = []
            
            # Check anomaly indicators
            for indicator in analysis.get("anomaly_indicators", []):
                anomaly = {
                    "type": indicator["type"],
                    "severity": self._determine_anomaly_severity(indicator),
                    "value": indicator["value"],
                    "threshold": indicator["threshold"],
                    "timestamp": datetime.now().isoformat(),
                    "network_data": network_data
                }
                anomalies.append(anomaly)
            
            # Check for DDoS patterns
            ddos_anomaly = self._detect_ddos_patterns(network_data)
            if ddos_anomaly:
                anomalies.append(ddos_anomaly)
            
            # Check for port scanning
            port_scan_anomaly = self._detect_port_scanning(network_data)
            if port_scan_anomaly:
                anomalies.append(port_scan_anomaly)
            
            return anomalies
            
        except Exception as e:
            self.logger.error(f"Failed to detect network anomalies: {e}")
            return []
    
    def _detect_ddos_patterns(self, network_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Detect DDoS attack patterns"""
        try:
            connections = network_data.get("connections", {})
            remote_addresses = connections.get("remote_addresses", {})
            
            # Check for high number of connections from single IP
            for ip, count in remote_addresses.items():
                if count > 50:  # Threshold for DDoS detection
                    return {
                        "type": "ddos_pattern",
                        "severity": "HIGH",
                        "source_ip": ip,
                        "connection_count": count,
                        "timestamp": datetime.now().isoformat(),
                        "description": f"High connection count from {ip}: {count} connections"
                    }
            
            return None
            
        except Exception as e:
            self.logger.error(f"Failed to detect DDoS patterns: {e}")
            return None
    
    def _detect_port_scanning(self, network_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Detect port scanning patterns"""
        try:
            connections = network_data.get("connections", {})
            suspicious_connections = connections.get("suspicious_connections", [])
            
            # Group suspicious connections by source IP
            ip_port_counts = defaultdict(set)
            for conn in suspicious_connections:
                if conn.get("raddr"):
                    ip_port_counts[conn["raddr"].ip].add(conn["laddr"].port)
            
            # Check for port scanning patterns
            for ip, ports in ip_port_counts.items():
                if len(ports) > 10:  # Threshold for port scanning
                    return {
                        "type": "port_scanning",
                        "severity": "MEDIUM",
                        "source_ip": ip,
                        "ports_scanned": len(ports),
                        "ports": list(ports),
                        "timestamp": datetime.now().isoformat(),
                        "description": f"Port scanning detected from {ip}: {len(ports)} ports"
                    }
            
            return None
            
        except Exception as e:
            self.logger.error(f"Failed to detect port scanning: {e}")
            return None
    
    def _classify_bandwidth_level(self, bandwidth: float) -> str:
        """Classify bandwidth usage level"""
        if bandwidth > 100000000:  # 100 MB/s
            return "VERY_HIGH"
        elif bandwidth > 10000000:  # 10 MB/s
            return "HIGH"
        elif bandwidth > 1000000:  # 1 MB/s
            return "MEDIUM"
        else:
            return "LOW"
    
    def _classify_connection_level(self, connections: int) -> str:
        """Classify connection count level"""
        if connections > 1000:
            return "VERY_HIGH"
        elif connections > 500:
            return "HIGH"
        elif connections > 100:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _analyze_traffic_trend(self, bandwidth: float) -> str:
        """Analyze traffic trend"""
        try:
            # Get recent bandwidth values
            recent_data = list(self.connection_history)[-5:]  # Last 5 samples
            bandwidth_values = [
                data.get("network_data", {}).get("traffic_rates", {}).get("total_bandwidth_per_sec", 0)
                for data in recent_data
            ]
            
            if len(bandwidth_values) < 2:
                return "UNKNOWN"
            
            # Calculate trend
            if bandwidth > bandwidth_values[-1] * 1.2:
                return "INCREASING"
            elif bandwidth < bandwidth_values[-1] * 0.8:
                return "DECREASING"
            else:
                return "STABLE"
                
        except Exception as e:
            self.logger.error(f"Failed to analyze traffic trend: {e}")
            return "UNKNOWN"
    
    def _determine_anomaly_severity(self, indicator: Dict[str, Any]) -> str:
        """Determine anomaly severity"""
        value = indicator["value"]
        threshold = indicator["threshold"]
        
        if value > threshold * 2:
            return "CRITICAL"
        elif value > threshold * 1.5:
            return "HIGH"
        elif value > threshold:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _process_network_anomalies(self, anomalies: List[Dict[str, Any]]):
        """Process network anomalies"""
        try:
            for anomaly in anomalies:
                self.logger.warning(f"NETWORK ANOMALY: {anomaly['type']} - {anomaly['severity']}")
                
                # Log anomaly
                self._log_network_anomaly(anomaly)
                
                # Store suspicious connections
                if anomaly["severity"] in ["HIGH", "CRITICAL"]:
                    self.suspicious_connections.append(anomaly)
                
                # Trigger response if needed
                if anomaly["severity"] == "CRITICAL":
                    self._trigger_network_response(anomaly)
                    
        except Exception as e:
            self.logger.error(f"Failed to process network anomalies: {e}")
    
    def _trigger_network_response(self, anomaly: Dict[str, Any]):
        """Trigger response for critical network anomalies"""
        try:
            self.logger.critical(f"Triggering network response for {anomaly['type']}")
            
            # This would integrate with the main system's response mechanisms
            # For now, just log the anomaly
            
        except Exception as e:
            self.logger.error(f"Failed to trigger network response: {e}")
    
    def _log_network_anomaly(self, anomaly: Dict[str, Any]):
        """Log network anomaly to file"""
        try:
            anomaly_file = "logs/network_anomalies.jsonl"
            with open(anomaly_file, 'a') as f:
                f.write(json.dumps(anomaly) + '\n')
        except Exception as e:
            self.logger.error(f"Failed to log network anomaly: {e}")
    
    def _establish_network_baseline(self):
        """Establish network baseline"""
        try:
            # Collect network data for baseline
            baseline_data = []
            for _ in range(10):  # Collect 10 samples
                network_data = self._collect_network_data()
                if network_data:
                    baseline_data.append(network_data)
                time.sleep(1)
            
            if baseline_data:
                # Calculate baseline averages
                self.network_baseline = self._calculate_network_baseline(baseline_data)
                self.logger.info("Network baseline established")
            
        except Exception as e:
            self.logger.error(f"Failed to establish network baseline: {e}")
    
    def _calculate_network_baseline(self, network_data_list: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate network baseline from data"""
        try:
            baseline = {}
            
            # Bandwidth baseline
            bandwidth_values = [
                data.get("traffic_rates", {}).get("total_bandwidth_per_sec", 0)
                for data in network_data_list
            ]
            baseline["avg_bandwidth"] = statistics.mean(bandwidth_values) if bandwidth_values else 0
            
            # Connection count baseline
            connection_counts = [
                data.get("total_connections", 0)
                for data in network_data_list
            ]
            baseline["avg_connections"] = statistics.mean(connection_counts) if connection_counts else 0
            
            return baseline
            
        except Exception as e:
            self.logger.error(f"Failed to calculate network baseline: {e}")
            return {}
    
    def get_network_status(self) -> Dict[str, Any]:
        """Get network analysis status"""
        try:
            with self.network_lock:
                recent_data = list(self.connection_history)[-10:] if self.connection_history else []
                recent_anomalies = list(self.suspicious_connections)[-10:] if self.suspicious_connections else []
                
                return {
                    "analysis_active": True,
                    "data_collected": len(self.connection_history),
                    "anomalies_detected": len(self.suspicious_connections),
                    "baseline_established": bool(self.network_baseline),
                    "network_baseline": self.network_baseline,
                    "recent_anomalies": recent_anomalies,
                    "last_analysis": recent_data[-1] if recent_data else None
                }
                
        except Exception as e:
            self.logger.error(f"Failed to get network status: {e}")
            return {"analysis_active": False, "error": str(e)}
    
    def get_network_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get network analysis history"""
        try:
            with self.network_lock:
                return list(self.connection_history)[-limit:] if self.connection_history else []
        except Exception as e:
            self.logger.error(f"Failed to get network history: {e}")
            return []
    
    def stop_analysis(self):
        """Stop network analysis"""
        try:
            self.logger.info("Stopping network analysis...")
            # Analysis will stop when the thread exits
        except Exception as e:
            self.logger.error(f"Failed to stop network analysis: {e}")
