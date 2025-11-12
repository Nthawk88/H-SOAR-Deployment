"""
Modul untuk monitoring host victim dan pengumpulan data
untuk deteksi anomali berbasis ML
"""

import psutil
import os
import time
import json
import subprocess
from datetime import datetime
from typing import Dict, List, Any
import logging

class HostMonitor:
    """Kelas untuk monitoring metrik host dan sistem"""
    
    def __init__(self, config_path: str = "config/host_config.json"):
        self.config = self._load_config(config_path)
        self.logger = self._setup_logger()
        # Global main config for toggles
        try:
            with open('config/main_config.json', 'r') as _f:
                self.main_config = json.load(_f)
        except Exception:
            self.main_config = {}
        
    def _load_config(self, config_path: str) -> Dict:
        """Load konfigurasi monitoring host"""
        default_config = {
            "monitoring_interval": 5,  # detik
            "cpu_threshold": 90.0,     # persen
            "memory_threshold": 90.0,  # persen
            "critical_files": [
                "/etc/passwd",
                "/etc/shadow", 
                "/etc/hosts",
                "/etc/firewall/rules"
            ],
            "suspicious_processes": [
                "nc", "netcat", "ncat",
                "wget", "curl", "powershell"
            ]
        }
        
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
                return {**default_config, **config}
        except FileNotFoundError:
            return default_config
    
    def _setup_logger(self) -> logging.Logger:
        """Setup logger untuk monitoring"""
        logger = logging.getLogger('HostMonitor')
        logger.setLevel(logging.INFO)
        
        handler = logging.FileHandler('logs/host_monitor.log')
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
        return logger
    
    def get_system_metrics(self) -> Dict[str, Any]:
        """Kumpulkan metrik sistem dasar"""
        try:
            # CPU usage - ambil 2 kali untuk mendapatkan nilai yang akurat
            cpu_percent = psutil.cpu_percent(interval=None)  # Non-blocking call
            time.sleep(1)  # Tunggu 1 detik
            cpu_percent = psutil.cpu_percent(interval=None)  # Ambil lagi untuk nilai akurat
            cpu_count = psutil.cpu_count()
            
            # Memory usage
            memory = psutil.virtual_memory()
            memory_percent = memory.percent
            memory_available = memory.available
            
            # Disk usage
            disk = psutil.disk_usage('/')
            disk_percent = disk.percent
            
            # Network stats
            network = psutil.net_io_counters()
            
            return {
                "timestamp": datetime.now().isoformat(),
                "cpu": {
                    "percent": cpu_percent,
                    "count": cpu_count
                },
                "memory": {
                    "percent": memory_percent,
                    "available_mb": memory_available / (1024 * 1024)
                },
                "disk": {
                    "percent": disk_percent
                },
                "network": {
                    "bytes_sent": network.bytes_sent,
                    "bytes_recv": network.bytes_recv,
                    "packets_sent": network.packets_sent,
                    "packets_recv": network.packets_recv
                }
            }
        except Exception as e:
            self.logger.error(f"Error collecting system metrics: {e}")
            return {}
    
    def get_process_metrics(self) -> List[Dict[str, Any]]:
        """Kumpulkan metrik proses yang berjalan"""
        processes = []
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 
                                           'memory_percent', 'cmdline']):
                try:
                    proc_info = proc.info
                    
                    # Cek apakah proses mencurigakan
                    is_suspicious = any(
                        suspicious in proc_info['name'].lower() 
                        for suspicious in self.config['suspicious_processes']
                    )
                    
                    processes.append({
                        "pid": proc_info['pid'],
                        "name": proc_info['name'],
                        "cpu_percent": proc_info['cpu_percent'],
                        "memory_percent": proc_info['memory_percent'],
                        "cmdline": ' '.join(proc_info['cmdline']) if proc_info['cmdline'] else '',
                        "is_suspicious": is_suspicious,
                        "timestamp": datetime.now().isoformat()
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
        except Exception as e:
            self.logger.error(f"Error collecting process metrics: {e}")
            
        return processes
    
    def check_critical_files(self) -> Dict[str, Any]:
        """Cek modifikasi file kritis"""
        file_status = {}
        
        for file_path in self.config['critical_files']:
            try:
                if os.path.exists(file_path):
                    stat = os.stat(file_path)
                    file_status[file_path] = {
                        "exists": True,
                        "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                        "size": stat.st_size,
                        "permissions": oct(stat.st_mode)[-3:]
                    }
                else:
                    file_status[file_path] = {
                        "exists": False,
                        "modified": None,
                        "size": 0,
                        "permissions": None
                    }
            except Exception as e:
                self.logger.error(f"Error checking file {file_path}: {e}")
                file_status[file_path] = {"error": str(e)}
                
        return file_status
    
    def get_network_connections(self) -> List[Dict[str, Any]]:
        """Kumpulkan informasi koneksi jaringan"""
        connections = []
        
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED':
                    connections.append({
                        "local_addr": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                        "remote_addr": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                        "status": conn.status,
                        "pid": conn.pid,
                        "timestamp": datetime.now().isoformat()
                    })
        except Exception as e:
            self.logger.error(f"Error collecting network connections: {e}")
            
        return connections
    
    def collect_all_metrics(self) -> Dict[str, Any]:
        """Kumpulkan semua metrik host"""
        return {
            "system": self.get_system_metrics(),
            "processes": self.get_process_metrics(),
            "critical_files": self.check_critical_files(),
            "network_connections": self.get_network_connections()
        }
    
    def detect_danger_signals(self, metrics: Dict[str, Any]) -> List[str]:
        """Deteksi sinyal bahaya berdasarkan metrik"""
        danger_signals = []
        
        perf_alerts = self.main_config.get('performance_alerts_enabled', True)
        # Cek CPU usage tinggi
        if perf_alerts and metrics.get('system', {}).get('cpu', {}).get('percent', 0) > self.config['cpu_threshold']:
            danger_signals.append(f"High CPU usage: {metrics['system']['cpu']['percent']}%")
        
        # Cek memory usage tinggi
        if perf_alerts and metrics.get('system', {}).get('memory', {}).get('percent', 0) > self.config['memory_threshold']:
            danger_signals.append(f"High memory usage: {metrics['system']['memory']['percent']}%")
        
        # Cek proses mencurigakan
        suspicious_procs = [
            proc for proc in metrics.get('processes', [])
            if proc.get('is_suspicious', False)
        ]
        if suspicious_procs:
            danger_signals.append(f"Suspicious processes detected: {len(suspicious_procs)}")
        
        # Cek modifikasi file kritis
        for file_path, status in metrics.get('critical_files', {}).items():
            if status.get('exists') and status.get('modified'):
                # Cek apakah file dimodifikasi dalam 5 menit terakhir
                modified_time = datetime.fromisoformat(status['modified'])
                if (datetime.now() - modified_time).seconds < 300:  # 5 menit
                    danger_signals.append(f"Critical file modified: {file_path}")
        
        return danger_signals
