"""
Sistem Containment dan Isolasi untuk IDS/IPS Auto-Healing
"""

import subprocess
import psutil
import time
import json
from datetime import datetime
from typing import Dict, List, Any, Optional
import logging

class ContainmentSystem:
    """Kelas untuk containment dan isolasi ancaman"""
    
    def __init__(self, config_path: str = "config/containment_config.json"):
        self.config = self._load_config(config_path)
        self.logger = self._setup_logger()
        self.isolation_rules = []
        self.blocked_ips = set()
        self.killed_processes = []
        
    def _load_config(self, config_path: str) -> Dict:
        """Load konfigurasi containment"""
        default_config = {
            "isolation_enabled": True,
            "network_isolation": True,
            "process_killing": True,
            "file_quarantine": True,
            "backup_restore": True,
            "iptables_rules": {
                "block_all_outbound": "iptables -A OUTPUT -j DROP",
                "block_specific_ip": "iptables -A OUTPUT -d {ip} -j DROP",
                "allow_local": "iptables -A OUTPUT -d 127.0.0.1 -j ACCEPT",
                "allow_dns": "iptables -A OUTPUT -p udp --dport 53 -j ACCEPT"
            },
            "critical_processes": [
                "systemd", "kernel", "init", "sshd", "networkd"
            ],
            "quarantine_path": "/tmp/quarantine"
        }
        
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
                return {**default_config, **config}
        except FileNotFoundError:
            return default_config
    
    def _setup_logger(self) -> logging.Logger:
        """Setup logger untuk containment system"""
        logger = logging.getLogger('ContainmentSystem')
        logger.setLevel(logging.INFO)
        
        handler = logging.FileHandler('logs/containment.log')
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
        return logger
    
    def execute_containment(self, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Eksekusi containment berdasarkan data ancaman"""
        try:
            self.logger.info("Memulai proses containment...")
            
            containment_actions = []
            start_time = time.time()
            
            # 1. Isolasi jaringan
            if self.config['network_isolation']:
                network_result = self._isolate_network(threat_data)
                containment_actions.append(network_result)
            
            # 2. Kill proses mencurigakan
            if self.config['process_killing']:
                process_result = self._kill_suspicious_processes(threat_data)
                containment_actions.append(process_result)
            
            # 3. Quarantine file mencurigakan
            if self.config['file_quarantine']:
                quarantine_result = self._quarantine_files(threat_data)
                containment_actions.append(quarantine_result)
            
            # 4. Backup dan restore
            if self.config['backup_restore']:
                backup_result = self._backup_and_restore(threat_data)
                containment_actions.append(backup_result)
            
            end_time = time.time()
            response_time = end_time - start_time
            
            result = {
                "containment_successful": True,
                "response_time_seconds": response_time,
                "actions_taken": containment_actions,
                "timestamp": datetime.now().isoformat(),
                "threat_level": threat_data.get('threat_level', 'UNKNOWN')
            }
            
            self.logger.info(f"Containment selesai dalam {response_time:.2f} detik")
            return result
            
        except Exception as e:
            self.logger.error(f"Error executing containment: {e}")
            return {
                "containment_successful": False,
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
    
    def _isolate_network(self, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Isolasi jaringan menggunakan iptables"""
        try:
            actions = []
            
            # Block all outbound traffic
            if self._execute_iptables_command(
                self.config['iptables_rules']['block_all_outbound']
            ):
                actions.append("Blocked all outbound traffic")
                self.logger.info("All outbound traffic blocked")
            
            # Allow local traffic
            if self._execute_iptables_command(
                self.config['iptables_rules']['allow_local']
            ):
                actions.append("Allowed local traffic")
            
            # Allow DNS
            if self._execute_iptables_command(
                self.config['iptables_rules']['allow_dns']
            ):
                actions.append("Allowed DNS traffic")
            
            # Block specific foreign IPs
            foreign_ips = threat_data.get('network_metrics', {}).get('foreign_ips', [])
            for ip in foreign_ips[:10]:  # Limit to 10 IPs
                if self._execute_iptables_command(
                    self.config['iptables_rules']['block_specific_ip'].format(ip=ip)
                ):
                    actions.append(f"Blocked foreign IP: {ip}")
                    self.blocked_ips.add(ip)
            
            return {
                "action": "network_isolation",
                "success": True,
                "details": actions,
                "blocked_ips": list(self.blocked_ips)
            }
            
        except Exception as e:
            self.logger.error(f"Error isolating network: {e}")
            return {
                "action": "network_isolation",
                "success": False,
                "error": str(e)
            }
    
    def _kill_suspicious_processes(self, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Kill proses mencurigakan"""
        try:
            killed_processes = []
            host_metrics = threat_data.get('host_metrics', {})
            processes = host_metrics.get('processes', [])
            
            for process in processes:
                if process.get('is_suspicious', False):
                    pid = process.get('pid')
                    name = process.get('name', 'unknown')
                    
                    # Skip critical system processes
                    if name.lower() in [p.lower() for p in self.config['critical_processes']]:
                        self.logger.warning(f"Skipping critical process: {name} (PID: {pid})")
                        continue
                    
                    try:
                        # Try graceful termination first
                        proc = psutil.Process(pid)
                        proc.terminate()
                        
                        # Wait for process to terminate
                        try:
                            proc.wait(timeout=5)
                            killed_processes.append({
                                "pid": pid,
                                "name": name,
                                "method": "terminate"
                            })
                            self.killed_processes.append(pid)
                            self.logger.info(f"Terminated process: {name} (PID: {pid})")
                        except psutil.TimeoutExpired:
                            # Force kill if graceful termination fails
                            proc.kill()
                            killed_processes.append({
                                "pid": pid,
                                "name": name,
                                "method": "kill"
                            })
                            self.killed_processes.append(pid)
                            self.logger.info(f"Force killed process: {name} (PID: {pid})")
                            
                    except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                        self.logger.warning(f"Cannot kill process {name} (PID: {pid}): {e}")
                        continue
            
            return {
                "action": "process_killing",
                "success": True,
                "killed_processes": killed_processes,
                "total_killed": len(killed_processes)
            }
            
        except Exception as e:
            self.logger.error(f"Error killing processes: {e}")
            return {
                "action": "process_killing",
                "success": False,
                "error": str(e)
            }
    
    def _quarantine_files(self, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Quarantine file mencurigakan"""
        try:
            import os
            import shutil
            
            quarantined_files = []
            host_metrics = threat_data.get('host_metrics', {})
            critical_files = host_metrics.get('critical_files', {})
            
            # Create quarantine directory
            quarantine_dir = self.config['quarantine_path']
            os.makedirs(quarantine_dir, exist_ok=True)
            
            for file_path, file_info in critical_files.items():
                if file_info.get('exists') and file_info.get('modified'):
                    # Check if file was modified recently (within last hour)
                    modified_time = datetime.fromisoformat(file_info['modified'])
                    if (datetime.now() - modified_time).seconds < 3600:
                        try:
                            # Create backup
                            backup_path = os.path.join(
                                quarantine_dir, 
                                f"{os.path.basename(file_path)}_{int(time.time())}"
                            )
                            shutil.copy2(file_path, backup_path)
                            
                            quarantined_files.append({
                                "original_path": file_path,
                                "backup_path": backup_path,
                                "modified_time": file_info['modified']
                            })
                            
                            self.logger.info(f"Quarantined file: {file_path}")
                            
                        except Exception as e:
                            self.logger.error(f"Error quarantining {file_path}: {e}")
            
            return {
                "action": "file_quarantine",
                "success": True,
                "quarantined_files": quarantined_files,
                "quarantine_directory": quarantine_dir
            }
            
        except Exception as e:
            self.logger.error(f"Error quarantining files: {e}")
            return {
                "action": "file_quarantine",
                "success": False,
                "error": str(e)
            }
    
    def _backup_and_restore(self, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Backup dan restore konfigurasi"""
        try:
            # This would typically involve Ansible playbooks
            # For now, we'll create a simple backup mechanism
            
            backup_info = {
                "timestamp": datetime.now().isoformat(),
                "threat_level": threat_data.get('threat_level', 'UNKNOWN'),
                "backup_files": []
            }
            
            # Create backup of critical files
            critical_files = [
                "/etc/passwd", "/etc/shadow", "/etc/hosts",
                "/etc/firewall/rules", "/etc/ssh/sshd_config"
            ]
            
            backup_dir = f"backups/{int(time.time())}"
            os.makedirs(backup_dir, exist_ok=True)
            
            for file_path in critical_files:
                if os.path.exists(file_path):
                    try:
                        backup_file = os.path.join(backup_dir, os.path.basename(file_path))
                        shutil.copy2(file_path, backup_file)
                        backup_info["backup_files"].append(backup_file)
                    except Exception as e:
                        self.logger.warning(f"Could not backup {file_path}: {e}")
            
            return {
                "action": "backup_restore",
                "success": True,
                "backup_directory": backup_dir,
                "backup_info": backup_info
            }
            
        except Exception as e:
            self.logger.error(f"Error in backup and restore: {e}")
            return {
                "action": "backup_restore",
                "success": False,
                "error": str(e)
            }
    
    def _execute_iptables_command(self, command: str) -> bool:
        """Execute iptables command"""
        try:
            result = subprocess.run(
                command.split(), 
                capture_output=True, 
                text=True, 
                timeout=10
            )
            return result.returncode == 0
        except Exception as e:
            self.logger.error(f"Error executing iptables command '{command}': {e}")
            return False
    
    def restore_network(self) -> bool:
        """Restore network connectivity"""
        try:
            # Flush iptables rules
            subprocess.run(["iptables", "-F"], check=True)
            subprocess.run(["iptables", "-X"], check=True)
            
            # Restore default policies
            subprocess.run(["iptables", "-P", "INPUT", "ACCEPT"], check=True)
            subprocess.run(["iptables", "-P", "FORWARD", "ACCEPT"], check=True)
            subprocess.run(["iptables", "-P", "OUTPUT", "ACCEPT"], check=True)
            
            self.logger.info("Network connectivity restored")
            return True
            
        except Exception as e:
            self.logger.error(f"Error restoring network: {e}")
            return False
    
    def get_containment_status(self) -> Dict[str, Any]:
        """Dapatkan status containment saat ini"""
        return {
            "isolation_enabled": self.config.get('isolation_enabled', True),
            "isolation_active": len(self.isolation_rules) > 0,
            "blocked_ips": list(self.blocked_ips),
            "killed_processes": self.killed_processes,
            "quarantine_directory": self.config['quarantine_path'],
            "timestamp": datetime.now().isoformat()
        }
