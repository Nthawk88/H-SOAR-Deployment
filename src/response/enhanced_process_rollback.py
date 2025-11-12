"""
Enhanced Process Memory Rollback System
Provides process memory state management and rollback
"""

import psutil
import time
import json
import threading
from datetime import datetime
from typing import Dict, List, Any, Optional
import logging
import os
import subprocess

class EnhancedProcessRollback:
    """Enhanced process memory rollback with state management"""
    
    def __init__(self, config_manager):
        self.config_manager = config_manager
        self.logger = logging.getLogger(__name__)
        self.process_lock = threading.Lock()
        
        # Process tracking
        self.process_states = {}
        self.process_history = []
        self.memory_snapshots = {}
        
        # Configuration
        self.backup_dir = "backups/process_states"
        self.max_history = 500
        self.critical_processes = [
            "explorer.exe", "winlogon.exe", "csrss.exe",
            "lsass.exe", "services.exe", "svchost.exe",
            "system", "kernel", "init", "systemd"
        ]
        
        # Initialize backup directory
        os.makedirs(self.backup_dir, exist_ok=True)
    
    def create_process_backup(self, process_id: int, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create comprehensive process backup"""
        try:
            with self.process_lock:
                try:
                    process = psutil.Process(process_id)
                except psutil.NoSuchProcess:
                    return {"success": False, "error": "Process does not exist"}
                
                # Get process info
                process_info = {
                    "pid": process.pid,
                    "name": process.name(),
                    "exe": process.exe(),
                    "cmdline": process.cmdline(),
                    "cwd": process.cwd(),
                    "status": process.status(),
                    "create_time": process.create_time(),
                    "cpu_percent": process.cpu_percent(),
                    "memory_info": process.memory_info()._asdict(),
                    "memory_percent": process.memory_percent(),
                    "num_threads": process.num_threads(),
                    "num_fds": process.num_fds() if hasattr(process, 'num_fds') else 0,
                    "connections": [conn._asdict() for conn in process.connections()],
                    "open_files": [f.path for f in process.open_files()],
                    "environ": dict(process.environ()),
                    "threat_data": threat_data,
                    "timestamp": datetime.now().isoformat()
                }
                
                # Create memory snapshot
                memory_snapshot = self._create_memory_snapshot(process)
                
                # Store process state
                backup_id = f"process_backup_{int(time.time())}_{process_id}"
                process_state = {
                    "backup_id": backup_id,
                    "process_info": process_info,
                    "memory_snapshot": memory_snapshot,
                    "timestamp": datetime.now().isoformat()
                }
                
                self.process_states[process_id] = process_state
                self.memory_snapshots[process_id] = memory_snapshot
                
                # Add to history
                self.process_history.append(process_state)
                if len(self.process_history) > self.max_history:
                    self.process_history.pop(0)
                
                # Save to disk
                self._save_process_states()
                
                return {
                    "success": True,
                    "backup_id": backup_id,
                    "process_id": process_id,
                    "process_name": process.name(),
                    "memory_usage": process.memory_percent(),
                    "cpu_usage": process.cpu_percent()
                }
                
        except Exception as e:
            self.logger.error(f"Process backup failed for PID {process_id}: {e}")
            return {"success": False, "error": str(e)}
    
    def rollback_process(self, process_id: int, backup_id: str = None) -> Dict[str, Any]:
        """Rollback process to previous state"""
        try:
            with self.process_lock:
                # Find backup
                if backup_id:
                    backup_state = self._find_backup_by_id(backup_id)
                else:
                    backup_state = self.process_states.get(process_id)
                
                if not backup_state:
                    return {"success": False, "error": "No backup found"}
                
                try:
                    process = psutil.Process(process_id)
                except psutil.NoSuchProcess:
                    return {"success": False, "error": "Process does not exist"}
                
                # Create current process backup before rollback
                current_backup = self.create_process_backup(process_id, {"rollback": True})
                
                # Restore process state
                restore_result = self._restore_process_state(process, backup_state)
                
                if restore_result.get("success"):
                    return {
                        "success": True,
                        "process_id": process_id,
                        "backup_id": backup_state["backup_id"],
                        "restore_result": restore_result,
                        "current_backup": current_backup
                    }
                else:
                    return {
                        "success": False,
                        "error": restore_result.get("error", "Process restore failed"),
                        "current_backup": current_backup
                    }
                
        except Exception as e:
            self.logger.error(f"Process rollback failed for PID {process_id}: {e}")
            return {"success": False, "error": str(e)}
    
    def terminate_suspicious_process(self, process_id: int, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Terminate suspicious process with backup"""
        try:
            with self.process_lock:
                try:
                    process = psutil.Process(process_id)
                except psutil.NoSuchProcess:
                    return {"success": False, "error": "Process does not exist"}
                
                # Create backup before termination
                backup_result = self.create_process_backup(process_id, threat_data)
                
                # Terminate process
                try:
                    process.terminate()
                    process.wait(timeout=5)
                except psutil.TimeoutExpired:
                    # Force kill if terminate doesn't work
                    process.kill()
                    process.wait(timeout=5)
                
                return {
                    "success": True,
                    "process_id": process_id,
                    "process_name": process.name(),
                    "backup_result": backup_result,
                    "termination_method": "terminate" if not hasattr(process, '_terminated') else "kill"
                }
                
        except Exception as e:
            self.logger.error(f"Process termination failed for PID {process_id}: {e}")
            return {"success": False, "error": str(e)}
    
    def restore_process_from_backup(self, backup_id: str) -> Dict[str, Any]:
        """Restore process from backup"""
        try:
            backup_state = self._find_backup_by_id(backup_id)
            if not backup_state:
                return {"success": False, "error": "Backup not found"}
            
            process_info = backup_state["process_info"]
            
            # Try to restart the process
            try:
                if process_info["exe"] and os.path.exists(process_info["exe"]):
                    # Start new process
                    new_process = subprocess.Popen(
                        process_info["cmdline"],
                        cwd=process_info["cwd"],
                        env=process_info["environ"]
                    )
                    
                    return {
                        "success": True,
                        "new_process_id": new_process.pid,
                        "backup_id": backup_id,
                        "original_process_id": process_info["pid"],
                        "process_name": process_info["name"]
                    }
                else:
                    return {"success": False, "error": "Executable not found"}
                    
            except Exception as e:
                return {"success": False, "error": f"Process restart failed: {e}"}
                
        except Exception as e:
            self.logger.error(f"Process restore from backup failed: {e}")
            return {"success": False, "error": str(e)}
    
    def scan_suspicious_processes(self) -> Dict[str, Any]:
        """Scan for suspicious processes"""
        try:
            suspicious_processes = []
            all_processes = []
            
            for process in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'cmdline']):
                try:
                    process_info = process.info
                    all_processes.append(process_info)
                    
                    # Check for suspicious patterns
                    suspicious_score = self._calculate_suspicious_score(process_info)
                    
                    if suspicious_score > 0.7:
                        suspicious_processes.append({
                            "process_info": process_info,
                            "suspicious_score": suspicious_score,
                            "reasons": self._get_suspicious_reasons(process_info)
                        })
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            return {
                "success": True,
                "total_processes": len(all_processes),
                "suspicious_processes": len(suspicious_processes),
                "suspicious_details": suspicious_processes,
                "all_processes": all_processes[:50]  # Limit for performance
            }
            
        except Exception as e:
            self.logger.error(f"Suspicious process scan failed: {e}")
            return {"success": False, "error": str(e)}
    
    def _create_memory_snapshot(self, process) -> Dict[str, Any]:
        """Create memory snapshot of process"""
        try:
            memory_info = process.memory_info()
            memory_maps = []
            
            try:
                for mmap in process.memory_maps():
                    memory_maps.append({
                        "path": mmap.path,
                        "rss": mmap.rss,
                        "size": mmap.size,
                        "pss": mmap.pss,
                        "shared_clean": mmap.shared_clean,
                        "shared_dirty": mmap.shared_dirty,
                        "private_clean": mmap.private_clean,
                        "private_dirty": mmap.private_dirty,
                        "referenced": mmap.referenced,
                        "anonymous": mmap.anonymous
                    })
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
            
            return {
                "memory_info": memory_info._asdict(),
                "memory_maps": memory_maps,
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Memory snapshot creation failed: {e}")
            return {}
    
    def _restore_process_state(self, process, backup_state) -> Dict[str, Any]:
        """Restore process state from backup"""
        try:
            # This is a simplified restoration
            # In reality, full process state restoration is complex and OS-dependent
            
            process_info = backup_state["process_info"]
            
            # Check if process is still running
            if process.status() == psutil.STATUS_ZOMBIE:
                return {"success": False, "error": "Process is zombie"}
            
            # Restore working directory if possible
            try:
                if os.path.exists(process_info["cwd"]):
                    os.chdir(process_info["cwd"])
            except Exception:
                pass
            
            return {
                "success": True,
                "restored_attributes": ["cwd"],
                "message": "Process state partially restored"
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def _calculate_suspicious_score(self, process_info) -> float:
        """Calculate suspicious score for process"""
        score = 0.0
        
        # High CPU usage
        if process_info.get("cpu_percent", 0) > 80:
            score += 0.3
        
        # High memory usage
        if process_info.get("memory_percent", 0) > 80:
            score += 0.3
        
        # Suspicious process names
        suspicious_names = ["malware", "virus", "trojan", "backdoor", "keylogger"]
        process_name = process_info.get("name", "").lower()
        for suspicious in suspicious_names:
            if suspicious in process_name:
                score += 0.4
                break
        
        # Suspicious command line
        cmdline = " ".join(process_info.get("cmdline", [])).lower()
        suspicious_cmds = ["nc", "netcat", "ncat", "wget", "curl", "powershell", "cmd"]
        for cmd in suspicious_cmds:
            if cmd in cmdline:
                score += 0.2
                break
        
        return min(score, 1.0)
    
    def _get_suspicious_reasons(self, process_info) -> List[str]:
        """Get reasons why process is suspicious"""
        reasons = []
        
        if process_info.get("cpu_percent", 0) > 80:
            reasons.append("High CPU usage")
        
        if process_info.get("memory_percent", 0) > 80:
            reasons.append("High memory usage")
        
        process_name = process_info.get("name", "").lower()
        suspicious_names = ["malware", "virus", "trojan", "backdoor", "keylogger"]
        for suspicious in suspicious_names:
            if suspicious in process_name:
                reasons.append(f"Suspicious process name: {suspicious}")
                break
        
        return reasons
    
    def _find_backup_by_id(self, backup_id: str) -> Optional[Dict[str, Any]]:
        """Find backup by ID"""
        for state in self.process_history:
            if state["backup_id"] == backup_id:
                return state
        return None
    
    def _save_process_states(self):
        """Save process states to disk"""
        try:
            states_file = os.path.join(self.backup_dir, "process_states.json")
            with open(states_file, 'w') as f:
                json.dump({
                    "process_states": self.process_states,
                    "process_history": self.process_history[-100:],  # Keep last 100
                    "memory_snapshots": {k: v for k, v in list(self.memory_snapshots.items())[-50:]}
                }, f, indent=2)
        except Exception as e:
            self.logger.error(f"Failed to save process states: {e}")
    
    def load_process_states(self):
        """Load process states from disk"""
        try:
            states_file = os.path.join(self.backup_dir, "process_states.json")
            if os.path.exists(states_file):
                with open(states_file, 'r') as f:
                    data = json.load(f)
                    self.process_states = data.get("process_states", {})
                    self.process_history = data.get("process_history", [])
                    self.memory_snapshots = data.get("memory_snapshots", {})
        except Exception as e:
            self.logger.error(f"Failed to load process states: {e}")
    
    def cleanup_old_backups(self, days: int = 7):
        """Cleanup old backups"""
        try:
            cutoff_time = time.time() - (days * 24 * 60 * 60)
            
            # Cleanup process history
            self.process_history = [
                state for state in self.process_history
                if datetime.fromisoformat(state["timestamp"]).timestamp() > cutoff_time
            ]
            
            self._save_process_states()
            
        except Exception as e:
            self.logger.error(f"Process backup cleanup failed: {e}")
    
    def get_process_statistics(self) -> Dict[str, Any]:
        """Get process rollback statistics"""
        return {
            "total_backups": len(self.process_states),
            "history_entries": len(self.process_history),
            "memory_snapshots": len(self.memory_snapshots),
            "critical_processes_monitored": len(self.critical_processes),
            "backup_directory": self.backup_dir
        }
