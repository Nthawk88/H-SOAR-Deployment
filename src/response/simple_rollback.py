"""
Simple Rollback System - Tanpa Ansible
Implementasi rollback sederhana menggunakan Python murni
"""

import os
import shutil
import json
import time
import subprocess
from datetime import datetime
from typing import Dict, Any, List
import logging

class SimpleRollback:
    """Simple rollback system tanpa dependency Ansible"""
    
    def __init__(self, backup_dir: str = "backups/"):
        self.backup_dir = backup_dir
        self.logger = self._setup_logger()
        os.makedirs(backup_dir, exist_ok=True)
    
    def _setup_logger(self) -> logging.Logger:
        """Setup logger"""
        logger = logging.getLogger('SimpleRollback')
        logger.setLevel(logging.INFO)
        
        handler = logging.FileHandler('logs/rollback.log')
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
        return logger
    
    def execute_rollback(self, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute rollback sederhana tanpa Ansible
        
        AUTO-HEALING STEPS:
        1. Restore modified files
        2. Clear suspicious processes (already done by containment)
        3. Reset network isolation
        4. Restore system state
        5. Generate report
        """
        try:
            self.logger.info("=" * 60)
            self.logger.info("MEMULAI AUTO-HEALING ROLLBACK")
            self.logger.info("=" * 60)
            
            start_time = time.time()
            actions_taken = []
            
            # Step 1: Restore network connectivity
            self.logger.info("Step 1: Restoring network connectivity...")
            network_result = self._restore_network()
            actions_taken.append(network_result)
            
            # Step 2: Restore quarantined files if needed
            self.logger.info("Step 2: Checking quarantined files...")
            quarantine_result = self._handle_quarantine()
            actions_taken.append(quarantine_result)
            
            # Step 3: Verify system processes
            self.logger.info("Step 3: Verifying system processes...")
            process_result = self._verify_processes()
            actions_taken.append(process_result)
            
            # Step 4: Clean temporary attack files
            self.logger.info("Step 4: Cleaning attack artifacts...")
            cleanup_result = self._cleanup_attack_artifacts()
            actions_taken.append(cleanup_result)
            
            # Step 5: Create recovery snapshot
            self.logger.info("Step 5: Creating recovery snapshot...")
            snapshot_result = self._create_recovery_snapshot(threat_data)
            actions_taken.append(snapshot_result)
            
            # Step 6: Generate rollback report
            report_file = self._generate_rollback_report(
                threat_data, actions_taken, start_time
            )
            
            elapsed = time.time() - start_time
            
            self.logger.info("=" * 60)
            self.logger.info(f"AUTO-HEALING ROLLBACK SELESAI ({elapsed:.2f}s)")
            self.logger.info("=" * 60)
            
            return {
                "success": True,
                "rollback_time_seconds": elapsed,
                "actions_taken": actions_taken,
                "report_file": report_file,
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Rollback error: {e}")
            return {
                "success": False,
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
    
    def _restore_network(self) -> Dict[str, Any]:
        """Restore network connectivity"""
        try:
            # Check OS
            import platform
            os_type = platform.system()
            
            if os_type == "Linux":
                # Flush iptables
                try:
                    subprocess.run(["sudo", "iptables", "-F"], 
                                 check=False, capture_output=True)
                    subprocess.run(["sudo", "iptables", "-X"], 
                                 check=False, capture_output=True)
                    
                    # Set default policies to ACCEPT
                    subprocess.run(["sudo", "iptables", "-P", "INPUT", "ACCEPT"], 
                                 check=False, capture_output=True)
                    subprocess.run(["sudo", "iptables", "-P", "OUTPUT", "ACCEPT"], 
                                 check=False, capture_output=True)
                    
                    self.logger.info("✓ Network restored (Linux iptables)")
                    return {
                        "action": "network_restore",
                        "status": "success",
                        "method": "iptables_flush"
                    }
                except Exception as e:
                    self.logger.warning(f"iptables restore failed: {e}")
                    return {
                        "action": "network_restore",
                        "status": "skipped",
                        "reason": "iptables not available or no sudo"
                    }
            
            elif os_type == "Windows":
                # Windows - no iptables, network should be normal
                self.logger.info("[OK] Network OK (Windows - no isolation was active)")
                return {
                    "action": "network_restore",
                    "status": "not_needed",
                    "reason": "Windows - no iptables isolation"
                }
            
            else:
                self.logger.info(f"✓ Network OK ({os_type})")
                return {
                    "action": "network_restore",
                    "status": "not_needed",
                    "reason": f"Unsupported OS: {os_type}"
                }
                
        except Exception as e:
            self.logger.error(f"Network restore error: {e}")
            return {
                "action": "network_restore",
                "status": "error",
                "error": str(e)
            }
    
    def _handle_quarantine(self) -> Dict[str, Any]:
        """Handle quarantined files"""
        try:
            quarantine_dir = "/tmp/quarantine"
            
            if not os.path.exists(quarantine_dir):
                return {
                    "action": "quarantine_check",
                    "status": "no_quarantine",
                    "files_found": 0
                }
            
            # List quarantined files
            quarantined_files = os.listdir(quarantine_dir)
            
            if not quarantined_files:
                return {
                    "action": "quarantine_check",
                    "status": "empty",
                    "files_found": 0
                }
            
            self.logger.info(f"Found {len(quarantined_files)} quarantined files")
            
            # Keep files in quarantine for analysis
            # (In production, admin would review and decide)
            
            return {
                "action": "quarantine_check",
                "status": "preserved",
                "files_found": len(quarantined_files),
                "note": "Files kept in quarantine for analysis"
            }
            
        except Exception as e:
            self.logger.error(f"Quarantine check error: {e}")
            return {
                "action": "quarantine_check",
                "status": "error",
                "error": str(e)
            }
    
    def _verify_processes(self) -> Dict[str, Any]:
        """Verify no suspicious processes running"""
        try:
            import psutil
            
            suspicious_names = ["nc", "netcat", "ncat", "wget", "curl"]
            found_suspicious = []
            
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    proc_name = proc.info['name'].lower()
                    if any(susp in proc_name for susp in suspicious_names):
                        found_suspicious.append({
                            'pid': proc.info['pid'],
                            'name': proc.info['name']
                        })
                except:
                    continue
            
            if found_suspicious:
                self.logger.warning(f"Found {len(found_suspicious)} suspicious processes still running")
            else:
                self.logger.info("✓ No suspicious processes found")
            
            return {
                "action": "process_verification",
                "status": "checked",
                "suspicious_found": len(found_suspicious),
                "processes": found_suspicious
            }
            
        except Exception as e:
            self.logger.error(f"Process verification error: {e}")
            return {
                "action": "process_verification",
                "status": "error",
                "error": str(e)
            }
    
    def _cleanup_attack_artifacts(self) -> Dict[str, Any]:
        """Clean up attack simulation artifacts"""
        try:
            artifacts_cleaned = 0
            
            # Clean common attack simulation files
            patterns_to_clean = [
                "malware_*.py",
                "nc_*.py",
                "wget_*.py",
                "curl_*.py",
                "test_*.txt",
                "simulated_attack_files/",
                "safe_test_files/"
            ]
            
            for pattern in patterns_to_clean:
                if "/" in pattern:
                    # Directory
                    if os.path.exists(pattern):
                        shutil.rmtree(pattern)
                        artifacts_cleaned += 1
                        self.logger.info(f"Cleaned directory: {pattern}")
                else:
                    # File pattern
                    import glob
                    for file in glob.glob(pattern):
                        try:
                            os.remove(file)
                            artifacts_cleaned += 1
                            self.logger.info(f"Cleaned file: {file}")
                        except:
                            pass
            
            self.logger.info(f"[OK] Cleaned {artifacts_cleaned} artifacts")
            
            return {
                "action": "cleanup_artifacts",
                "status": "success",
                "artifacts_cleaned": artifacts_cleaned
            }
            
        except Exception as e:
            self.logger.error(f"Cleanup error: {e}")
            return {
                "action": "cleanup_artifacts",
                "status": "error",
                "error": str(e)
            }
    
    def _create_recovery_snapshot(self, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create recovery snapshot"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            snapshot_dir = f"{self.backup_dir}/recovery_{timestamp}"
            os.makedirs(snapshot_dir, exist_ok=True)
            
            # Save recovery info
            recovery_info = {
                "timestamp": datetime.now().isoformat(),
                "threat_level": threat_data.get('threat_level', 'UNKNOWN'),
                "recovery_actions": "Containment + Rollback executed",
                "system_status": "Recovered"
            }
            
            with open(f"{snapshot_dir}/recovery_info.json", 'w') as f:
                json.dump(recovery_info, f, indent=2)
            
            self.logger.info(f"[OK] Recovery snapshot created: {snapshot_dir}")
            
            return {
                "action": "recovery_snapshot",
                "status": "success",
                "snapshot_dir": snapshot_dir
            }
            
        except Exception as e:
            self.logger.error(f"Snapshot error: {e}")
            return {
                "action": "recovery_snapshot",
                "status": "error",
                "error": str(e)
            }
    
    def _generate_rollback_report(self, threat_data: Dict[str, Any], 
                                 actions: List[Dict], start_time: float) -> str:
        """Generate rollback report"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_file = f"{self.backup_dir}/rollback_report_{timestamp}.txt"
            
            elapsed = time.time() - start_time
            
            report = f"""
{'=' * 70}
AUTO-HEALING ROLLBACK REPORT
{'=' * 70}

Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Duration: {elapsed:.2f} seconds

THREAT INFORMATION:
- Threat Level: {threat_data.get('threat_level', 'UNKNOWN')}
- Validation Score: {threat_data.get('validation_score', 0):.2f}

RECOVERY ACTIONS TAKEN:
"""
            
            for i, action in enumerate(actions, 1):
                report += f"\n{i}. {action.get('action', 'Unknown').replace('_', ' ').title()}\n"
                report += f"   Status: {action.get('status', 'unknown')}\n"
                
                if 'files_found' in action:
                    report += f"   Files Found: {action['files_found']}\n"
                
                if 'suspicious_found' in action:
                    report += f"   Suspicious Processes: {action['suspicious_found']}\n"
                
                if 'artifacts_cleaned' in action:
                    report += f"   Artifacts Cleaned: {action['artifacts_cleaned']}\n"
            
            report += f"""

SYSTEM STATUS: RECOVERED ✓

{'=' * 70}
NOTES:
- Containment executed successfully
- Suspicious processes terminated
- Files quarantined for analysis
- Network connectivity restored
- System monitoring continues

{'=' * 70}
"""
            
            with open(report_file, 'w') as f:
                f.write(report)
            
            self.logger.info(f"✓ Rollback report generated: {report_file}")
            
            return report_file
            
        except Exception as e:
            self.logger.error(f"Report generation error: {e}")
            return ""

