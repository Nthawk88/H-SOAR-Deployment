"""
Sistem Self-Learning untuk IDS/IPS Auto-Healing
Mengekstrak pola dari serangan yang berhasil dideteksi dan memperbarui model
"""

import json
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import logging
import os
from collections import defaultdict

class SelfLearningSystem:
    """Kelas untuk sistem pembelajaran mandiri"""
    
    def __init__(self, learning_path: str = "learning_data/"):
        self.learning_path = learning_path
        self.logger = self._setup_logger()
        self.attack_patterns = {}
        self.feature_importance = {}
        self.signature_database = []
        
        # Buat direktori learning jika belum ada
        os.makedirs(learning_path, exist_ok=True)
        os.makedirs(f"{learning_path}/patterns", exist_ok=True)
        os.makedirs(f"{learning_path}/signatures", exist_ok=True)
    
    def _setup_logger(self) -> logging.Logger:
        """Setup logger untuk self-learning system"""
        logger = logging.getLogger('SelfLearningSystem')
        logger.setLevel(logging.INFO)
        
        handler = logging.FileHandler('logs/self_learning.log')
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
        return logger
    
    def learn_from_attack(self, attack_data: Dict[str, Any]) -> bool:
        """Belajar dari serangan yang berhasil dideteksi"""
        try:
            self.logger.info("Memulai pembelajaran dari serangan...")
            
            # 1. Ekstrak pola serangan
            attack_pattern = self._extract_attack_pattern(attack_data)
            
            # 2. Update feature importance
            self._update_feature_importance(attack_data)
            
            # 3. Generate signature baru
            new_signature = self._generate_signature(attack_pattern, attack_data)
            
            # 4. Simpan data pembelajaran
            self._save_learning_data(attack_pattern, new_signature)
            
            # 5. Update model ML jika diperlukan
            self._update_ml_model(attack_data)
            
            self.logger.info("Pembelajaran selesai")
            return True
            
        except Exception as e:
            self.logger.error(f"Error in self-learning: {e}")
            return False
    
    def _extract_attack_pattern(self, attack_data: Dict[str, Any]) -> Dict[str, Any]:
        """Ekstrak pola unik dari serangan"""
        pattern = {
            "timestamp": datetime.now().isoformat(),
            "attack_id": f"attack_{int(datetime.now().timestamp())}",
            "threat_level": attack_data.get('threat_level', 'UNKNOWN'),
            "features": {},
            "network_patterns": {},
            "host_patterns": {},
            "temporal_patterns": {}
        }
        
        # Ekstrak fitur host
        host_metrics = attack_data.get('host_metrics', {})
        if host_metrics:
            pattern["host_patterns"] = {
                "cpu_usage": host_metrics.get('system', {}).get('cpu', {}).get('percent', 0),
                "memory_usage": host_metrics.get('system', {}).get('memory', {}).get('percent', 0),
                "suspicious_processes": [
                    p for p in host_metrics.get('processes', [])
                    if p.get('is_suspicious', False)
                ],
                "modified_files": [
                    f for f, info in host_metrics.get('critical_files', {}).items()
                    if info.get('exists') and info.get('modified')
                ]
            }
        
        # Ekstrak pola jaringan
        network_metrics = attack_data.get('network_metrics', {})
        if network_metrics:
            features = network_metrics.get('features', {})
            pattern["network_patterns"] = {
                "foreign_ips": network_metrics.get('foreign_ips', []),
                "unique_ports": features.get('unique_ports', []),
                "protocols": features.get('protocols', {}),
                "suspicious_patterns": features.get('suspicious_patterns', []),
                "packet_sizes": features.get('packet_sizes', []),
                "connection_count": features.get('total_events', 0)
            }
        
        # Ekstrak pola temporal
        pattern["temporal_patterns"] = {
            "detection_time": attack_data.get('timestamp', datetime.now().isoformat()),
            "response_time": attack_data.get('response_time_seconds', 0),
            "duration": self._calculate_attack_duration(attack_data)
        }
        
        return pattern
    
    def _calculate_attack_duration(self, attack_data: Dict[str, Any]) -> float:
        """Hitung durasi serangan dalam detik"""
        # Ini adalah estimasi sederhana
        # Dalam implementasi nyata, akan ada timestamp yang lebih akurat
        return attack_data.get('response_time_seconds', 0)
    
    def _update_feature_importance(self, attack_data: Dict[str, Any]):
        """Update importance score untuk setiap fitur"""
        # Hitung kontribusi setiap fitur dalam deteksi
        feature_weights = {
            "cpu_usage": 0.15,
            "memory_usage": 0.15,
            "suspicious_processes": 0.25,
            "modified_files": 0.20,
            "foreign_connections": 0.15,
            "network_anomaly": 0.10
        }
        
        # Update feature importance berdasarkan serangan ini
        for feature, weight in feature_weights.items():
            if feature not in self.feature_importance:
                self.feature_importance[feature] = 0.0
            
            # Tambahkan weight ke importance score
            self.feature_importance[feature] += weight * 0.1  # Learning rate
        
        # Normalisasi importance scores
        total_importance = sum(self.feature_importance.values())
        if total_importance > 0:
            for feature in self.feature_importance:
                self.feature_importance[feature] /= total_importance
    
    def _generate_signature(self, attack_pattern: Dict[str, Any], 
                          attack_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate signature baru berdasarkan pola serangan"""
        signature = {
            "signature_id": f"sig_{int(datetime.now().timestamp())}",
            "created_at": datetime.now().isoformat(),
            "attack_type": self._classify_attack_type(attack_pattern),
            "severity": attack_data.get('threat_level', 'MEDIUM'),
            "rules": [],
            "confidence": 0.8
        }
        
        # Generate rules berdasarkan pola
        rules = []
        
        # Rule untuk proses mencurigakan
        suspicious_procs = attack_pattern.get('host_patterns', {}).get('suspicious_processes', [])
        for proc in suspicious_procs:
            rules.append({
                "type": "process",
                "condition": f"process_name == '{proc.get('name', '')}'",
                "action": "alert",
                "description": f"Suspicious process detected: {proc.get('name', '')}"
            })
        
        # Rule untuk file kritis
        modified_files = attack_pattern.get('host_patterns', {}).get('modified_files', [])
        for file_path in modified_files:
            rules.append({
                "type": "file",
                "condition": f"file_modified == '{file_path}'",
                "action": "alert",
                "description": f"Critical file modified: {file_path}"
            })
        
        # Rule untuk IP asing
        foreign_ips = attack_pattern.get('network_patterns', {}).get('foreign_ips', [])
        for ip in foreign_ips[:5]:  # Limit to 5 IPs
            rules.append({
                "type": "network",
                "condition": f"dest_ip == '{ip}'",
                "action": "block",
                "description": f"Connection to foreign IP: {ip}"
            })
        
        # Rule untuk port scanning
        unique_ports = attack_pattern.get('network_patterns', {}).get('unique_ports', [])
        if len(unique_ports) > 10:
            rules.append({
                "type": "network",
                "condition": f"unique_ports > 10",
                "action": "alert",
                "description": "Potential port scanning detected"
            })
        
        signature["rules"] = rules
        return signature
    
    def _classify_attack_type(self, attack_pattern: Dict[str, Any]) -> str:
        """Klasifikasi jenis serangan berdasarkan pola"""
        host_patterns = attack_pattern.get('host_patterns', {})
        network_patterns = attack_pattern.get('network_patterns', {})
        
        # Cek indikator ransomware
        if (host_patterns.get('cpu_usage', 0) > 80 and 
            host_patterns.get('memory_usage', 0) > 80 and
            len(host_patterns.get('modified_files', [])) > 3):
            return "RANSOMWARE"
        
        # Cek indikator port scanning
        if len(network_patterns.get('unique_ports', [])) > 20:
            return "PORT_SCAN"
        
        # Cek indikator data exfiltration
        if (len(network_patterns.get('foreign_ips', [])) > 5 and
            network_patterns.get('connection_count', 0) > 100):
            return "DATA_EXFILTRATION"
        
        # Cek indikator privilege escalation
        if any('passwd' in f or 'shadow' in f for f in host_patterns.get('modified_files', [])):
            return "PRIVILEGE_ESCALATION"
        
        return "UNKNOWN"
    
    def _save_learning_data(self, attack_pattern: Dict[str, Any], 
                          signature: Dict[str, Any]):
        """Simpan data pembelajaran"""
        try:
            # Simpan attack pattern
            pattern_file = f"{self.learning_path}/patterns/{attack_pattern['attack_id']}.json"
            with open(pattern_file, 'w') as f:
                json.dump(attack_pattern, f, indent=2)
            
            # Simpan signature
            signature_file = f"{self.learning_path}/signatures/{signature['signature_id']}.json"
            with open(signature_file, 'w') as f:
                json.dump(signature, f, indent=2)
            
            # Update signature database
            self.signature_database.append(signature)
            
            # Simpan feature importance
            importance_file = f"{self.learning_path}/feature_importance.json"
            with open(importance_file, 'w') as f:
                json.dump(self.feature_importance, f, indent=2)
            
            self.logger.info(f"Learning data saved: {attack_pattern['attack_id']}")
            
        except Exception as e:
            self.logger.error(f"Error saving learning data: {e}")
    
    def _update_ml_model(self, attack_data: Dict[str, Any]):
        """Update model ML dengan data serangan baru"""
        try:
            # Simpan data serangan untuk retraining
            attack_file = f"{self.learning_path}/attacks/attack_{int(datetime.now().timestamp())}.json"
            os.makedirs(f"{self.learning_path}/attacks", exist_ok=True)
            
            with open(attack_file, 'w') as f:
                json.dump(attack_data, f, indent=2)
            
            # Trigger retraining jika ada cukup data baru
            self._check_retraining_trigger()
            
        except Exception as e:
            self.logger.error(f"Error updating ML model: {e}")
    
    def _check_retraining_trigger(self):
        """Cek apakah perlu retraining model"""
        attacks_dir = f"{self.learning_path}/attacks"
        if not os.path.exists(attacks_dir):
            return
        
        attack_files = [f for f in os.listdir(attacks_dir) if f.endswith('.json')]
        
        # Retrain jika ada 10 serangan baru
        if len(attack_files) >= 10:
            self.logger.info("Triggering model retraining...")
            # Di sini akan dipanggil fungsi retraining model
            # self._retrain_model()
    
    def get_learning_stats(self) -> Dict[str, Any]:
        """Dapatkan statistik pembelajaran"""
        try:
            patterns_dir = f"{self.learning_path}/patterns"
            signatures_dir = f"{self.learning_path}/signatures"
            
            pattern_count = len([f for f in os.listdir(patterns_dir) if f.endswith('.json')]) if os.path.exists(patterns_dir) else 0
            signature_count = len([f for f in os.listdir(signatures_dir) if f.endswith('.json')]) if os.path.exists(signatures_dir) else 0
            
            return {
                "total_patterns_learned": pattern_count,
                "total_signatures_generated": signature_count,
                "feature_importance": self.feature_importance,
                "recent_attacks": len(self.signature_database),
                "learning_active": True
            }
            
        except Exception as e:
            self.logger.error(f"Error getting learning stats: {e}")
            return {"error": str(e)}
    
    def export_signatures(self, output_file: str = "generated_signatures.json"):
        """Export semua signature yang dihasilkan"""
        try:
            with open(output_file, 'w') as f:
                json.dump(self.signature_database, f, indent=2)
            
            self.logger.info(f"Signatures exported to {output_file}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error exporting signatures: {e}")
            return False
