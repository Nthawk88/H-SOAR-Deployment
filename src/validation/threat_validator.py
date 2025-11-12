"""
Sistem Validasi Ancaman Cerdas menggunakan Danger Theory
untuk mengurangi False Positive Rate
"""

import time
import json
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import logging

class ThreatValidator:
    """Kelas untuk validasi ancaman menggunakan Danger Theory"""
    
    def __init__(self, config_path: str = "config/threat_config.json"):
        self.config = self._load_config(config_path)
        self.logger = self._setup_logger()
        self.danger_signals_history = []
        self.anomaly_history = []
        self.validation_threshold = 0.7  # Threshold untuk validasi ancaman
        
    def _load_config(self, config_path: str) -> Dict:
        """Load konfigurasi validasi ancaman"""
        default_config = {
            "danger_signal_timeout": 5,  # detik
            "anomaly_score_threshold": 70.0,
            "validation_window": 10,  # detik
            "high_confidence_threshold": 85.0,
            "medium_confidence_threshold": 60.0,
            "danger_signals": {
                "critical_file_modification": {
                    "weight": 0.3,
                    "files": ["/etc/passwd", "/etc/shadow", "/etc/hosts"]
                },
                "high_resource_usage": {
                    "weight": 0.2,
                    "cpu_threshold": 90.0,
                    "memory_threshold": 90.0
                },
                "suspicious_process": {
                    "weight": 0.25,
                    "processes": ["nc", "netcat", "ncat", "wget", "curl"]
                },
                "network_anomaly": {
                    "weight": 0.15,
                    "foreign_connection_threshold": 10,
                    "port_scan_threshold": 5
                },
                "encryption_activity": {
                    "weight": 0.1,
                    "file_encryption_threshold": 5
                }
            }
        }
        
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
                return {**default_config, **config}
        except FileNotFoundError:
            return default_config
    
    def _setup_logger(self) -> logging.Logger:
        """Setup logger untuk threat validator"""
        logger = logging.getLogger('ThreatValidator')
        logger.setLevel(logging.INFO)
        
        handler = logging.FileHandler('logs/threat_validator.log')
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
        return logger
    
    def validate_threat(self, anomaly_result: Dict[str, Any], 
                       danger_signals: List[str],
                       host_metrics: Dict[str, Any],
                       network_metrics: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validasi ancaman menggunakan kombinasi anomaly score dan danger signals
        """
        try:
            current_time = datetime.now()
            
            # Simpan data ke history
            self._update_history(anomaly_result, danger_signals, current_time)
            
            # Hitung danger signal score
            danger_score = self._calculate_danger_score(danger_signals, host_metrics)
            
            # Hitung anomaly score
            anomaly_score = anomaly_result.get('anomaly_score', 0.0)
            confidence = anomaly_result.get('confidence', 0.0)
            
            # Hitung skor validasi gabungan
            validation_score = self._calculate_validation_score(
                anomaly_score, danger_score, confidence
            )
            
            # Tentukan tingkat ancaman
            threat_level = self._determine_threat_level(validation_score, danger_score)
            
            # Cek apakah ada korelasi temporal
            temporal_correlation = self._check_temporal_correlation(current_time)
            
            # Buat keputusan validasi
            is_validated_threat = self._make_validation_decision(
                validation_score, threat_level, temporal_correlation
            )
            
            # Generate explanation
            explanation = self._generate_validation_explanation(
                anomaly_score, danger_score, validation_score, 
                threat_level, temporal_correlation
            )
            
            result = {
                "is_validated_threat": is_validated_threat,
                "validation_score": validation_score,
                "threat_level": threat_level,
                "danger_score": danger_score,
                "anomaly_score": anomaly_score,
                "confidence": confidence,
                "temporal_correlation": temporal_correlation,
                "explanation": explanation,
                "timestamp": current_time.isoformat(),
                "action_required": is_validated_threat and threat_level in ["HIGH", "CRITICAL"]
            }
            
            # Log hasil validasi
            self.logger.info(f"Threat validation: {is_validated_threat}, "
                           f"Score: {validation_score:.2f}, Level: {threat_level}")
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error validating threat: {e}")
            return {
                "is_validated_threat": False,
                "validation_score": 0.0,
                "threat_level": "LOW",
                "explanation": f"Error: {str(e)}",
                "action_required": False
            }
    
    def _update_history(self, anomaly_result: Dict[str, Any], 
                       danger_signals: List[str], timestamp: datetime):
        """Update history untuk analisis temporal"""
        # Simpan anomaly history
        self.anomaly_history.append({
            "timestamp": timestamp,
            "anomaly_score": anomaly_result.get('anomaly_score', 0.0),
            "confidence": anomaly_result.get('confidence', 0.0)
        })
        
        # Simpan danger signals history
        if danger_signals:
            self.danger_signals_history.append({
                "timestamp": timestamp,
                "signals": danger_signals
            })
        
        # Bersihkan history lama (lebih dari 1 jam)
        cutoff_time = timestamp - timedelta(hours=1)
        self.anomaly_history = [
            h for h in self.anomaly_history 
            if h['timestamp'] > cutoff_time
        ]
        self.danger_signals_history = [
            h for h in self.danger_signals_history 
            if h['timestamp'] > cutoff_time
        ]
    
    def _calculate_danger_score(self, danger_signals: List[str], 
                               host_metrics: Dict[str, Any]) -> float:
        """Hitung skor danger berdasarkan sinyal bahaya"""
        if not danger_signals:
            return 0.0
        
        total_score = 0.0
        signal_weights = self.config['danger_signals']
        
        for signal in danger_signals:
            signal_lower = signal.lower()
            
            # Critical file modification
            if any(file in signal_lower for file in signal_weights['critical_file_modification']['files']):
                total_score += signal_weights['critical_file_modification']['weight'] * 100
            
            # High resource usage
            elif 'cpu' in signal_lower or 'memory' in signal_lower:
                total_score += signal_weights['high_resource_usage']['weight'] * 100
            
            # Suspicious process
            elif any(proc in signal_lower for proc in signal_weights['suspicious_process']['processes']):
                total_score += signal_weights['suspicious_process']['weight'] * 100
            
            # Network anomaly
            elif 'foreign' in signal_lower or 'connection' in signal_lower:
                total_score += signal_weights['network_anomaly']['weight'] * 100
            
            # Encryption activity
            elif 'encrypt' in signal_lower or 'file' in signal_lower:
                total_score += signal_weights['encryption_activity']['weight'] * 100
            
            # Default weight untuk sinyal lainnya
            else:
                total_score += 0.1 * 100
        
        return min(total_score, 100.0)
    
    def _calculate_validation_score(self, anomaly_score: float, 
                                  danger_score: float, confidence: float) -> float:
        """Hitung skor validasi gabungan"""
        # Bobot: Anomaly 40%, Danger 40%, Confidence 20%
        validation_score = (
            anomaly_score * 0.4 +
            danger_score * 0.4 +
            confidence * 0.2
        )
        
        return min(validation_score, 100.0)
    
    def _determine_threat_level(self, validation_score: float, 
                               danger_score: float) -> str:
        """Tentukan tingkat ancaman"""
        if validation_score >= 90 or danger_score >= 80:
            return "CRITICAL"
        elif validation_score >= 75 or danger_score >= 60:
            return "HIGH"
        elif validation_score >= 50 or danger_score >= 40:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _check_temporal_correlation(self, current_time: datetime) -> bool:
        """Cek korelasi temporal antara anomaly dan danger signals"""
        window_seconds = self.config['validation_window']
        cutoff_time = current_time - timedelta(seconds=window_seconds)
        
        # Cek apakah ada anomaly score tinggi dalam window waktu
        recent_anomalies = [
            h for h in self.anomaly_history 
            if h['timestamp'] > cutoff_time and h['anomaly_score'] > 60
        ]
        
        # Cek apakah ada danger signals dalam window waktu
        recent_danger_signals = [
            h for h in self.danger_signals_history 
            if h['timestamp'] > cutoff_time
        ]
        
        # Ada korelasi jika ada keduanya dalam window waktu yang sama
        return len(recent_anomalies) > 0 and len(recent_danger_signals) > 0
    
    def _make_validation_decision(self, validation_score: float, 
                                 threat_level: str, temporal_correlation: bool) -> bool:
        """Buat keputusan validasi akhir"""
        # Threshold untuk validasi ancaman
        threshold = self.config['anomaly_score_threshold']
        
        # Kriteria validasi:
        # 1. Validation score di atas threshold
        # 2. Threat level minimal MEDIUM
        # 3. Ada korelasi temporal (opsional untuk HIGH/CRITICAL)
        
        if threat_level == "CRITICAL":
            return validation_score >= threshold * 0.8  # Threshold lebih rendah untuk CRITICAL
        elif threat_level == "HIGH":
            return validation_score >= threshold and temporal_correlation
        elif threat_level == "MEDIUM":
            return validation_score >= threshold and temporal_correlation
        else:
            return False
    
    def _generate_validation_explanation(self, anomaly_score: float, 
                                       danger_score: float, validation_score: float,
                                       threat_level: str, temporal_correlation: bool) -> str:
        """Generate penjelasan untuk hasil validasi"""
        explanations = []
        
        # Penjelasan berdasarkan skor
        if validation_score >= 90:
            explanations.append("Skor validasi sangat tinggi")
        elif validation_score >= 70:
            explanations.append("Skor validasi tinggi")
        elif validation_score >= 50:
            explanations.append("Skor validasi sedang")
        else:
            explanations.append("Skor validasi rendah")
        
        # Penjelasan berdasarkan threat level
        if threat_level == "CRITICAL":
            explanations.append("Tingkat ancaman KRITIS terdeteksi")
        elif threat_level == "HIGH":
            explanations.append("Tingkat ancaman TINGGI terdeteksi")
        elif threat_level == "MEDIUM":
            explanations.append("Tingkat ancaman SEDANG terdeteksi")
        
        # Penjelasan berdasarkan komponen
        if anomaly_score >= 70:
            explanations.append(f"Skor anomali tinggi: {anomaly_score:.1f}")
        if danger_score >= 50:
            explanations.append(f"Banyak sinyal bahaya: {danger_score:.1f}")
        if temporal_correlation:
            explanations.append("Ada korelasi temporal antara anomali dan sinyal bahaya")
        
        return "; ".join(explanations)
    
    def get_validation_stats(self) -> Dict[str, Any]:
        """Dapatkan statistik validasi"""
        if not self.anomaly_history:
            return {
                "validator_ready": True,  # Validator siap meski belum ada data
                "message": "Belum ada data validasi"
            }
        
        recent_anomalies = self.anomaly_history[-10:]  # 10 data terakhir
        recent_danger_signals = self.danger_signals_history[-10:]
        
        avg_anomaly_score = sum(h['anomaly_score'] for h in recent_anomalies) / len(recent_anomalies)
        avg_confidence = sum(h['confidence'] for h in recent_anomalies) / len(recent_anomalies)
        
        return {
            "validator_ready": True,
            "total_anomalies": len(self.anomaly_history),
            "total_danger_signals": len(self.danger_signals_history),
            "avg_anomaly_score": avg_anomaly_score,
            "avg_confidence": avg_confidence,
            "recent_anomalies": len(recent_anomalies),
            "recent_danger_signals": len(recent_danger_signals)
        }
