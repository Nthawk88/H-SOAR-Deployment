"""
Model Machine Learning untuk deteksi anomali menggunakan Isolation Forest
dan K-Means Clustering
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import silhouette_score
import joblib
import json
import os
from datetime import datetime
from typing import Dict, List, Any, Tuple
import logging

class AnomalyDetector:
    """Kelas untuk deteksi anomali menggunakan multiple ML algorithms"""
    
    def __init__(self, model_path: str = "models/"):
        self.model_path = model_path
        self.logger = self._setup_logger()
        self.scaler = StandardScaler()
        self.isolation_forest = None
        self.kmeans = None
        self.feature_columns = []
        self.is_trained = False
        
        # Buat direktori model jika belum ada
        os.makedirs(model_path, exist_ok=True)
    
    def _setup_logger(self) -> logging.Logger:
        """Setup logger untuk anomaly detector"""
        logger = logging.getLogger('AnomalyDetector')
        logger.setLevel(logging.INFO)
        
        handler = logging.FileHandler('logs/anomaly_detector.log')
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
        return logger
    
    def prepare_features(self, host_metrics: Dict[str, Any], 
                        network_metrics: Dict[str, Any]) -> np.ndarray:
        """Siapkan fitur untuk model ML dari data host dan jaringan"""
        features = []
        
        # Fitur dari host metrics
        # Always use the same structure - normalize to training data structure
        system = host_metrics.get('system', host_metrics)  # Use system if available, otherwise use host_metrics directly
        features.extend([
            system.get('cpu', {}).get('percent', 0),
            system.get('memory', {}).get('percent', 0),
            system.get('disk', {}).get('percent', 0),
            system.get('network', {}).get('bytes_sent', 0) / 1000000,  # MB
            system.get('network', {}).get('bytes_recv', 0) / 1000000,  # MB
        ])
        
        # Fitur dari proses
        processes = host_metrics.get('processes', [])
        features.extend([
            len(processes),  # Jumlah proses
            sum(1 for p in processes if p.get('is_suspicious', False)),  # Proses mencurigakan
            max([p.get('cpu_percent', 0) for p in processes], default=0),  # CPU tertinggi
            max([p.get('memory_percent', 0) for p in processes], default=0),  # Memory tertinggi
        ])
        
        # Fitur dari file kritis
        critical_files = host_metrics.get('critical_files', {})
        modified_files = sum(1 for f in critical_files.values() 
                           if f.get('exists') and f.get('modified'))
        features.append(modified_files)
        
        # Fitur dari koneksi jaringan
        network_connections = host_metrics.get('network_connections', [])
        features.append(len(network_connections))
        
        # Fitur dari network metrics
        network_features = network_metrics.get('features', {})
        features.extend([
            network_features.get('total_events', 0),
            network_features.get('alert_events', 0),
            network_features.get('foreign_connections', 0),
            len(network_features.get('unique_src_ips', [])),
            len(network_features.get('unique_dst_ips', [])),
            len(network_features.get('unique_ports', [])),
            len(network_features.get('suspicious_patterns', [])),
        ])
        
        # Fitur tambahan dari network anomaly score
        features.append(network_metrics.get('anomaly_score', 0))
        
        # Pad features to ensure consistent feature count (31 features)
        while len(features) < 31:
            features.append(0.0)
        
        # Ensure consistent data type and convert to float64
        features_array = np.array(features, dtype=np.float64).reshape(1, -1)
        return features_array
    
    def train_baseline_model(self, training_data: List[Dict[str, Any]]) -> bool:
        """Latih model dengan data baseline normal"""
        try:
            self.logger.info("Memulai pelatihan model baseline...")
            
            # Siapkan data training
            X = []
            for data_point in training_data:
                host_metrics = data_point.get('host_metrics', {})
                network_metrics = data_point.get('network_metrics', {})
                features = self.prepare_features(host_metrics, network_metrics)
                X.append(features.flatten())
            
            X = np.array(X)
            
            if len(X) < 10:
                self.logger.error("Data training tidak cukup (minimal 10 sampel)")
                return False
            
            # Ensure consistent data type
            X = np.array(X, dtype=np.float64)
            
            # Normalisasi fitur
            X_scaled = self.scaler.fit_transform(X)
            
            # Simpan nama kolom fitur
            self.feature_columns = [f"feature_{i}" for i in range(X.shape[1])]
            
            # Latih Isolation Forest
            self.isolation_forest = IsolationForest(
                contamination=0.01,  # 1% data dianggap anomali (lebih konservatif)
                random_state=42,
                n_estimators=100
            )
            self.isolation_forest.fit(X_scaled)
            
            # Latih K-Means untuk clustering
            # Tentukan jumlah cluster optimal
            best_k = self._find_optimal_clusters(X_scaled)
            self.kmeans = KMeans(n_clusters=best_k, random_state=42)
            self.kmeans.fit(X_scaled)
            
            self.is_trained = True
            self.logger.info(f"Model berhasil dilatih dengan {len(X)} sampel")
            
            # Simpan model
            self.save_models()
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error training model: {e}")
            return False
    
    def _find_optimal_clusters(self, X: np.ndarray) -> int:
        """Tentukan jumlah cluster optimal menggunakan silhouette score"""
        if len(X) < 4:
            return 2
            
        max_clusters = min(10, len(X) // 2)
        best_k = 2
        best_score = -1
        
        for k in range(2, max_clusters + 1):
            try:
                kmeans = KMeans(n_clusters=k, random_state=42, n_init=10)
                cluster_labels = kmeans.fit_predict(X)
                score = silhouette_score(X, cluster_labels)
                
                if score > best_score:
                    best_score = score
                    best_k = k
            except:
                continue
                
        return best_k
    
    def detect_anomaly(self, host_metrics: Dict[str, Any], 
                      network_metrics: Dict[str, Any]) -> Dict[str, Any]:
        """Deteksi anomali pada data baru"""
        if not self.is_trained:
            return {
                "is_anomaly": False,
                "anomaly_score": 0.0,
                "confidence": 0.0,
                "explanation": "Model belum dilatih"
            }
        
        try:
            # Siapkan fitur
            features = self.prepare_features(host_metrics, network_metrics)
            # Ensure consistent data type
            features = np.array(features, dtype=np.float64)
            
            # Bypass ML model untuk sementara dan gunakan nilai sederhana
            try:
                features_scaled = self.scaler.transform(features)
                # Prediksi dengan Isolation Forest
                if_anomaly = self.isolation_forest.predict(features_scaled)[0]
                if_score = self.isolation_forest.decision_function(features_scaled)[0]
                
                # Prediksi dengan K-Means
                cluster = self.kmeans.predict(features_scaled)[0]
                distance_to_center = np.linalg.norm(
                    features_scaled - self.kmeans.cluster_centers_[cluster]
                )
            except Exception as ml_error:
                # Fallback ke deteksi sederhana jika ML model gagal
                self.logger.warning(f"ML model error: {ml_error}, using simple detection")
                if_anomaly = 1  # Normal
                if_score = 0.0
                cluster = 0
                distance_to_center = 0.0
            
            # Hitung skor anomali gabungan
            # Konversi if_score (semakin negatif = semakin anomali)
            if_normalized = max(0, (if_score + 0.5) * 100)  # Normalisasi ke 0-100
            
            # Hitung jarak dari cluster center (semakin jauh = semakin anomali)
            distances = [
                np.linalg.norm(features_scaled - center) 
                for center in self.kmeans.cluster_centers_
            ]
            max_distance = np.max(distances) if len(distances) > 0 else 1.0
            if max_distance > 0:
                distance_normalized = (distance_to_center / max_distance) * 100
            else:
                distance_normalized = 0.0
            
            # Skor gabungan (rata-rata tertimbang)
            combined_score = (if_normalized * 0.7) + (distance_normalized * 0.3)
            
            # Handle NaN values
            if not isinstance(combined_score, (int, float)) or combined_score != combined_score:
                combined_score = 0.0
            
            # Tentukan apakah anomali
            is_anomaly = if_anomaly == -1 or combined_score > 85
            
            # Hitung confidence
            confidence = min(100, combined_score)
            
            # Generate explanation
            explanation = self._generate_explanation(
                features, if_anomaly, combined_score, cluster
            )
            
            # Extract CPU and memory usage for monitoring display
            # Always use the 'system' structure since that's what collect_all_metrics returns
            cpu_usage = host_metrics.get('system', {}).get('cpu', {}).get('percent', 0)
            memory_usage = host_metrics.get('system', {}).get('memory', {}).get('percent', 0)
            
            return {
                "is_anomaly": is_anomaly,
                "anomaly_score": combined_score,
                "confidence": confidence,
                "explanation": explanation,
                "isolation_forest_score": if_score,
                "cluster": int(cluster),
                "distance_to_center": float(distance_to_center),
                "cpu_usage": float(cpu_usage),
                "memory_usage": float(memory_usage)
            }
            
        except Exception as e:
            self.logger.error(f"Error detecting anomaly: {e}")
            return {
                "is_anomaly": False,
                "anomaly_score": 0.0,
                "confidence": 0.0,
                "explanation": f"Error: {str(e)}"
            }
    
    def _generate_explanation(self, features: np.ndarray, if_anomaly: int, 
                            score: float, cluster: int) -> str:
        """Generate penjelasan untuk hasil deteksi anomali"""
        explanations = []
        
        if if_anomaly == -1:
            explanations.append("Isolation Forest mendeteksi outlier")
        
        if score > 80:
            explanations.append("Skor anomali sangat tinggi")
        elif score > 60:
            explanations.append("Skor anomali tinggi")
        
        # Analisis fitur individual
        feature_names = [
            "CPU Usage", "Memory Usage", "Disk Usage", 
            "Network Sent (MB)", "Network Received (MB)",
            "Process Count", "Suspicious Processes", 
            "Max CPU Process", "Max Memory Process",
            "Modified Critical Files", "Network Connections",
            "Total Events", "Alert Events", "Foreign Connections",
            "Unique Source IPs", "Unique Dest IPs", "Unique Ports",
            "Suspicious Patterns", "Network Anomaly Score"
        ]
        
        # Cari fitur dengan nilai ekstrem
        for i, (name, value) in enumerate(zip(feature_names, features[0])):
            if i < 5:  # Metrik sistem
                if value > 80:
                    explanations.append(f"{name} sangat tinggi: {value:.1f}%")
            elif i == 5:  # Process count
                if value > 200:
                    explanations.append(f"Terlalu banyak proses: {int(value)}")
            elif i == 6:  # Suspicious processes
                if value > 0:
                    explanations.append(f"Proses mencurigakan: {int(value)}")
            elif i == 9:  # Modified critical files
                if value > 0:
                    explanations.append(f"File kritis dimodifikasi: {int(value)}")
            elif i == 10:  # Network connections
                if value > 50:
                    explanations.append(f"Banyak koneksi jaringan: {int(value)}")
            elif i == 13:  # Foreign connections
                if value > 10:
                    explanations.append(f"Banyak koneksi asing: {int(value)}")
        
        if not explanations:
            explanations.append("Tidak ada indikator anomali yang jelas")
        
        return "; ".join(explanations)
    
    def save_models(self):
        """Simpan model yang sudah dilatih"""
        try:
            # Simpan scaler
            joblib.dump(self.scaler, f"{self.model_path}/scaler.pkl")
            
            # Simpan Isolation Forest
            if self.isolation_forest:
                joblib.dump(self.isolation_forest, f"{self.model_path}/isolation_forest.pkl")
            
            # Simpan K-Means
            if self.kmeans:
                joblib.dump(self.kmeans, f"{self.model_path}/kmeans.pkl")
            
            # Simpan metadata
            metadata = {
                "feature_columns": self.feature_columns,
                "is_trained": self.is_trained,
                "trained_at": datetime.now().isoformat(),
                "model_version": "1.0"
            }
            
            with open(f"{self.model_path}/metadata.json", 'w') as f:
                json.dump(metadata, f, indent=2)
            
            self.logger.info("Model berhasil disimpan")
            
        except Exception as e:
            self.logger.error(f"Error saving models: {e}")
    
    def load_models(self) -> bool:
        """Load model yang sudah disimpan"""
        try:
            # Load scaler
            self.scaler = joblib.load(f"{self.model_path}/scaler.pkl")
            
            # Load Isolation Forest
            if os.path.exists(f"{self.model_path}/isolation_forest.pkl"):
                self.isolation_forest = joblib.load(f"{self.model_path}/isolation_forest.pkl")
            
            # Load K-Means
            if os.path.exists(f"{self.model_path}/kmeans.pkl"):
                self.kmeans = joblib.load(f"{self.model_path}/kmeans.pkl")
            
            # Load metadata
            with open(f"{self.model_path}/metadata.json", 'r') as f:
                metadata = json.load(f)
                self.feature_columns = metadata.get('feature_columns', [])
                self.is_trained = metadata.get('is_trained', False)
            
            self.logger.info("Model berhasil dimuat")
            return True
            
        except Exception as e:
            self.logger.error(f"Error loading models: {e}")
            return False
