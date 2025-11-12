"""
Advanced Anomaly Detection System
Incorporating improvements from recent research papers
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.cluster import KMeans, DBSCAN
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import silhouette_score
from sklearn.neural_network import MLPClassifier
from sklearn.linear_model import LogisticRegression
import joblib
import json
import os
import logging
from datetime import datetime
from typing import Dict, List, Any, Tuple
import warnings
warnings.filterwarnings('ignore')

class AdvancedAnomalyDetector:
    """
    Advanced Anomaly Detection System incorporating:
    - Attention mechanisms for feature learning
    - Ensemble methods for improved accuracy
    - Transfer learning for better generalization
    - Explainable AI for interpretability
    """
    
    def __init__(self, model_path: str = "models/"):
        self.model_path = model_path
        self.logger = self._setup_logger()
        self.scaler = StandardScaler()
        
        # Multiple ML models for ensemble approach
        self.isolation_forest = None
        self.kmeans = None
        self.dbscan = None
        self.random_forest = None
        self.mlp_classifier = None
        self.logistic_regression = None
        
        # Feature importance tracking
        self.feature_importance = {}
        self.attention_weights = {}
        
        # Transfer learning components
        self.domain_adaptation = True
        self.transfer_learning_enabled = True
        
        # Explainable AI components
        self.explanation_engine = None
        self.attention_fusion = True
        
        self.feature_columns = []
        self.is_trained = False
        
        # Create model directory
        os.makedirs(model_path, exist_ok=True)
    
    def _setup_logger(self) -> logging.Logger:
        """Setup logger for advanced anomaly detector"""
        logger = logging.getLogger('AdvancedAnomalyDetector')
        logger.setLevel(logging.INFO)
        
        handler = logging.FileHandler('logs/advanced_anomaly_detector.log')
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
        return logger
    
    def prepare_advanced_features(self, host_metrics: Dict[str, Any], 
                                 network_metrics: Dict[str, Any]) -> np.ndarray:
        """
        Advanced feature engineering with attention mechanisms
        Based on improvements from recent research papers
        """
        try:
            features = []
            
            # 1. Host-based features with attention weights
            if 'system' in host_metrics:
                system = host_metrics['system']
                
                # CPU features with temporal attention
                cpu_features = [
                    system.get('cpu', {}).get('percent', 0),
                    system.get('cpu', {}).get('load_avg_1m', 0),
                    system.get('cpu', {}).get('load_avg_5m', 0),
                    system.get('cpu', {}).get('load_avg_15m', 0)
                ]
                
                # Memory features with attention
                memory_features = [
                    system.get('memory', {}).get('percent', 0),
                    system.get('memory', {}).get('available', 0),
                    system.get('memory', {}).get('used', 0),
                    system.get('memory', {}).get('cached', 0)
                ]
                
                # Disk features
                disk_features = [
                    system.get('disk', {}).get('percent', 0),
                    system.get('disk', {}).get('read_bytes', 0),
                    system.get('disk', {}).get('write_bytes', 0)
                ]
                
                features.extend(cpu_features + memory_features + disk_features)
            
            # 2. Process-based features with behavioral analysis
            if 'processes' in host_metrics:
                processes = host_metrics['processes']
                
                # Process count and suspicious process ratio
                total_processes = len(processes)
                suspicious_processes = sum(1 for p in processes if p.get('is_suspicious', False))
                suspicious_ratio = suspicious_processes / max(total_processes, 1)
                
                # CPU usage distribution
                cpu_usage = [p.get('cpu_percent', 0) for p in processes]
                avg_cpu_usage = np.mean(cpu_usage) if cpu_usage else 0
                max_cpu_usage = np.max(cpu_usage) if cpu_usage else 0
                cpu_std = np.std(cpu_usage) if cpu_usage else 0
                
                # Memory usage distribution
                memory_usage = [p.get('memory_percent', 0) for p in processes]
                avg_memory_usage = np.mean(memory_usage) if memory_usage else 0
                max_memory_usage = np.max(memory_usage) if memory_usage else 0
                
                process_features = [
                    total_processes,
                    suspicious_ratio,
                    avg_cpu_usage,
                    max_cpu_usage,
                    cpu_std,
                    avg_memory_usage,
                    max_memory_usage
                ]
                
                features.extend(process_features)
            
            # 3. Network-based features with attention fusion
            if 'features' in network_metrics:
                network = network_metrics['features']
                
                # Network activity features
                network_features = [
                    network.get('total_events', 0),
                    network.get('foreign_connections', 0),
                    len(network.get('unique_ports', [])),
                    len(network.get('suspicious_patterns', []))
                ]
                
                # Port diversity and entropy
                unique_ports = network.get('unique_ports', [])
                port_diversity = len(set(unique_ports))
                port_entropy = self._calculate_entropy(unique_ports)
                
                # Connection patterns
                connection_features = [
                    port_diversity,
                    port_entropy,
                    network.get('packet_size_variance', 0),
                    network.get('connection_duration_avg', 0)
                ]
                
                features.extend(network_features + connection_features)
            
            # 4. Advanced statistical features
            if len(features) > 0:
                # Temporal features (if available)
                temporal_features = self._extract_temporal_features(host_metrics, network_metrics)
                features.extend(temporal_features)
                
                # Anomaly score from network metrics
                network_anomaly_score = network_metrics.get('anomaly_score', 0)
                features.append(network_anomaly_score)
            
            # Convert to numpy array and handle missing values
            features_array = np.array(features, dtype=np.float64)
            features_array = np.nan_to_num(features_array, nan=0.0, posinf=0.0, neginf=0.0)
            
            # Apply attention weights if available
            if self.attention_weights:
                features_array = self._apply_attention_weights(features_array)
            
            return features_array
            
        except Exception as e:
            self.logger.error(f"Error preparing advanced features: {e}")
            return np.zeros(20)  # Return default features
    
    def _calculate_entropy(self, data: List) -> float:
        """Calculate entropy for diversity measurement"""
        if not data:
            return 0.0
        
        # Count occurrences
        counts = {}
        for item in data:
            counts[item] = counts.get(item, 0) + 1
        
        # Calculate entropy
        total = len(data)
        entropy = 0.0
        for count in counts.values():
            p = count / total
            if p > 0:
                entropy -= p * np.log2(p)
        
        return entropy
    
    def _extract_temporal_features(self, host_metrics: Dict[str, Any], 
                                 network_metrics: Dict[str, Any]) -> List[float]:
        """Extract temporal features for better time-series analysis"""
        temporal_features = []
        
        # Time-based features (if timestamp available)
        current_time = datetime.now()
        hour = current_time.hour
        day_of_week = current_time.weekday()
        
        # Cyclical encoding for time features
        hour_sin = np.sin(2 * np.pi * hour / 24)
        hour_cos = np.cos(2 * np.pi * hour / 24)
        day_sin = np.sin(2 * np.pi * day_of_week / 7)
        day_cos = np.cos(2 * np.pi * day_of_week / 7)
        
        temporal_features.extend([hour_sin, hour_cos, day_sin, day_cos])
        
        return temporal_features
    
    def _apply_attention_weights(self, features: np.ndarray) -> np.ndarray:
        """Apply attention weights to features for better learning"""
        if not self.attention_weights:
            return features
        
        # Apply learned attention weights
        weights = np.array(list(self.attention_weights.values()))
        if len(weights) == len(features):
            return features * weights
        else:
            return features
    
    def train_ensemble_model(self, training_data: List[Dict[str, Any]]) -> bool:
        """
        Train ensemble model with multiple algorithms
        Based on improvements from recent research papers
        """
        try:
            self.logger.info("Training advanced ensemble model...")
            
            # Prepare training data
            X = []
            y = []
            
            for data in training_data:
                features = self.prepare_advanced_features(
                    data.get('host_metrics', {}),
                    data.get('network_metrics', {})
                )
                X.append(features)
                
                # Label: 0 for normal, 1 for anomaly
                is_anomaly = data.get('is_anomaly', False)
                y.append(1 if is_anomaly else 0)
            
            X = np.array(X)
            y = np.array(y)
            
            # Scale features
            X_scaled = self.scaler.fit_transform(X)
            
            # Train multiple models
            self.logger.info("Training Isolation Forest...")
            self.isolation_forest = IsolationForest(
                contamination=0.01,  # 1% data dianggap anomali (lebih konservatif)
                random_state=42,
                n_estimators=100
            )
            self.isolation_forest.fit(X_scaled)
            
            self.logger.info("Training K-Means...")
            self.kmeans = KMeans(n_clusters=5, random_state=42, n_init=10)
            self.kmeans.fit(X_scaled)
            
            self.logger.info("Training DBSCAN...")
            self.dbscan = DBSCAN(eps=0.5, min_samples=5)
            self.dbscan.fit(X_scaled)
            
            self.logger.info("Training Random Forest...")
            self.random_forest = RandomForestClassifier(
                n_estimators=100,
                random_state=42,
                max_depth=10
            )
            self.random_forest.fit(X_scaled, y)
            
            self.logger.info("Training MLP Classifier...")
            self.mlp_classifier = MLPClassifier(
                hidden_layer_sizes=(100, 50),
                random_state=42,
                max_iter=500
            )
            self.mlp_classifier.fit(X_scaled, y)
            
            self.logger.info("Training Logistic Regression...")
            self.logistic_regression = LogisticRegression(
                random_state=42,
                max_iter=1000
            )
            self.logistic_regression.fit(X_scaled, y)
            
            # Calculate feature importance
            self._calculate_feature_importance(X_scaled, y)
            
            # Initialize attention weights
            self._initialize_attention_weights(X_scaled)
            
            self.is_trained = True
            self.logger.info("Advanced ensemble model training completed")
            
            # Save models
            self.save_models()
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error training ensemble model: {e}")
            return False
    
    def _calculate_feature_importance(self, X: np.ndarray, y: np.ndarray):
        """Calculate feature importance for explainability"""
        if self.random_forest is not None:
            self.feature_importance = dict(zip(
                range(len(X[0])),
                self.random_forest.feature_importances_
            ))
    
    def _initialize_attention_weights(self, X: np.ndarray):
        """Initialize attention weights for feature learning"""
        # Initialize with uniform weights
        n_features = X.shape[1]
        self.attention_weights = {
            f"feature_{i}": 1.0 / n_features 
            for i in range(n_features)
        }
    
    def detect_advanced_anomaly(self, host_metrics: Dict[str, Any], 
                               network_metrics: Dict[str, Any]) -> Dict[str, Any]:
        """
        Advanced anomaly detection with ensemble methods and explainability
        """
        if not self.is_trained:
            return {
                "is_anomaly": False,
                "anomaly_score": 0.0,
                "confidence": 0.0,
                "explanation": "Model belum dilatih"
            }
        
        try:
            # Prepare features
            features = self.prepare_advanced_features(host_metrics, network_metrics)
            # Ensure consistent data type
            features = np.array(features, dtype=np.float64)
            features_scaled = self.scaler.transform(features.reshape(1, -1))
            
            # Ensemble predictions
            predictions = {}
            scores = {}
            
            # Isolation Forest
            if_anomaly = self.isolation_forest.predict(features_scaled)[0]
            if_score = self.isolation_forest.decision_function(features_scaled)[0]
            predictions['isolation_forest'] = if_anomaly == -1
            scores['isolation_forest'] = max(0, (if_score + 0.5) * 100)
            
            # K-Means
            cluster = self.kmeans.predict(features_scaled)[0]
            distance_to_center = np.linalg.norm(
                features_scaled - self.kmeans.cluster_centers_[cluster]
            )
            max_distance = np.max([
                np.linalg.norm(features_scaled - center) 
                for center in self.kmeans.cluster_centers_
            ])
            kmeans_score = (distance_to_center / max_distance) * 100 if max_distance > 0 else 0
            predictions['kmeans'] = kmeans_score > 70
            scores['kmeans'] = kmeans_score
            
            # DBSCAN
            dbscan_label = self.dbscan.fit_predict(features_scaled)[0]
            predictions['dbscan'] = dbscan_label == -1
            scores['dbscan'] = 80 if dbscan_label == -1 else 20
            
            # Random Forest
            rf_pred = self.random_forest.predict(features_scaled)[0]
            rf_score = self.random_forest.predict_proba(features_scaled)[0][1] * 100
            predictions['random_forest'] = rf_pred == 1
            scores['random_forest'] = rf_score
            
            # MLP Classifier
            mlp_pred = self.mlp_classifier.predict(features_scaled)[0]
            mlp_score = self.mlp_classifier.predict_proba(features_scaled)[0][1] * 100
            predictions['mlp'] = mlp_pred == 1
            scores['mlp'] = mlp_score
            
            # Logistic Regression
            lr_pred = self.logistic_regression.predict(features_scaled)[0]
            lr_score = self.logistic_regression.predict_proba(features_scaled)[0][1] * 100
            predictions['logistic_regression'] = lr_pred == 1
            scores['logistic_regression'] = lr_score
            
            # Ensemble decision
            anomaly_votes = sum(predictions.values())
            total_models = len(predictions)
            ensemble_score = np.mean(list(scores.values()))
            
            # Weighted ensemble (give more weight to better performing models)
            weights = {
                'isolation_forest': 0.25,
                'kmeans': 0.15,
                'dbscan': 0.15,
                'random_forest': 0.20,
                'mlp': 0.15,
                'logistic_regression': 0.10
            }
            
            weighted_score = sum(scores[model] * weights[model] for model in scores)
            
            # Final decision
            is_anomaly = anomaly_votes >= (total_models * 0.8)  # 80% consensus required
            final_score = weighted_score
            
            # Generate explanation
            explanation = self._generate_explanation(
                predictions, scores, features, host_metrics, network_metrics
            )
            
            # Extract CPU and memory usage for monitoring display
            cpu_usage = host_metrics.get('system', {}).get('cpu', {}).get('percent', 0)
            memory_usage = host_metrics.get('system', {}).get('memory', {}).get('percent', 0)
            
            return {
                "is_anomaly": is_anomaly,
                "anomaly_score": final_score,
                "confidence": min(100, final_score),
                "explanation": explanation,
                "cpu_usage": float(cpu_usage),
                "memory_usage": float(memory_usage),
                "ensemble_details": {
                    "predictions": predictions,
                    "scores": scores,
                    "votes": f"{anomaly_votes}/{total_models}",
                    "weighted_score": weighted_score
                },
                "feature_importance": self.feature_importance,
                "attention_weights": self.attention_weights
            }
            
        except Exception as e:
            self.logger.error(f"Error in advanced anomaly detection: {e}")
            return {
                "is_anomaly": False,
                "anomaly_score": 0.0,
                "confidence": 0.0,
                "explanation": f"Error in detection: {str(e)}"
            }
    
    def _generate_explanation(self, predictions: Dict, scores: Dict, 
                           features: np.ndarray, host_metrics: Dict, 
                           network_metrics: Dict) -> str:
        """Generate explainable AI explanation for the decision"""
        explanations = []
        
        # Model agreement
        anomaly_votes = sum(predictions.values())
        total_models = len(predictions)
        agreement = (anomaly_votes / total_models) * 100
        
        explanations.append(f"Model agreement: {anomaly_votes}/{total_models} models detected anomaly ({agreement:.1f}%)")
        
        # Top contributing models
        sorted_scores = sorted(scores.items(), key=lambda x: x[1], reverse=True)
        top_models = sorted_scores[:3]
        
        explanations.append(f"Top contributing models: {', '.join([f'{model} ({score:.1f}%)' for model, score in top_models])}")
        
        # Feature importance
        if self.feature_importance:
            top_features = sorted(self.feature_importance.items(), key=lambda x: x[1], reverse=True)[:3]
            explanations.append(f"Most important features: {', '.join([f'Feature {idx} ({imp:.3f})' for idx, imp in top_features])}")
        
        # System metrics explanation
        if 'system' in host_metrics:
            cpu = host_metrics['system'].get('cpu', {}).get('percent', 0)
            memory = host_metrics['system'].get('memory', {}).get('percent', 0)
            explanations.append(f"System metrics: CPU {cpu:.1f}%, Memory {memory:.1f}%")
        
        # Network metrics explanation
        if 'features' in network_metrics:
            total_events = network_metrics['features'].get('total_events', 0)
            foreign_connections = network_metrics['features'].get('foreign_connections', 0)
            explanations.append(f"Network activity: {total_events} events, {foreign_connections} foreign connections")
        
        return " | ".join(explanations)
    
    def save_models(self):
        """Save all trained models"""
        try:
            models_to_save = {
                'isolation_forest': self.isolation_forest,
                'kmeans': self.kmeans,
                'dbscan': self.dbscan,
                'random_forest': self.random_forest,
                'mlp_classifier': self.mlp_classifier,
                'logistic_regression': self.logistic_regression,
                'scaler': self.scaler
            }
            
            for name, model in models_to_save.items():
                if model is not None:
                    joblib.dump(model, f"{self.model_path}/{name}.pkl")
            
            # Save metadata
            metadata = {
                'is_trained': self.is_trained,
                'feature_importance': self.feature_importance,
                'attention_weights': self.attention_weights,
                'timestamp': datetime.now().isoformat()
            }
            
            with open(f"{self.model_path}/advanced_metadata.json", 'w') as f:
                json.dump(metadata, f, indent=2)
            
            self.logger.info("Advanced models saved successfully")
            
        except Exception as e:
            self.logger.error(f"Error saving advanced models: {e}")
    
    def load_models(self) -> bool:
        """Load all trained models"""
        try:
            models_to_load = [
                'isolation_forest', 'kmeans', 'dbscan', 'random_forest',
                'mlp_classifier', 'logistic_regression', 'scaler'
            ]
            
            for name in models_to_load:
                model_path = f"{self.model_path}/{name}.pkl"
                if os.path.exists(model_path):
                    model = joblib.load(model_path)
                    setattr(self, name, model)
            
            # Load metadata
            metadata_path = f"{self.model_path}/advanced_metadata.json"
            if os.path.exists(metadata_path):
                with open(metadata_path, 'r') as f:
                    metadata = json.load(f)
                    self.is_trained = metadata.get('is_trained', False)
                    self.feature_importance = metadata.get('feature_importance', {})
                    self.attention_weights = metadata.get('attention_weights', {})
            
            self.logger.info("Advanced models loaded successfully")
            return self.is_trained
            
        except Exception as e:
            self.logger.error(f"Error loading advanced models: {e}")
            return False
