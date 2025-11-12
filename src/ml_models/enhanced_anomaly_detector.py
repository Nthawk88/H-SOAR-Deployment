"""
Enhanced Anomaly Detection System
Provides advanced anomaly detection with multiple algorithms
"""

import numpy as np
import pandas as pd
import time
import json
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
import logging
from collections import deque
import statistics
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.cluster import DBSCAN, KMeans
from sklearn.neural_network import MLPClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import joblib
import os

class EnhancedAnomalyDetector:
    """Enhanced anomaly detection with multiple ML algorithms"""
    
    def __init__(self, config_manager):
        self.config_manager = config_manager
        self.logger = logging.getLogger(__name__)
        self.detector_lock = threading.Lock()
        
        # Models
        self.models = {}
        self.scalers = {}
        self.model_weights = {}
        self.model_performance = {}
        
        # Data
        self.feature_history = deque(maxlen=10000)
        self.anomaly_history = deque(maxlen=1000)
        self.baseline_features = {}
        
        # Configuration
        self.model_dir = "models/enhanced_anomaly"
        self.retrain_interval = 3600  # 1 hour
        self.last_retrain = 0
        
        # Feature engineering
        self.feature_names = [
            'cpu_usage', 'memory_usage', 'disk_usage', 'network_bandwidth',
            'process_count', 'connection_count', 'file_changes', 'response_time',
            'cpu_trend', 'memory_trend', 'network_trend', 'process_trend'
        ]
        
        # Initialize models
        self._initialize_models()
    
    def _initialize_models(self):
        """Initialize all anomaly detection models"""
        try:
            os.makedirs(self.model_dir, exist_ok=True)
            
            # Initialize models
            self.models = {
                'isolation_forest': IsolationForest(
                    contamination=0.1,
                    random_state=42,
                    n_estimators=100
                ),
                'dbscan': DBSCAN(
                    eps=0.5,
                    min_samples=5
                ),
                'kmeans': KMeans(
                    n_clusters=8,
                    random_state=42,
                    n_init=10
                ),
                'random_forest': RandomForestClassifier(
                    n_estimators=100,
                    random_state=42,
                    max_depth=10
                ),
                'mlp_classifier': MLPClassifier(
                    hidden_layer_sizes=(100, 50),
                    random_state=42,
                    max_iter=1000
                ),
                'logistic_regression': LogisticRegression(
                    random_state=42,
                    max_iter=1000
                )
            }
            
            # Initialize scalers
            self.scalers = {
                'standard': StandardScaler(),
                'robust': StandardScaler()
            }
            
            # Initialize model weights
            self.model_weights = {
                'isolation_forest': 0.25,
                'dbscan': 0.15,
                'kmeans': 0.15,
                'random_forest': 0.20,
                'mlp_classifier': 0.15,
                'logistic_regression': 0.10
            }
            
            # Initialize performance tracking
            self.model_performance = {
                model_name: {
                    'accuracy': 0.0,
                    'precision': 0.0,
                    'recall': 0.0,
                    'f1_score': 0.0,
                    'last_update': 0
                } for model_name in self.models.keys()
            }
            
            # Load existing models if available
            self._load_models()
            
            self.logger.info("Enhanced anomaly detection models initialized")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize models: {e}")
    
    def detect_enhanced_anomaly(self, host_metrics: Dict[str, Any], 
                              network_metrics: Dict[str, Any],
                              additional_features: Dict[str, Any] = None) -> Dict[str, Any]:
        """Detect anomalies using enhanced ensemble approach"""
        try:
            # Extract features
            features = self._extract_features(host_metrics, network_metrics, additional_features)
            
            if not features:
                return {"is_anomaly": False, "anomaly_score": 0.0, "error": "No features extracted"}
            
            # Store features for training
            with self.detector_lock:
                self.feature_history.append({
                    "timestamp": datetime.now().isoformat(),
                    "features": features,
                    "host_metrics": host_metrics,
                    "network_metrics": network_metrics
                })
            
            # Detect anomalies using ensemble
            ensemble_result = self._ensemble_anomaly_detection(features)
            
            # Analyze anomaly patterns
            pattern_analysis = self._analyze_anomaly_patterns(features, ensemble_result)
            
            # Determine threat level
            threat_level = self._determine_threat_level(ensemble_result, pattern_analysis)
            
            # Store anomaly result
            anomaly_result = {
                "is_anomaly": ensemble_result["is_anomaly"],
                "anomaly_score": ensemble_result["anomaly_score"],
                "confidence": ensemble_result["confidence"],
                "threat_level": threat_level,
                "pattern_analysis": pattern_analysis,
                "model_predictions": ensemble_result["model_predictions"],
                "features": features,
                "timestamp": datetime.now().isoformat()
            }
            
            with self.detector_lock:
                self.anomaly_history.append(anomaly_result)
            
            # Retrain models if needed
            self._check_retrain_models()
            
            return anomaly_result
            
        except Exception as e:
            self.logger.error(f"Enhanced anomaly detection failed: {e}")
            return {"is_anomaly": False, "anomaly_score": 0.0, "error": str(e)}
    
    def _extract_features(self, host_metrics: Dict[str, Any], 
                         network_metrics: Dict[str, Any],
                         additional_features: Dict[str, Any] = None) -> List[float]:
        """Extract comprehensive features from metrics"""
        try:
            features = []
            
            # Basic system features
            cpu_usage = host_metrics.get("cpu_usage", 0)
            memory_usage = host_metrics.get("memory_usage", 0)
            disk_usage = host_metrics.get("disk_usage", 0)
            process_count = host_metrics.get("process_count", 0)
            
            # Network features
            network_bandwidth = network_metrics.get("packets_per_second", 0)
            connection_count = network_metrics.get("connections", 0)
            
            # Additional features
            file_changes = additional_features.get("file_changes", 0) if additional_features else 0
            response_time = additional_features.get("response_time", 0) if additional_features else 0
            
            # Calculate trend features
            cpu_trend = self._calculate_trend_feature('cpu_usage', cpu_usage)
            memory_trend = self._calculate_trend_feature('memory_usage', memory_usage)
            network_trend = self._calculate_trend_feature('network_bandwidth', network_bandwidth)
            process_trend = self._calculate_trend_feature('process_count', process_count)
            
            # Combine all features
            features = [
                cpu_usage, memory_usage, disk_usage, network_bandwidth,
                process_count, connection_count, file_changes, response_time,
                cpu_trend, memory_trend, network_trend, process_trend
            ]
            
            # Normalize features
            features = self._normalize_features(features)
            
            return features
            
        except Exception as e:
            self.logger.error(f"Feature extraction failed: {e}")
            return []
    
    def _calculate_trend_feature(self, feature_name: str, current_value: float) -> float:
        """Calculate trend feature based on historical data"""
        try:
            if len(self.feature_history) < 5:
                return 0.0
            
            # Get recent values for this feature
            recent_values = []
            for entry in list(self.feature_history)[-10:]:
                features = entry.get("features", [])
                if len(features) >= len(self.feature_names):
                    feature_index = self.feature_names.index(feature_name)
                    recent_values.append(features[feature_index])
            
            if len(recent_values) < 3:
                return 0.0
            
            # Calculate trend (slope)
            x = np.arange(len(recent_values))
            y = np.array(recent_values)
            
            # Simple linear regression slope
            slope = np.polyfit(x, y, 1)[0]
            
            return slope
            
        except Exception as e:
            self.logger.error(f"Trend calculation failed for {feature_name}: {e}")
            return 0.0
    
    def _normalize_features(self, features: List[float]) -> List[float]:
        """Normalize features using baseline statistics"""
        try:
            if not self.baseline_features:
                return features
            
            normalized_features = []
            for i, feature in enumerate(features):
                if i < len(self.feature_names):
                    feature_name = self.feature_names[i]
                    baseline_stats = self.baseline_features.get(feature_name, {})
                    
                    mean = baseline_stats.get("mean", 0)
                    std = baseline_stats.get("std", 1)
                    
                    if std > 0:
                        normalized_feature = (feature - mean) / std
                    else:
                        normalized_feature = feature
                    
                    normalized_features.append(normalized_feature)
                else:
                    normalized_features.append(feature)
            
            return normalized_features
            
        except Exception as e:
            self.logger.error(f"Feature normalization failed: {e}")
            return features
    
    def _ensemble_anomaly_detection(self, features: List[float]) -> Dict[str, Any]:
        """Perform ensemble anomaly detection"""
        try:
            features_array = np.array(features).reshape(1, -1)
            
            # Scale features
            scaled_features = self.scalers['standard'].fit_transform(features_array)
            
            model_predictions = {}
            anomaly_scores = []
            
            # Get predictions from each model
            for model_name, model in self.models.items():
                try:
                    if model_name in ['isolation_forest', 'dbscan', 'kmeans']:
                        # Unsupervised models
                        if model_name == 'isolation_forest':
                            score = model.decision_function(scaled_features)[0]
                            prediction = model.predict(scaled_features)[0]
                            anomaly_scores.append(score)
                        elif model_name == 'dbscan':
                            prediction = model.fit_predict(scaled_features)[0]
                            score = -1 if prediction == -1 else 1  # -1 is outlier
                            anomaly_scores.append(score)
                        elif model_name == 'kmeans':
                            distances = model.transform(scaled_features)[0]
                            score = np.min(distances)
                            prediction = 1 if score > np.mean(distances) * 1.5 else 0
                            anomaly_scores.append(score)
                        
                        model_predictions[model_name] = {
                            "prediction": prediction,
                            "score": score,
                            "weight": self.model_weights[model_name]
                        }
                    
                    else:
                        # Supervised models (if trained)
                        if hasattr(model, 'predict_proba'):
                            try:
                                proba = model.predict_proba(scaled_features)[0]
                                prediction = model.predict(scaled_features)[0]
                                score = proba[1] if len(proba) > 1 else proba[0]
                                
                                model_predictions[model_name] = {
                                    "prediction": prediction,
                                    "score": score,
                                    "weight": self.model_weights[model_name]
                                }
                                
                                anomaly_scores.append(score)
                            except:
                                # Model not trained yet
                                model_predictions[model_name] = {
                                    "prediction": 0,
                                    "score": 0.0,
                                    "weight": self.model_weights[model_name]
                                    "error": "Model not trained"
                                }
                
                except Exception as e:
                    self.logger.error(f"Model {model_name} prediction failed: {e}")
                    model_predictions[model_name] = {
                        "prediction": 0,
                        "score": 0.0,
                        "weight": self.model_weights[model_name],
                        "error": str(e)
                    }
            
            # Calculate ensemble score
            if anomaly_scores:
                ensemble_score = np.mean(anomaly_scores)
                ensemble_prediction = 1 if ensemble_score > 0.5 else 0
            else:
                ensemble_score = 0.0
                ensemble_prediction = 0
            
            # Calculate confidence
            confidence = self._calculate_confidence(model_predictions)
            
            return {
                "is_anomaly": bool(ensemble_prediction),
                "anomaly_score": float(ensemble_score),
                "confidence": confidence,
                "model_predictions": model_predictions
            }
            
        except Exception as e:
            self.logger.error(f"Ensemble anomaly detection failed: {e}")
            return {
                "is_anomaly": False,
                "anomaly_score": 0.0,
                "confidence": 0.0,
                "model_predictions": {}
            }
    
    def _calculate_confidence(self, model_predictions: Dict[str, Any]) -> float:
        """Calculate confidence based on model agreement"""
        try:
            predictions = []
            weights = []
            
            for model_name, prediction_data in model_predictions.items():
                if "error" not in prediction_data:
                    predictions.append(prediction_data["prediction"])
                    weights.append(prediction_data["weight"])
            
            if not predictions:
                return 0.0
            
            # Calculate weighted agreement
            weighted_sum = sum(p * w for p, w in zip(predictions, weights))
            total_weight = sum(weights)
            
            if total_weight == 0:
                return 0.0
            
            agreement = weighted_sum / total_weight
            
            # Calculate confidence based on agreement
            if agreement > 0.8 or agreement < 0.2:
                confidence = 0.9  # High confidence
            elif agreement > 0.6 or agreement < 0.4:
                confidence = 0.7  # Medium confidence
            else:
                confidence = 0.5  # Low confidence
            
            return confidence
            
        except Exception as e:
            self.logger.error(f"Confidence calculation failed: {e}")
            return 0.0
    
    def _analyze_anomaly_patterns(self, features: List[float], 
                                ensemble_result: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze anomaly patterns"""
        try:
            pattern_analysis = {
                "feature_anomalies": [],
                "pattern_type": "unknown",
                "severity_indicators": [],
                "temporal_pattern": "unknown"
            }
            
            # Analyze individual feature anomalies
            for i, feature_value in enumerate(features):
                if i < len(self.feature_names):
                    feature_name = self.feature_names[i]
                    baseline_stats = self.baseline_features.get(feature_name, {})
                    
                    mean = baseline_stats.get("mean", 0)
                    std = baseline_stats.get("std", 1)
                    
                    # Check if feature is anomalous
                    if std > 0:
                        z_score = abs(feature_value - mean) / std
                        if z_score > 2.0:  # 2 standard deviations
                            pattern_analysis["feature_anomalies"].append({
                                "feature": feature_name,
                                "value": feature_value,
                                "z_score": z_score,
                                "severity": "high" if z_score > 3.0 else "medium"
                            })
            
            # Determine pattern type
            pattern_analysis["pattern_type"] = self._determine_pattern_type(
                pattern_analysis["feature_anomalies"]
            )
            
            # Analyze temporal patterns
            pattern_analysis["temporal_pattern"] = self._analyze_temporal_patterns()
            
            return pattern_analysis
            
        except Exception as e:
            self.logger.error(f"Pattern analysis failed: {e}")
            return {"feature_anomalies": [], "pattern_type": "unknown"}
    
    def _determine_pattern_type(self, feature_anomalies: List[Dict[str, Any]]) -> str:
        """Determine the type of anomaly pattern"""
        try:
            if not feature_anomalies:
                return "normal"
            
            # Count anomalies by category
            cpu_anomalies = [a for a in feature_anomalies if "cpu" in a["feature"]]
            memory_anomalies = [a for a in feature_anomalies if "memory" in a["feature"]]
            network_anomalies = [a for a in feature_anomalies if "network" in a["feature"]]
            process_anomalies = [a for a in feature_anomalies if "process" in a["feature"]]
            
            # Determine pattern type
            if len(cpu_anomalies) > 0 and len(memory_anomalies) > 0:
                return "resource_exhaustion"
            elif len(network_anomalies) > 0:
                return "network_anomaly"
            elif len(process_anomalies) > 0:
                return "process_anomaly"
            elif len(feature_anomalies) > 5:
                return "system_wide_anomaly"
            else:
                return "isolated_anomaly"
                
        except Exception as e:
            self.logger.error(f"Pattern type determination failed: {e}")
            return "unknown"
    
    def _analyze_temporal_patterns(self) -> str:
        """Analyze temporal patterns in anomalies"""
        try:
            if len(self.anomaly_history) < 5:
                return "insufficient_data"
            
            # Get recent anomaly scores
            recent_scores = [
                entry["anomaly_score"] for entry in list(self.anomaly_history)[-10:]
            ]
            
            # Analyze trend
            if len(recent_scores) >= 3:
                x = np.arange(len(recent_scores))
                y = np.array(recent_scores)
                slope = np.polyfit(x, y, 1)[0]
                
                if slope > 0.1:
                    return "increasing"
                elif slope < -0.1:
                    return "decreasing"
                else:
                    return "stable"
            
            return "unknown"
            
        except Exception as e:
            self.logger.error(f"Temporal pattern analysis failed: {e}")
            return "unknown"
    
    def _determine_threat_level(self, ensemble_result: Dict[str, Any], 
                              pattern_analysis: Dict[str, Any]) -> str:
        """Determine threat level based on anomaly analysis"""
        try:
            anomaly_score = ensemble_result["anomaly_score"]
            confidence = ensemble_result["confidence"]
            pattern_type = pattern_analysis["pattern_type"]
            
            # Base threat level on anomaly score
            if anomaly_score > 0.8 and confidence > 0.8:
                base_level = "CRITICAL"
            elif anomaly_score > 0.6 and confidence > 0.6:
                base_level = "HIGH"
            elif anomaly_score > 0.4 and confidence > 0.4:
                base_level = "MEDIUM"
            else:
                base_level = "LOW"
            
            # Adjust based on pattern type
            if pattern_type == "system_wide_anomaly":
                if base_level == "LOW":
                    base_level = "MEDIUM"
                elif base_level == "MEDIUM":
                    base_level = "HIGH"
            elif pattern_type == "resource_exhaustion":
                if base_level == "LOW":
                    base_level = "MEDIUM"
            
            return base_level
            
        except Exception as e:
            self.logger.error(f"Threat level determination failed: {e}")
            return "LOW"
    
    def _check_retrain_models(self):
        """Check if models need retraining"""
        try:
            current_time = time.time()
            
            if current_time - self.last_retrain > self.retrain_interval:
                self._retrain_models()
                self.last_retrain = current_time
                
        except Exception as e:
            self.logger.error(f"Model retrain check failed: {e}")
    
    def _retrain_models(self):
        """Retrain models with new data"""
        try:
            self.logger.info("Retraining anomaly detection models...")
            
            if len(self.feature_history) < 100:
                self.logger.warning("Insufficient data for retraining")
                return
            
            # Prepare training data
            X = []
            y = []
            
            for entry in self.feature_history:
                features = entry.get("features", [])
                if len(features) == len(self.feature_names):
                    X.append(features)
                    
                    # Create labels based on anomaly history
                    timestamp = datetime.fromisoformat(entry["timestamp"])
                    is_anomaly = self._is_anomaly_at_time(timestamp)
                    y.append(1 if is_anomaly else 0)
            
            if len(X) < 50:
                self.logger.warning("Insufficient labeled data for retraining")
                return
            
            X = np.array(X)
            y = np.array(y)
            
            # Scale features
            X_scaled = self.scalers['standard'].fit_transform(X)
            
            # Retrain supervised models
            for model_name in ['random_forest', 'mlp_classifier', 'logistic_regression']:
                try:
                    model = self.models[model_name]
                    model.fit(X_scaled, y)
                    
                    # Evaluate model
                    y_pred = model.predict(X_scaled)
                    accuracy = accuracy_score(y, y_pred)
                    precision = precision_score(y, y_pred, average='weighted')
                    recall = recall_score(y, y_pred, average='weighted')
                    f1 = f1_score(y, y_pred, average='weighted')
                    
                    # Update performance
                    self.model_performance[model_name] = {
                        'accuracy': accuracy,
                        'precision': precision,
                        'recall': recall,
                        'f1_score': f1,
                        'last_update': time.time()
                    }
                    
                    self.logger.info(f"Model {model_name} retrained - Accuracy: {accuracy:.3f}")
                    
                except Exception as e:
                    self.logger.error(f"Failed to retrain {model_name}: {e}")
            
            # Retrain unsupervised models
            for model_name in ['isolation_forest', 'dbscan', 'kmeans']:
                try:
                    model = self.models[model_name]
                    model.fit(X_scaled)
                    self.logger.info(f"Model {model_name} retrained")
                    
                except Exception as e:
                    self.logger.error(f"Failed to retrain {model_name}: {e}")
            
            # Update baseline features
            self._update_baseline_features(X)
            
            # Save models
            self._save_models()
            
            self.logger.info("Model retraining completed")
            
        except Exception as e:
            self.logger.error(f"Model retraining failed: {e}")
    
    def _is_anomaly_at_time(self, timestamp: datetime) -> bool:
        """Check if there was an anomaly at a specific time"""
        try:
            time_window = timedelta(minutes=5)
            
            for anomaly_entry in self.anomaly_history:
                anomaly_time = datetime.fromisoformat(anomaly_entry["timestamp"])
                
                if abs((timestamp - anomaly_time).total_seconds()) < time_window.total_seconds():
                    return anomaly_entry["is_anomaly"]
            
            return False
            
        except Exception as e:
            self.logger.error(f"Anomaly time check failed: {e}")
            return False
    
    def _update_baseline_features(self, X: np.ndarray):
        """Update baseline feature statistics"""
        try:
            for i, feature_name in enumerate(self.feature_names):
                if i < X.shape[1]:
                    feature_values = X[:, i]
                    
                    self.baseline_features[feature_name] = {
                        "mean": np.mean(feature_values),
                        "std": np.std(feature_values),
                        "min": np.min(feature_values),
                        "max": np.max(feature_values),
                        "median": np.median(feature_values)
                    }
            
        except Exception as e:
            self.logger.error(f"Baseline update failed: {e}")
    
    def _save_models(self):
        """Save trained models"""
        try:
            for model_name, model in self.models.items():
                model_path = os.path.join(self.model_dir, f"{model_name}.pkl")
                joblib.dump(model, model_path)
            
            # Save scalers
            scaler_path = os.path.join(self.model_dir, "scalers.pkl")
            joblib.dump(self.scalers, scaler_path)
            
            # Save baseline features
            baseline_path = os.path.join(self.model_dir, "baseline_features.json")
            with open(baseline_path, 'w') as f:
                json.dump(self.baseline_features, f, indent=2)
            
            # Save model performance
            performance_path = os.path.join(self.model_dir, "model_performance.json")
            with open(performance_path, 'w') as f:
                json.dump(self.model_performance, f, indent=2)
            
        except Exception as e:
            self.logger.error(f"Model saving failed: {e}")
    
    def _load_models(self):
        """Load existing models"""
        try:
            # Load models
            for model_name in self.models.keys():
                model_path = os.path.join(self.model_dir, f"{model_name}.pkl")
                if os.path.exists(model_path):
                    self.models[model_name] = joblib.load(model_path)
            
            # Load scalers
            scaler_path = os.path.join(self.model_dir, "scalers.pkl")
            if os.path.exists(scaler_path):
                self.scalers = joblib.load(scaler_path)
            
            # Load baseline features
            baseline_path = os.path.join(self.model_dir, "baseline_features.json")
            if os.path.exists(baseline_path):
                with open(baseline_path, 'r') as f:
                    self.baseline_features = json.load(f)
            
            # Load model performance
            performance_path = os.path.join(self.model_dir, "model_performance.json")
            if os.path.exists(performance_path):
                with open(performance_path, 'r') as f:
                    self.model_performance = json.load(f)
            
            self.logger.info("Models loaded successfully")
            
        except Exception as e:
            self.logger.error(f"Model loading failed: {e}")
    
    def get_detector_status(self) -> Dict[str, Any]:
        """Get anomaly detector status"""
        try:
            with self.detector_lock:
                return {
                    "models_loaded": len([m for m in self.models.values() if hasattr(m, 'fit')]),
                    "feature_history_size": len(self.feature_history),
                    "anomaly_history_size": len(self.anomaly_history),
                    "baseline_established": bool(self.baseline_features),
                    "model_performance": self.model_performance,
                    "last_retrain": self.last_retrain,
                    "feature_names": self.feature_names
                }
                
        except Exception as e:
            self.logger.error(f"Failed to get detector status: {e}")
            return {"error": str(e)}
    
    def get_anomaly_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get anomaly detection history"""
        try:
            with self.detector_lock:
                return list(self.anomaly_history)[-limit:] if self.anomaly_history else []
        except Exception as e:
            self.logger.error(f"Failed to get anomaly history: {e}")
            return []
