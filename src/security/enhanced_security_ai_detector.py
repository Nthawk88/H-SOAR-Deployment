"""
Enhanced AI Security Detector with Ensemble Models
Comprehensive security-focused AI system with multiple algorithms
"""

import pickle
import numpy as np
import logging
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
import os
import json

from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.neighbors import LocalOutlierFactor
from sklearn.covariance import EllipticEnvelope
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import roc_auc_score
import warnings
warnings.filterwarnings('ignore')


class EnhancedSecurityAIDetector:
    """
    Enhanced AI Security Detector with Ensemble Models
    
    Features:
    - Multiple anomaly detection algorithms
    - Ensemble voting and calibration
    - Adaptive thresholds
    - Security-focused feature engineering
    - Real-time performance optimization
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Ensemble models
        self.models = {}
        self.scalers = {}
        self.is_trained = False
        self.baseline_stats = {}
        
        # Configuration
        self.model_paths = config.get('model_paths', {})
        self.thresholds = config.get('thresholds', {})
        self.ensemble_weights = config.get('ensemble_weights', {})
        self.calibration_enabled = config.get('calibration_enabled', True)
        
        # Performance tracking
        self.prediction_history = []
        self.calibration_history = []
        self.max_history_size = config.get('max_history_size', 1000)
        
        # Initialize models first
        self._initialize_models()
        
        # Auto-load models jika tersedia
        self.load_models()
        
    def _initialize_models(self):
        """Initialize ensemble models with optimized parameters"""
        try:
            # Isolation Forest - Primary model
            self.models['isolation_forest'] = IsolationForest(
                contamination=0.1,
                random_state=42,
                n_estimators=100,
                max_samples='auto',
                max_features=1.0,
                bootstrap=False
            )
            
            # One-Class SVM - Linear kernel for speed
            self.models['one_class_svm'] = OneClassSVM(
                kernel='rbf',
                gamma='scale',
                nu=0.1,
                degree=3,
                coef0=0.0
            )
            
            # Local Outlier Factor - Density-based
            self.models['local_outlier_factor'] = LocalOutlierFactor(
                n_neighbors=20,
                algorithm='auto',
                leaf_size=30,
                metric='minkowski',
                p=2,
                contamination=0.1
            )
            
            # Elliptic Envelope - Robust covariance
            self.models['elliptic_envelope'] = EllipticEnvelope(
                store_precision=True,
                assume_centered=False,
                support_fraction=None,
                contamination=0.1,
                random_state=42
            )
            
            # Initialize scalers for each model
            for model_name in self.models.keys():
                self.scalers[model_name] = StandardScaler()
                
            # Default ensemble weights (can be calibrated)
            self.ensemble_weights = {
                'isolation_forest': 0.35,
                'one_class_svm': 0.25,
                'local_outlier_factor': 0.20,
                'elliptic_envelope': 0.20
            }
            
            # Default thresholds
            self.thresholds = {
                'isolation_forest': 0.85,
                'one_class_svm': 0.80,
                'local_outlier_factor': 0.75,
                'elliptic_envelope': 0.80,
                'ensemble': 0.75
            }
            
            self.logger.info("[ENHANCED-SECURITY] Ensemble models initialized successfully")
            
        except Exception as e:
            self.logger.error(f"[ENHANCED-SECURITY] Error initializing models: {e}")
            raise
    
    def train_baseline(self, feature_vectors: List[List[float]]) -> bool:
        """Train ensemble models on baseline security data"""
        try:
            if not feature_vectors or len(feature_vectors) < 20:  # Reduced from 50 to 20
                self.logger.warning(f"[ENHANCED-SECURITY] Insufficient training data: {len(feature_vectors) if feature_vectors else 0} samples (minimum: 20)")
                return False
            
            X = np.array(feature_vectors)
            self.logger.info(f"[ENHANCED-SECURITY] Training ensemble on {len(X)} samples with {X.shape[1]} features")
            
            # Train each model
            trained_models = {}
            for model_name, model in self.models.items():
                try:
                    # Scale features
                    X_scaled = self.scalers[model_name].fit_transform(X)
                    
                    # Train model
                    if model_name == 'local_outlier_factor':
                        # LOF needs different training approach
                        model.fit(X_scaled)
                        trained_models[model_name] = model
                    else:
                        model.fit(X_scaled)
                        trained_models[model_name] = model
                    
                    self.logger.info(f"[ENHANCED-SECURITY] {model_name} trained successfully")
                    
                except Exception as e:
                    self.logger.error(f"[ENHANCED-SECURITY] Error training {model_name}: {e}")
                    continue
            
            if len(trained_models) < 2:
                self.logger.error("[ENHANCED-SECURITY] Insufficient models trained")
                return False
            
            # Update models
            self.models.update(trained_models)
            
            # Calculate baseline statistics
            self._calculate_baseline_stats(X)
            
            # Calibrate thresholds if enabled
            if self.calibration_enabled:
                self._calibrate_thresholds(X)
            
            self.is_trained = True
            
            # Save models
            self._save_models()
            
            self.logger.info(f"[ENHANCED-SECURITY] Ensemble training completed: {len(trained_models)} models")
            return True
            
        except Exception as e:
            self.logger.error(f"[ENHANCED-SECURITY] Error in training: {e}")
            return False
    
    def _calculate_baseline_stats(self, X: np.ndarray):
        """Calculate baseline statistics for calibration"""
        try:
            # Get predictions from all trained models
            predictions = {}
            scores = {}
            
            for model_name, model in self.models.items():
                if hasattr(model, 'decision_function'):
                    # Check if scaler is fitted
                    if not hasattr(self.scalers[model_name], 'mean_') or self.scalers[model_name].mean_ is None:
                        self.logger.warning(f"[ENHANCED-SECURITY] Scaler for {model_name} not fitted in baseline stats, skipping")
                        continue
                    
                    X_scaled = self.scalers[model_name].transform(X)
                    pred_scores = model.decision_function(X_scaled)
                    scores[model_name] = pred_scores
                    
                    # Convert to anomaly scores (0-1)
                    if model_name == 'isolation_forest':
                        # IF: higher = more normal, convert to anomaly score
                        anomaly_scores = 1 - (pred_scores - pred_scores.min()) / (pred_scores.max() - pred_scores.min())
                    else:
                        # Other models: lower = more anomalous
                        anomaly_scores = (pred_scores.max() - pred_scores) / (pred_scores.max() - pred_scores.min())
                    
                    predictions[model_name] = anomaly_scores
            
            # Store baseline statistics
            self.baseline_stats = {
                'mean_scores': {name: np.mean(scores) for name, scores in scores.items()},
                'std_scores': {name: np.std(scores) for name, scores in scores.items()},
                'percentile_95': {name: np.percentile(scores, 95) for name, scores in scores.items()},
                'percentile_99': {name: np.percentile(scores, 99) for name, scores in scores.items()},
                'training_samples': len(X),
                'feature_count': X.shape[1],
                'timestamp': datetime.now().isoformat()
            }
            
            self.logger.info("[ENHANCED-SECURITY] Baseline statistics calculated")
            
        except Exception as e:
            self.logger.error(f"[ENHANCED-SECURITY] Error calculating baseline stats: {e}")
    
    def _calibrate_thresholds(self, X: np.ndarray):
        """Calibrate thresholds based on training data"""
        try:
            calibrated_thresholds = {}
            
            for model_name, model in self.models.items():
                if hasattr(model, 'decision_function'):
                    # Check if scaler is fitted
                    if not hasattr(self.scalers[model_name], 'mean_') or self.scalers[model_name].mean_ is None:
                        self.logger.warning(f"[ENHANCED-SECURITY] Scaler for {model_name} not fitted in calibration, skipping")
                        continue
                    
                    X_scaled = self.scalers[model_name].transform(X)
                    scores = model.decision_function(X_scaled)
                    
                    # Convert to anomaly scores
                    if model_name == 'isolation_forest':
                        anomaly_scores = 1 - (scores - scores.min()) / (scores.max() - scores.min())
                    else:
                        anomaly_scores = (scores.max() - scores) / (scores.max() - scores.min())
                    
                    # Set threshold at 95th percentile of anomaly scores
                    calibrated_thresholds[model_name] = float(np.percentile(anomaly_scores, 95))
            
            # Update thresholds
            self.thresholds.update(calibrated_thresholds)
            
            # Ensemble threshold (average of individual thresholds)
            self.thresholds['ensemble'] = float(np.mean(list(calibrated_thresholds.values())))
            
            self.logger.info(f"[ENHANCED-SECURITY] Thresholds calibrated: {self.thresholds}")
            
        except Exception as e:
            self.logger.error(f"[ENHANCED-SECURITY] Error calibrating thresholds: {e}")
    
    def score(self, features: List[float]) -> Dict[str, Any]:
        """Score security features using ensemble models"""
        try:
            if not self.is_trained or not self.models:
                return {
                    "ai_security_available": False,
                    "ai_score": 0.0,
                    "ai_alert": False,
                    "ensemble_details": {}
                }
            
            X = np.array([features])
            ensemble_scores = {}
            individual_alerts = {}
            weighted_score = 0.0
            
            # Get predictions from each model
            for model_name, model in self.models.items():
                try:
                    # Check if scaler is fitted
                    if not hasattr(self.scalers[model_name], 'mean_') or self.scalers[model_name].mean_ is None:
                        self.logger.warning(f"[ENHANCED-SECURITY] Scaler for {model_name} not fitted, skipping")
                        continue
                    
                    X_scaled = self.scalers[model_name].transform(X)
                    
                    if hasattr(model, 'decision_function'):
                        score = model.decision_function(X_scaled)[0]
                        
                        # Convert to anomaly score (0-1)
                        if model_name == 'isolation_forest':
                            # IF: higher = more normal
                            anomaly_score = max(0.0, min(1.0, 0.5 - score))
                        else:
                            # Other models: lower = more anomalous
                            anomaly_score = max(0.0, min(1.0, 0.5 - score))
                        
                        ensemble_scores[model_name] = float(anomaly_score)
                        
                        # Check individual alert
                        threshold = self.thresholds.get(model_name, 0.8)
                        individual_alerts[model_name] = anomaly_score >= threshold
                        
                        # Add to weighted score
                        weight = self.ensemble_weights.get(model_name, 0.25)
                        weighted_score += anomaly_score * weight
                        
                except Exception as e:
                    self.logger.warning(f"[ENHANCED-SECURITY] Error scoring with {model_name}: {e}")
                    ensemble_scores[model_name] = 0.0
                    individual_alerts[model_name] = False
            
            # Final ensemble decision
            ensemble_threshold = self.thresholds.get('ensemble', 0.75)
            ensemble_alert = weighted_score >= ensemble_threshold
            
            # Calculate confidence
            alerting_models = sum(individual_alerts.values())
            total_models = len(individual_alerts)
            confidence = alerting_models / total_models if total_models > 0 else 0.0
            
            # Update prediction history
            self._update_prediction_history(weighted_score, ensemble_alert)
            
            return {
                "ai_security_available": True,
                "ai_score": float(weighted_score),
                "ai_alert": ensemble_alert,
                "confidence": float(confidence),
                "ensemble_details": {
                    "individual_scores": ensemble_scores,
                    "individual_alerts": individual_alerts,
                    "alerting_models": alerting_models,
                    "total_models": total_models,
                    "ensemble_threshold": ensemble_threshold,
                    "weights": self.ensemble_weights
                }
            }
            
        except Exception as e:
            self.logger.error(f"[ENHANCED-SECURITY] Error in scoring: {e}")
            return {
                "ai_security_available": False,
                "ai_score": 0.0,
                "ai_alert": False,
                "ensemble_details": {}
            }
    
    def _update_prediction_history(self, score: float, alert: bool):
        """Update prediction history for adaptive learning"""
        try:
            self.prediction_history.append({
                'timestamp': datetime.now().isoformat(),
                'score': score,
                'alert': alert
            })
            
            # Keep only recent history
            if len(self.prediction_history) > self.max_history_size:
                self.prediction_history = self.prediction_history[-self.max_history_size:]
                
        except Exception as e:
            self.logger.warning(f"[ENHANCED-SECURITY] Error updating prediction history: {e}")
    
    def adaptive_calibration(self) -> bool:
        """Perform adaptive calibration based on recent predictions"""
        try:
            if len(self.prediction_history) < 100:
                return False
            
            recent_predictions = self.prediction_history[-100:]
            recent_scores = [p['score'] for p in recent_predictions]
            
            # Check if recalibration is needed
            current_threshold = self.thresholds.get('ensemble', 0.75)
            score_std = np.std(recent_scores)
            score_mean = np.mean(recent_scores)
            
            # If scores are consistently high/low, adjust threshold
            if score_mean > current_threshold + 0.1:
                new_threshold = min(0.9, current_threshold + 0.05)
                self.thresholds['ensemble'] = new_threshold
                self.logger.info(f"[ENHANCED-SECURITY] Threshold adjusted: {current_threshold} -> {new_threshold}")
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"[ENHANCED-SECURITY] Error in adaptive calibration: {e}")
            return False
    
    def _save_models(self):
        """Save trained models and configuration"""
        try:
            # Save individual models
            for model_name, model in self.models.items():
                model_path = self.model_paths.get(model_name, f'models/security_{model_name}.pkl')
                os.makedirs(os.path.dirname(model_path), exist_ok=True)
                
                with open(model_path, 'wb') as f:
                    pickle.dump(model, f)
                
                # Save scaler
                scaler_path = model_path.replace('.pkl', '_scaler.pkl')
                with open(scaler_path, 'wb') as f:
                    pickle.dump(self.scalers[model_name], f)
            
            # Save configuration
            config_path = 'models/enhanced_security_config.json'
            config_data = {
                'thresholds': self.thresholds,
                'ensemble_weights': self.ensemble_weights,
                'baseline_stats': self.baseline_stats,
                'is_trained': self.is_trained,
                'timestamp': datetime.now().isoformat()
            }
            
            with open(config_path, 'w') as f:
                json.dump(config_data, f, indent=2)
            
            self.logger.info("[ENHANCED-SECURITY] Models and configuration saved")
            
        except Exception as e:
            self.logger.error(f"[ENHANCED-SECURITY] Error saving models: {e}")
    
    def load_models(self) -> bool:
        """Load trained models and configuration"""
        try:
            # Load configuration
            config_path = 'models/enhanced_security_config.json'
            if not os.path.exists(config_path):
                return False
            
            with open(config_path, 'r') as f:
                config_data = json.load(f)
            
            self.thresholds = config_data.get('thresholds', self.thresholds)
            self.ensemble_weights = config_data.get('ensemble_weights', self.ensemble_weights)
            self.baseline_stats = config_data.get('baseline_stats', {})
            self.is_trained = config_data.get('is_trained', False)
            
            # Load individual models
            loaded_models = {}
            for model_name in self.models.keys():
                model_path = self.model_paths.get(model_name, f'models/security_{model_name}.pkl')
                scaler_path = model_path.replace('.pkl', '_scaler.pkl')
                
                if os.path.exists(model_path) and os.path.exists(scaler_path):
                    with open(model_path, 'rb') as f:
                        loaded_models[model_name] = pickle.load(f)
                    
                    with open(scaler_path, 'rb') as f:
                        self.scalers[model_name] = pickle.load(f)
            
            if loaded_models:
                self.models.update(loaded_models)
                self.logger.info(f"[ENHANCED-SECURITY] Loaded {len(loaded_models)} models")
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"[ENHANCED-SECURITY] Error loading models: {e}")
            return False
    
    def get_model_status(self) -> Dict[str, Any]:
        """Get status of ensemble models"""
        return {
            'is_trained': self.is_trained,
            'models_loaded': len([m for m in self.models.values() if hasattr(m, 'decision_function')]),
            'total_models': len(self.models),
            'thresholds': self.thresholds,
            'ensemble_weights': self.ensemble_weights,
            'baseline_stats': self.baseline_stats,
            'prediction_history_size': len(self.prediction_history),
            'calibration_enabled': self.calibration_enabled
        }
