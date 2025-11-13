#!/usr/bin/env python3
"""
ML Classifier for H-SOAR HIDS
Machine learning classifier for event classification (benign/suspicious/malicious)
"""

import os
import json
import logging
import pickle
import pandas as pd
import numpy as np
from typing import Dict, List, Any, Optional, Tuple
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.svm import SVC
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.utils.class_weight import compute_sample_weight
import warnings
warnings.filterwarnings('ignore')

class HIDSMLClassifier:
    """
    Machine learning classifier for HIDS event classification
    """
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize ML classifier"""
        self.config = config
        self.logger = logging.getLogger('HIDSMLClassifier')
        
        # Model configuration
        self.model_type = config.get('model_type', 'ensemble')
        self.models_config = config.get('models', ['random_forest', 'gradient_boosting'])
        self.training_data_path = config.get('training_data_path', 'data/training_dataset.csv')
        self.model_save_path = config.get('model_save_path', 'models/hids_classifier.pkl')
        
        # Initialize models
        self.models = {}
        self.scalers = {}
        self.label_encoder = LabelEncoder()
        self.is_trained = False
        
        # Performance metrics
        self.performance_metrics = {}
        
        # Load existing model if available
        self._load_model()
    
    def _initialize_models(self):
        """Initialize ML models"""
        if 'random_forest' in self.models_config:
            self.models['random_forest'] = RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                min_samples_split=5,
                min_samples_leaf=2,
                random_state=42,
                n_jobs=-1,
                class_weight='balanced'  # Handle class imbalance
            )
            self.scalers['random_forest'] = StandardScaler()
        
        if 'gradient_boosting' in self.models_config:
            self.models['gradient_boosting'] = GradientBoostingClassifier(
                n_estimators=100,
                learning_rate=0.1,
                max_depth=6,
                random_state=42
            )
            self.scalers['gradient_boosting'] = StandardScaler()
        
        if 'svm' in self.models_config:
            self.models['svm'] = SVC(
                kernel='rbf',
                C=1.0,
                gamma='scale',
                probability=True,
                random_state=42,
                class_weight='balanced'  # Handle class imbalance
            )
            self.scalers['svm'] = StandardScaler()
        
        self.logger.info(f"Initialized {len(self.models)} models: {list(self.models.keys())}")
    
    def train(self, dataset_path: str = None) -> Dict[str, Any]:
        """Train ML models"""
        try:
            # Use provided dataset or default
            if dataset_path is None:
                dataset_path = self.training_data_path
            
            self.logger.info(f"Training models with dataset: {dataset_path}")
            
            # Load dataset
            if not os.path.exists(dataset_path):
                return {
                    'success': False,
                    'error': f'Dataset file not found: {dataset_path}',
                    'suggestion': 'Run dataset collection first or provide valid dataset path'
                }
            
            # Load and preprocess data
            df = pd.read_csv(dataset_path)
            self.logger.info(f"Loaded dataset with {len(df)} samples and {len(df.columns)} features")
            
            # Prepare features and labels
            X, y = self._prepare_data(df)
            
            if len(X) == 0:
                return {
                    'success': False,
                    'error': 'No valid samples found in dataset',
                    'suggestion': 'Check dataset format and feature extraction'
                }
            
            # Initialize models if not already done
            if not self.models:
                self._initialize_models()
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42, stratify=y
            )

            self.logger.info(f"Training set: {len(X_train)} samples")
            self.logger.info(f"Test set: {len(X_test)} samples")

            # Compute sample weights to balance classes
            sample_weights = compute_sample_weight(class_weight='balanced', y=y_train)

            # Train each model
            model_results = {}
            for model_name, model in self.models.items():
                self.logger.info(f"Training {model_name}...")

                # Scale features
                scaler = self.scalers[model_name]
                X_train_scaled = scaler.fit_transform(X_train)
                X_test_scaled = scaler.transform(X_test)

                # Train model with class-balanced weights when supported
                try:
                    model.fit(X_train_scaled, y_train, sample_weight=sample_weights)
                except TypeError:
                    model.fit(X_train_scaled, y_train)
                
                # Evaluate model
                y_pred = model.predict(X_test_scaled)
                accuracy = accuracy_score(y_test, y_pred)
                
                # Cross-validation
                cv_scores = cross_val_score(model, X_train_scaled, y_train, cv=5)
                
                model_results[model_name] = {
                    'accuracy': accuracy,
                    'cv_mean': cv_scores.mean(),
                    'cv_std': cv_scores.std(),
                    'test_predictions': y_pred,
                    'test_labels': y_test
                }
                
                self.logger.info(f"{model_name} - Accuracy: {accuracy:.3f}, CV: {cv_scores.mean():.3f} ± {cv_scores.std():.3f}")
            
            # Ensemble prediction
            ensemble_predictions = self._ensemble_predict(X_test_scaled)
            ensemble_accuracy = accuracy_score(y_test, ensemble_predictions)
            
            # Calculate detailed metrics
            self.performance_metrics = self._calculate_metrics(y_test, ensemble_predictions)
            
            # Mark as trained BEFORE saving
            self.is_trained = True
            
            # Save models (now with is_trained=True)
            self._save_model()
            
            return {
                'success': True,
                'accuracy': ensemble_accuracy,
                'precision': self.performance_metrics.get('precision', 0),
                'recall': self.performance_metrics.get('recall', 0),
                'f1_score': self.performance_metrics.get('f1_score', 0),
                'model_results': model_results,
                'ensemble_accuracy': ensemble_accuracy,
                'confusion_matrix': self.performance_metrics.get('confusion_matrix', []).tolist()
            }
        
        except Exception as e:
            self.logger.error(f"Error during training: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _prepare_data(self, df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
        """Prepare features and labels from dataframe"""
        try:
            # Separate features and labels
            feature_columns = [col for col in df.columns if col != 'label']
            X = df[feature_columns].values
            
            # Encode labels
            y = self.label_encoder.fit_transform(df['label'].values)
            
            # Handle missing values
            X = np.nan_to_num(X, nan=0.0)
            
            return X, y
        
        except Exception as e:
            self.logger.error(f"Error preparing data: {e}")
            return np.array([]), np.array([])
    
    def classify(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """Classify event based on features"""
        try:
            if not self.is_trained or not self.models:
                return {
                    'success': False,
                    'error': 'Model not trained',
                    'classification': 'unknown',
                    'confidence': 0.0
                }
            
            # Convert features to array
            feature_array = self._features_to_array(features)
            
            if len(feature_array) == 0:
                return {
                    'success': False,
                    'error': 'Invalid features',
                    'classification': 'unknown',
                    'confidence': 0.0
                }
            
            # Get predictions from all models
            predictions = {}
            confidences = {}
            
            for model_name, model in self.models.items():
                scaler = self.scalers[model_name]
                features_scaled = scaler.transform(feature_array.reshape(1, -1))
                
                # Get prediction and probability
                prediction = model.predict(features_scaled)[0]
                probabilities = model.predict_proba(features_scaled)[0]
                
                predictions[model_name] = prediction
                confidences[model_name] = max(probabilities)
            
            # Ensemble prediction
            ensemble_prediction = self._ensemble_classify(predictions, confidences)
            
            # Get confidence
            avg_confidence = np.mean(list(confidences.values()))
            
            # Decode prediction
            classification = self.label_encoder.inverse_transform([ensemble_prediction])[0]
            
            return {
                'success': True,
                'classification': classification,
                'confidence': avg_confidence,
                'individual_predictions': predictions,
                'individual_confidences': confidences,
                'ensemble_prediction': ensemble_prediction
            }
        
        except Exception as e:
            self.logger.error(f"Error during classification: {e}")
            return {
                'success': False,
                'error': str(e),
                'classification': 'unknown',
                'confidence': 0.0
            }
    
    def _features_to_array(self, features: Dict[str, Any]) -> np.ndarray:
        """Convert features dictionary to numpy array"""
        try:
            # Define feature order (should match training data)
            feature_order = [
                'event_type', 'action',
                'filepath_criticality', 'filepath_depth', 'filepath_suspicious',
                'file_extension_suspicious', 'is_system_directory', 'is_web_directory', 'is_temp_directory',
                'process_suspicious', 'process_is_shell', 'process_is_web_server', 'process_is_system',
                'process_name_length',
                'user_is_root', 'user_is_system', 'user_is_web',
                'action_is_write', 'action_is_delete', 'action_is_execute', 'action_is_attribute',
                'hour_of_day', 'day_of_week'
            ]
            
            feature_array = []
            for feature_name in feature_order:
                value = features.get(feature_name, 0)
                if isinstance(value, (int, float)):
                    feature_array.append(value)
                else:
                    feature_array.append(0)
            
            return np.array(feature_array)
        
        except Exception as e:
            self.logger.error(f"Error converting features to array: {e}")
            return np.array([])
    
    def _ensemble_classify(self, predictions: Dict[str, int], confidences: Dict[str, float]) -> int:
        """Perform ensemble classification"""
        try:
            # Weighted voting based on confidence
            weighted_votes = {}
            
            for model_name, prediction in predictions.items():
                confidence = confidences[model_name]
                if prediction not in weighted_votes:
                    weighted_votes[prediction] = 0
                weighted_votes[prediction] += confidence
            
            # Return prediction with highest weighted vote
            return max(weighted_votes.items(), key=lambda x: x[1])[0]
        
        except Exception as e:
            self.logger.error(f"Error in ensemble classification: {e}")
            return 0
    
    def _ensemble_predict(self, X_test_scaled: np.ndarray) -> np.ndarray:
        """Perform ensemble prediction on test set"""
        try:
            predictions = []
            
            for model_name, model in self.models.items():
                scaler = self.scalers[model_name]
                X_scaled = scaler.transform(X_test_scaled)
                pred = model.predict(X_scaled)
                predictions.append(pred)
            
            # Simple majority voting
            predictions_array = np.array(predictions)
            ensemble_pred = []
            
            for i in range(predictions_array.shape[1]):
                votes = predictions_array[:, i]
                ensemble_pred.append(np.bincount(votes).argmax())
            
            return np.array(ensemble_pred)
        
        except Exception as e:
            self.logger.error(f"Error in ensemble prediction: {e}")
            return np.array([])
    
    def _calculate_metrics(self, y_true: np.ndarray, y_pred: np.ndarray) -> Dict[str, Any]:
        """Calculate detailed performance metrics"""
        try:
            # Classification report
            report = classification_report(y_true, y_pred, output_dict=True)
            
            # Confusion matrix
            cm = confusion_matrix(y_true, y_pred)
            
            # Calculate metrics for each class
            metrics = {}
            for class_name in self.label_encoder.classes_:
                class_idx = self.label_encoder.transform([class_name])[0]
                if class_name in report:
                    metrics[class_name] = {
                        'precision': report[class_name]['precision'],
                        'recall': report[class_name]['recall'],
                        'f1_score': report[class_name]['f1-score'],
                        'support': report[class_name]['support']
                    }
            
            return {
                'precision': report['macro avg']['precision'],
                'recall': report['macro avg']['recall'],
                'f1_score': report['macro avg']['f1-score'],
                'accuracy': report['accuracy'],
                'confusion_matrix': cm,
                'class_metrics': metrics
            }
        
        except Exception as e:
            self.logger.error(f"Error calculating metrics: {e}")
            return {}
    
    def _save_model(self):
        """Save trained models"""
        try:
            # Create models directory
            os.makedirs(os.path.dirname(self.model_save_path), exist_ok=True)
            
            # Save models and scalers
            model_data = {
                'models': self.models,
                'scalers': self.scalers,
                'label_encoder': self.label_encoder,
                'performance_metrics': self.performance_metrics,
                'is_trained': self.is_trained
            }
            
            with open(self.model_save_path, 'wb') as f:
                pickle.dump(model_data, f)
            
            self.logger.info(f"Models saved to {self.model_save_path}")
        
        except Exception as e:
            self.logger.error(f"Error saving models: {e}")
    
    def _load_model(self):
        """Load trained models"""
        try:
            if os.path.exists(self.model_save_path):
                with open(self.model_save_path, 'rb') as f:
                    model_data = pickle.load(f)
                
                self.models = model_data.get('models', {})
                self.scalers = model_data.get('scalers', {})
                self.label_encoder = model_data.get('label_encoder', LabelEncoder())
                self.performance_metrics = model_data.get('performance_metrics', {})
                self.is_trained = model_data.get('is_trained', False)
                
                self.logger.info(f"Models loaded from {self.model_save_path}")
                self.logger.info(f"Model status: {'Trained' if self.is_trained else 'Not trained'}")
        
        except Exception as e:
            self.logger.warning(f"Could not load models: {e}")
            self.models = {}
            self.scalers = {}
            self.is_trained = False
    
    def get_status(self) -> Dict[str, Any]:
        """Get classifier status"""
        return {
            'trained': self.is_trained,
            'model_type': self.model_type,
            'models_available': list(self.models.keys()),
            'performance_metrics': self.performance_metrics,
            'model_save_path': self.model_save_path
        }
    
    def get_feature_importance(self) -> Dict[str, Any]:
        """Get feature importance from Random Forest"""
        try:
            if 'random_forest' in self.models and self.is_trained:
                rf_model = self.models['random_forest']
                feature_names = [
                    'event_type', 'action',
                    'filepath_criticality', 'filepath_depth', 'filepath_suspicious',
                    'file_extension_suspicious', 'is_system_directory', 'is_web_directory', 'is_temp_directory',
                    'process_suspicious', 'process_is_shell', 'process_is_web_server', 'process_is_system',
                    'process_name_length',
                    'user_is_root', 'user_is_system', 'user_is_web',
                    'action_is_write', 'action_is_delete', 'action_is_execute', 'action_is_attribute',
                    'hour_of_day', 'day_of_week'
                ]
                
                importance = rf_model.feature_importances_
                feature_importance = dict(zip(feature_names, importance))
                
                # Sort by importance
                sorted_importance = dict(sorted(feature_importance.items(), key=lambda x: x[1], reverse=True))
                
                return sorted_importance
            
            return {}
        
        except Exception as e:
            self.logger.error(f"Error getting feature importance: {e}")
            return {}
