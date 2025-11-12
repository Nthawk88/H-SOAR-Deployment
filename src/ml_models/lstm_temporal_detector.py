"""
LSTM Temporal Pattern Detection
Advanced LSTM-based temporal anomaly detection for time series data
"""

import numpy as np
import pandas as pd
import logging
import time
import pickle
import os
from typing import Dict, List, Any, Optional, Tuple, Union
from dataclasses import dataclass
from datetime import datetime, timedelta
import threading
from collections import deque
import warnings
warnings.filterwarnings('ignore')

# Suppress TensorFlow warnings
import os
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
import warnings
warnings.filterwarnings('ignore')

# Try to import TensorFlow/Keras, fallback to sklearn if not available
try:
    import tensorflow as tf
    tf.get_logger().setLevel('ERROR')
    tf.autograph.set_verbosity(0)
    from tensorflow.keras.models import Sequential, Model
    from tensorflow.keras.layers import LSTM, Dense, Dropout, Input, TimeDistributed, Bidirectional
    from tensorflow.keras.optimizers import Adam
    from tensorflow.keras.callbacks import EarlyStopping, ReduceLROnPlateau
    from tensorflow.keras.utils import to_categorical
    TENSORFLOW_AVAILABLE = True
except ImportError:
    TENSORFLOW_AVAILABLE = False
    # Fallback to sklearn for basic functionality
    from sklearn.neural_network import MLPRegressor
    from sklearn.preprocessing import StandardScaler

from sklearn.preprocessing import MinMaxScaler
from sklearn.metrics import mean_squared_error, mean_absolute_error
import joblib


@dataclass
class TemporalPattern:
    """Temporal pattern data structure"""
    pattern_id: str
    pattern_type: str
    sequence_length: int
    features: List[str]
    anomaly_threshold: float
    confidence: float
    created_at: datetime
    last_seen: datetime
    frequency: int = 0


@dataclass
class LSTMPrediction:
    """LSTM prediction result"""
    timestamp: datetime
    predicted_values: List[float]
    actual_values: List[float]
    anomaly_score: float
    confidence: float
    pattern_type: str
    is_anomaly: bool


class LSTMTemporalDetector:
    """
    LSTM-based temporal pattern detector with:
    - Multi-variate time series analysis
    - Pattern recognition and classification
    - Anomaly detection and scoring
    - Adaptive learning and retraining
    - Memory-efficient processing
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Configuration
        self.sequence_length = config.get('sequence_length', 60)  # 60 time steps
        self.feature_count = config.get('feature_count', 10)
        self.hidden_units = config.get('hidden_units', 50)
        self.dropout_rate = config.get('dropout_rate', 0.2)
        self.learning_rate = config.get('learning_rate', 0.001)
        self.batch_size = config.get('batch_size', 32)
        self.epochs = config.get('epochs', 100)
        self.validation_split = config.get('validation_split', 0.2)
        
        # Model configuration
        self.model_type = config.get('model_type', 'autoencoder')  # 'autoencoder', 'predictor', 'classifier'
        self.use_bidirectional = config.get('use_bidirectional', True)
        self.use_attention = config.get('use_attention', False)
        
        # Anomaly detection
        self.anomaly_threshold = config.get('anomaly_threshold', 0.1)
        self.threshold_percentile = config.get('threshold_percentile', 95)
        self.min_samples_for_training = config.get('min_samples_for_training', 1000)
        
        # Data management
        self.data_buffer = deque(maxlen=self.sequence_length * 10)
        self.scaler = MinMaxScaler()
        self.feature_names = []
        
        # Model components
        self.model = None
        self.is_trained = False
        self.training_history = []
        
        # Pattern recognition
        self.known_patterns = {}
        self.pattern_counter = 0
        
        # Performance tracking
        self.performance_metrics = {
            'total_predictions': 0,
            'correct_predictions': 0,
            'false_positives': 0,
            'false_negatives': 0,
            'average_prediction_time': 0.0,
            'model_accuracy': 0.0
        }
        
        # Threading
        self.lock = threading.RLock()
        self.retraining_enabled = config.get('retraining_enabled', True)
        self.retraining_interval = config.get('retraining_interval', 3600)  # 1 hour
        self.retraining_thread = None
        
        # Initialize
        self._initialize_model()
        if self.retraining_enabled:
            self._start_retraining_thread()
        
        self.logger.info(f"[LSTM-TEMPORAL] LSTM temporal detector initialized (TensorFlow: {TENSORFLOW_AVAILABLE})")
    
    def _initialize_model(self):
        """Initialize LSTM model"""
        try:
            if TENSORFLOW_AVAILABLE:
                self._create_tensorflow_model()
            else:
                self._create_sklearn_model()
                
        except Exception as e:
            self.logger.error(f"[LSTM-TEMPORAL] Error initializing model: {e}")
            self._create_sklearn_model()  # Fallback
    
    def _create_tensorflow_model(self):
        """Create TensorFlow/Keras LSTM model"""
        try:
            if self.model_type == 'autoencoder':
                self.model = self._create_autoencoder_model()
            elif self.model_type == 'predictor':
                self.model = self._create_predictor_model()
            elif self.model_type == 'classifier':
                self.model = self._create_classifier_model()
            else:
                self.model = self._create_autoencoder_model()  # Default
            
            # Compile model
            self.model.compile(
                optimizer=Adam(learning_rate=self.learning_rate),
                loss='mse' if self.model_type != 'classifier' else 'categorical_crossentropy',
                metrics=['mae'] if self.model_type != 'classifier' else ['accuracy']
            )
            
            self.logger.info(f"[LSTM-TEMPORAL] Created TensorFlow {self.model_type} model")
            
        except Exception as e:
            self.logger.error(f"[LSTM-TEMPORAL] Error creating TensorFlow model: {e}")
            raise
    
    def _create_autoencoder_model(self):
        """Create LSTM autoencoder model"""
        try:
            # Encoder
            encoder_input = Input(shape=(self.sequence_length, self.feature_count))
            
            if self.use_bidirectional:
                encoder_lstm = Bidirectional(LSTM(self.hidden_units, return_sequences=True))(encoder_input)
                encoder_lstm = Bidirectional(LSTM(self.hidden_units // 2, return_sequences=False))(encoder_lstm)
            else:
                encoder_lstm = LSTM(self.hidden_units, return_sequences=True)(encoder_input)
                encoder_lstm = LSTM(self.hidden_units // 2, return_sequences=False)(encoder_lstm)
            
            encoder_output = Dropout(self.dropout_rate)(encoder_lstm)
            
            # Decoder
            decoder_input = Input(shape=(self.hidden_units // 2,))
            decoder_lstm = LSTM(self.hidden_units // 2, return_sequences=True)(decoder_input)
            decoder_lstm = LSTM(self.hidden_units, return_sequences=True)(decoder_lstm)
            decoder_output = TimeDistributed(Dense(self.feature_count))(decoder_lstm)
            
            # Autoencoder model
            autoencoder = Model([encoder_input, decoder_input], decoder_output)
            
            return autoencoder
            
        except Exception as e:
            self.logger.error(f"[LSTM-TEMPORAL] Error creating autoencoder: {e}")
            raise
    
    def _create_predictor_model(self):
        """Create LSTM predictor model"""
        try:
            model = Sequential()
            
            if self.use_bidirectional:
                model.add(Bidirectional(LSTM(self.hidden_units, return_sequences=True), 
                                      input_shape=(self.sequence_length, self.feature_count)))
                model.add(Bidirectional(LSTM(self.hidden_units // 2, return_sequences=False)))
            else:
                model.add(LSTM(self.hidden_units, return_sequences=True, 
                             input_shape=(self.sequence_length, self.feature_count)))
                model.add(LSTM(self.hidden_units // 2, return_sequences=False))
            
            model.add(Dropout(self.dropout_rate))
            model.add(Dense(self.feature_count))
            
            return model
            
        except Exception as e:
            self.logger.error(f"[LSTM-TEMPORAL] Error creating predictor: {e}")
            raise
    
    def _create_classifier_model(self):
        """Create LSTM classifier model"""
        try:
            model = Sequential()
            
            if self.use_bidirectional:
                model.add(Bidirectional(LSTM(self.hidden_units, return_sequences=True), 
                                      input_shape=(self.sequence_length, self.feature_count)))
                model.add(Bidirectional(LSTM(self.hidden_units // 2, return_sequences=False)))
            else:
                model.add(LSTM(self.hidden_units, return_sequences=True, 
                             input_shape=(self.sequence_length, self.feature_count)))
                model.add(LSTM(self.hidden_units // 2, return_sequences=False))
            
            model.add(Dropout(self.dropout_rate))
            model.add(Dense(2, activation='softmax'))  # Binary classification
            
            return model
            
        except Exception as e:
            self.logger.error(f"[LSTM-TEMPORAL] Error creating classifier: {e}")
            raise
    
    def _create_sklearn_model(self):
        """Create sklearn fallback model"""
        try:
            self.model = MLPRegressor(
                hidden_layer_sizes=(self.hidden_units, self.hidden_units // 2),
                activation='relu',
                solver='adam',
                alpha=0.001,
                batch_size=self.batch_size,
                learning_rate='adaptive',
                max_iter=self.epochs,
                random_state=42
            )
            
            self.logger.info("[LSTM-TEMPORAL] Created sklearn fallback model")
            
        except Exception as e:
            self.logger.error(f"[LSTM-TEMPORAL] Error creating sklearn model: {e}")
            raise
    
    def add_data(self, data: Dict[str, Any]):
        """Add new data point to the temporal buffer"""
        try:
            with self.lock:
                # Extract features
                features = self._extract_features(data)
                
                # Add timestamp
                features['timestamp'] = datetime.now()
                
                # Add to buffer
                self.data_buffer.append(features)
                
                # Update feature names if first data point
                if not self.feature_names:
                    self.feature_names = [k for k in features.keys() if k != 'timestamp']
                    self.feature_count = len(self.feature_names)
                
        except Exception as e:
            self.logger.error(f"[LSTM-TEMPORAL] Error adding data: {e}")
    
    def _extract_features(self, data: Dict[str, Any]) -> Dict[str, float]:
        """Extract features from data"""
        try:
            features = {}
            
            # System metrics
            if 'host_metrics' in data:
                host = data['host_metrics']
                features['cpu_percent'] = host.get('cpu', {}).get('percent', 0.0)
                features['memory_percent'] = host.get('memory', {}).get('percent', 0.0)
                features['disk_percent'] = host.get('disk', {}).get('percent', 0.0)
            
            # Network metrics
            if 'network_metrics' in data:
                net = data['network_metrics']
                features['connection_count'] = net.get('connection_count', 0)
                features['foreign_connections'] = net.get('foreign_connections', 0)
                features['bytes_sent'] = net.get('bytes_sent', 0) / 1024  # KB
                features['bytes_recv'] = net.get('bytes_recv', 0) / 1024  # KB
            
            # Process metrics
            if 'process_metrics' in data:
                proc = data['process_metrics']
                features['total_processes'] = proc.get('total_processes', 0)
                features['suspicious_processes'] = proc.get('suspicious_processes', 0)
            
            # Anomaly scores
            if 'anomaly_score' in data:
                features['anomaly_score'] = data['anomaly_score']
            
            # Security indicators
            if 'security_indicators' in data:
                sec = data['security_indicators']
                features['security_score'] = sec.get('score', 0.0)
                features['threat_level'] = self._encode_threat_level(sec.get('level', 'LOW'))
            
            return features
            
        except Exception as e:
            self.logger.error(f"[LSTM-TEMPORAL] Error extracting features: {e}")
            return {}
    
    def _encode_threat_level(self, threat_level: str) -> float:
        """Encode threat level as numeric value"""
        encoding = {
            'LOW': 0.0,
            'MEDIUM': 0.5,
            'HIGH': 0.8,
            'CRITICAL': 1.0
        }
        return encoding.get(threat_level.upper(), 0.0)
    
    def train(self, data: Optional[List[Dict[str, Any]]] = None) -> bool:
        """Train the LSTM model"""
        try:
            with self.lock:
                # Prepare training data
                if data is None:
                    data = list(self.data_buffer)
                
                if len(data) < self.min_samples_for_training:
                    self.logger.warning(f"[LSTM-TEMPORAL] Insufficient data for training: {len(data)} < {self.min_samples_for_training}")
                    return False
                
                # Convert to sequences
                X, y = self._prepare_training_sequences(data)
                
                if len(X) == 0:
                    self.logger.warning("[LSTM-TEMPORAL] No valid sequences for training")
                    return False
                
                # Scale data
                X_scaled = self.scaler.fit_transform(X.reshape(-1, X.shape[-1])).reshape(X.shape)
                
                if TENSORFLOW_AVAILABLE and self.model_type != 'sklearn':
                    success = self._train_tensorflow_model(X_scaled, y)
                else:
                    success = self._train_sklearn_model(X_scaled, y)
                
                if success:
                    self.is_trained = True
                    self.logger.info(f"[LSTM-TEMPORAL] Model trained successfully with {len(X)} sequences")
                
                return success
                
        except Exception as e:
            self.logger.error(f"[LSTM-TEMPORAL] Error training model: {e}")
            return False
    
    def _prepare_training_sequences(self, data: List[Dict[str, Any]]) -> Tuple[np.ndarray, np.ndarray]:
        """Prepare training sequences from data"""
        try:
            sequences = []
            targets = []
            
            # Convert data to DataFrame for easier processing
            df = pd.DataFrame(data)
            
            if len(df) < self.sequence_length:
                return np.array([]), np.array([])
            
            # Extract feature columns
            feature_cols = [col for col in df.columns if col != 'timestamp']
            
            if not feature_cols:
                return np.array([]), np.array([])
            
            # Create sequences
            for i in range(len(df) - self.sequence_length):
                sequence = df[feature_cols].iloc[i:i + self.sequence_length].values
                target = df[feature_cols].iloc[i + self.sequence_length].values
                
                sequences.append(sequence)
                targets.append(target)
            
            return np.array(sequences), np.array(targets)
            
        except Exception as e:
            self.logger.error(f"[LSTM-TEMPORAL] Error preparing sequences: {e}")
            return np.array([]), np.array([])
    
    def _train_tensorflow_model(self, X: np.ndarray, y: np.ndarray) -> bool:
        """Train TensorFlow model"""
        try:
            # Prepare data based on model type
            if self.model_type == 'autoencoder':
                # For autoencoder, input and target are the same
                X_train = X
                y_train = X
            else:
                X_train = X
                y_train = y
            
            # Callbacks
            callbacks = [
                EarlyStopping(patience=10, restore_best_weights=True),
                ReduceLROnPlateau(factor=0.5, patience=5)
            ]
            
            # Train model
            history = self.model.fit(
                X_train, y_train,
                batch_size=self.batch_size,
                epochs=self.epochs,
                validation_split=self.validation_split,
                callbacks=callbacks,
                verbose=0
            )
            
            # Store training history
            self.training_history.append(history.history)
            
            return True
            
        except Exception as e:
            self.logger.error(f"[LSTM-TEMPORAL] Error training TensorFlow model: {e}")
            return False
    
    def _train_sklearn_model(self, X: np.ndarray, y: np.ndarray) -> bool:
        """Train sklearn model"""
        try:
            # Reshape for sklearn
            X_reshaped = X.reshape(X.shape[0], -1)
            y_reshaped = y.reshape(y.shape[0], -1)
            
            # Train model
            self.model.fit(X_reshaped, y_reshaped)
            
            return True
            
        except Exception as e:
            self.logger.error(f"[LSTM-TEMPORAL] Error training sklearn model: {e}")
            return False
    
    def predict(self, data: Optional[Dict[str, Any]] = None) -> Optional[LSTMPrediction]:
        """Make prediction using LSTM model"""
        try:
            if not self.is_trained:
                self.logger.warning("[LSTM-TEMPORAL] Model not trained, cannot make prediction")
                return None
            
            with self.lock:
                # Get recent data
                if data is None:
                    if len(self.data_buffer) < self.sequence_length:
                        return None
                    recent_data = list(self.data_buffer)[-self.sequence_length:]
                else:
                    # Add new data and get recent
                    self.add_data(data)
                    if len(self.data_buffer) < self.sequence_length:
                        return None
                    recent_data = list(self.data_buffer)[-self.sequence_length:]
                
                # Prepare input sequence
                X = self._prepare_prediction_sequence(recent_data)
                
                if X is None:
                    return None
                
                # Scale input
                X_scaled = self.scaler.transform(X.reshape(-1, X.shape[-1])).reshape(X.shape)
                
                # Make prediction
                start_time = time.time()
                
                if TENSORFLOW_AVAILABLE and self.model_type != 'sklearn':
                    prediction = self._predict_tensorflow(X_scaled)
                else:
                    prediction = self._predict_sklearn(X_scaled)
                
                prediction_time = time.time() - start_time
                
                # Calculate anomaly score
                anomaly_score = self._calculate_anomaly_score(X_scaled, prediction)
                
                # Create result
                result = LSTMPrediction(
                    timestamp=datetime.now(),
                    predicted_values=prediction.tolist() if hasattr(prediction, 'tolist') else prediction,
                    actual_values=recent_data[-1] if recent_data else [],
                    anomaly_score=anomaly_score,
                    confidence=self._calculate_confidence(anomaly_score),
                    pattern_type=self._identify_pattern_type(prediction),
                    is_anomaly=anomaly_score > self.anomaly_threshold
                )
                
                # Update performance metrics
                self._update_performance_metrics(result, prediction_time)
                
                return result
                
        except Exception as e:
            self.logger.error(f"[LSTM-TEMPORAL] Error making prediction: {e}")
            return None
    
    def _prepare_prediction_sequence(self, data: List[Dict[str, Any]]) -> Optional[np.ndarray]:
        """Prepare input sequence for prediction"""
        try:
            if len(data) < self.sequence_length:
                return None
            
            # Extract features
            features = []
            for item in data:
                feature_vector = self._extract_features(item)
                feature_values = [feature_vector.get(name, 0.0) for name in self.feature_names]
                features.append(feature_values)
            
            return np.array(features)
            
        except Exception as e:
            self.logger.error(f"[LSTM-TEMPORAL] Error preparing prediction sequence: {e}")
            return None
    
    def _predict_tensorflow(self, X: np.ndarray) -> np.ndarray:
        """Make prediction using TensorFlow model"""
        try:
            if self.model_type == 'autoencoder':
                # For autoencoder, predict reconstruction
                prediction = self.model.predict(X, verbose=0)
                return prediction[0, -1, :]  # Last timestep
            else:
                prediction = self.model.predict(X, verbose=0)
                return prediction[0]
                
        except Exception as e:
            self.logger.error(f"[LSTM-TEMPORAL] Error in TensorFlow prediction: {e}")
            return np.zeros(self.feature_count)
    
    def _predict_sklearn(self, X: np.ndarray) -> np.ndarray:
        """Make prediction using sklearn model"""
        try:
            X_reshaped = X.reshape(1, -1)
            prediction = self.model.predict(X_reshaped)
            return prediction[0]
            
        except Exception as e:
            self.logger.error(f"[LSTM-TEMPORAL] Error in sklearn prediction: {e}")
            return np.zeros(self.feature_count)
    
    def _calculate_anomaly_score(self, X: np.ndarray, prediction: np.ndarray) -> float:
        """Calculate anomaly score"""
        try:
            if self.model_type == 'autoencoder':
                # For autoencoder, calculate reconstruction error
                actual = X[0, -1, :]  # Last timestep
                error = np.mean(np.square(actual - prediction))
                return float(error)
            else:
                # For predictor, calculate prediction error
                actual = X[0, -1, :]  # Last timestep
                error = np.mean(np.abs(actual - prediction))
                return float(error)
                
        except Exception as e:
            self.logger.error(f"[LSTM-TEMPORAL] Error calculating anomaly score: {e}")
            return 0.0
    
    def _calculate_confidence(self, anomaly_score: float) -> float:
        """Calculate prediction confidence"""
        try:
            # Higher anomaly score = lower confidence
            confidence = max(0.0, 1.0 - anomaly_score)
            return confidence
            
        except Exception as e:
            self.logger.error(f"[LSTM-TEMPORAL] Error calculating confidence: {e}")
            return 0.0
    
    def _identify_pattern_type(self, prediction: np.ndarray) -> str:
        """Identify pattern type from prediction"""
        try:
            # Simple pattern classification based on prediction values
            if np.mean(prediction) > 0.8:
                return "high_activity"
            elif np.mean(prediction) < 0.2:
                return "low_activity"
            elif np.std(prediction) > 0.3:
                return "volatile"
            else:
                return "normal"
                
        except Exception as e:
            self.logger.error(f"[LSTM-TEMPORAL] Error identifying pattern type: {e}")
            return "unknown"
    
    def _update_performance_metrics(self, result: LSTMPrediction, prediction_time: float):
        """Update performance metrics"""
        try:
            self.performance_metrics['total_predictions'] += 1
            self.performance_metrics['average_prediction_time'] = (
                (self.performance_metrics['average_prediction_time'] * (self.performance_metrics['total_predictions'] - 1) + 
                 prediction_time) / self.performance_metrics['total_predictions']
            )
            
            # Update accuracy metrics (simplified)
            if result.is_anomaly and result.anomaly_score > 0.5:
                self.performance_metrics['correct_predictions'] += 1
            elif not result.is_anomaly and result.anomaly_score < 0.3:
                self.performance_metrics['correct_predictions'] += 1
            
            # Calculate model accuracy
            if self.performance_metrics['total_predictions'] > 0:
                self.performance_metrics['model_accuracy'] = (
                    self.performance_metrics['correct_predictions'] / 
                    self.performance_metrics['total_predictions']
                )
                
        except Exception as e:
            self.logger.error(f"[LSTM-TEMPORAL] Error updating performance metrics: {e}")
    
    def _start_retraining_thread(self):
        """Start background retraining thread"""
        try:
            def retraining_worker():
                while True:
                    try:
                        time.sleep(self.retraining_interval)
                        
                        # Check if retraining is needed
                        if self._should_retrain():
                            self.logger.info("[LSTM-TEMPORAL] Starting periodic retraining")
                            self.train()
                            
                    except Exception as e:
                        self.logger.error(f"[LSTM-TEMPORAL] Retraining thread error: {e}")
                        time.sleep(60)
            
            self.retraining_thread = threading.Thread(target=retraining_worker, daemon=True)
            self.retraining_thread.start()
            
        except Exception as e:
            self.logger.error(f"[LSTM-TEMPORAL] Error starting retraining thread: {e}")
    
    def _should_retrain(self) -> bool:
        """Determine if model should be retrained"""
        try:
            # Retrain if accuracy is low
            if self.performance_metrics['model_accuracy'] < 0.7:
                return True
            
            # Retrain if we have enough new data
            if len(self.data_buffer) > self.min_samples_for_training * 2:
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"[LSTM-TEMPORAL] Error checking retraining condition: {e}")
            return False
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get performance metrics"""
        return self.performance_metrics.copy()
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get model information"""
        try:
            info = {
                'model_type': self.model_type,
                'is_trained': self.is_trained,
                'sequence_length': self.sequence_length,
                'feature_count': self.feature_count,
                'feature_names': self.feature_names,
                'tensorflow_available': TENSORFLOW_AVAILABLE,
                'data_buffer_size': len(self.data_buffer),
                'known_patterns': len(self.known_patterns),
                'training_history_size': len(self.training_history)
            }
            
            if self.model and hasattr(self.model, 'count_params'):
                info['model_parameters'] = self.model.count_params()
            
            return info
            
        except Exception as e:
            self.logger.error(f"[LSTM-TEMPORAL] Error getting model info: {e}")
            return {}
    
    def save_model(self, filepath: str):
        """Save model to disk"""
        try:
            model_data = {
                'model': self.model,
                'scaler': self.scaler,
                'feature_names': self.feature_names,
                'config': self.config,
                'performance_metrics': self.performance_metrics,
                'is_trained': self.is_trained,
                'timestamp': datetime.now().isoformat()
            }
            
            with open(filepath, 'wb') as f:
                pickle.dump(model_data, f)
            
            self.logger.info(f"[LSTM-TEMPORAL] Model saved to {filepath}")
            
        except Exception as e:
            self.logger.error(f"[LSTM-TEMPORAL] Error saving model: {e}")
    
    def load_model(self, filepath: str) -> bool:
        """Load model from disk"""
        try:
            if not os.path.exists(filepath):
                return False
            
            with open(filepath, 'rb') as f:
                model_data = pickle.load(f)
            
            self.model = model_data['model']
            self.scaler = model_data['scaler']
            self.feature_names = model_data['feature_names']
            self.performance_metrics = model_data['performance_metrics']
            self.is_trained = model_data['is_trained']
            
            self.logger.info(f"[LSTM-TEMPORAL] Model loaded from {filepath}")
            return True
            
        except Exception as e:
            self.logger.error(f"[LSTM-TEMPORAL] Error loading model: {e}")
            return False
