"""
Advanced Self-Learning System
Incorporating improvements from recent research papers
"""

import json
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import logging
import os
from collections import defaultdict
from sklearn.cluster import KMeans
from sklearn.metrics import silhouette_score
import joblib

class AdvancedSelfLearningSystem:
    """
    Advanced Self-Learning System incorporating:
    - Proactive healing mechanisms
    - Predictive maintenance capabilities
    - Transfer learning for better generalization
    - Attention fusion for pattern recognition
    """
    
    def __init__(self, learning_path: str = "learning_data/"):
        self.learning_path = learning_path
        self.logger = self._setup_logger()
        
        # Learning components
        self.attack_patterns = {}
        self.feature_importance = {}
        self.signature_database = []
        self.prediction_models = {}
        
        # Proactive healing components
        self.proactive_thresholds = {}
        self.predictive_models = {}
        self.maintenance_schedule = {}
        
        # Transfer learning components
        self.domain_adaptation = True
        self.transfer_learning_enabled = True
        self.source_domain_data = []
        self.target_domain_data = []
        
        # Attention fusion components
        self.attention_fusion = True
        self.attention_weights = {}
        self.pattern_attention = {}
        
        # Create learning directories
        os.makedirs(learning_path, exist_ok=True)
        os.makedirs(f"{learning_path}/patterns", exist_ok=True)
        os.makedirs(f"{learning_path}/signatures", exist_ok=True)
        os.makedirs(f"{learning_path}/predictions", exist_ok=True)
        os.makedirs(f"{learning_path}/proactive", exist_ok=True)
    
    def _setup_logger(self) -> logging.Logger:
        """Setup logger for advanced self-learning system"""
        logger = logging.getLogger('AdvancedSelfLearningSystem')
        logger.setLevel(logging.INFO)
        
        handler = logging.FileHandler('logs/advanced_self_learning.log')
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
        return logger
    
    def learn_from_attack(self, attack_data: Dict[str, Any]) -> bool:
        """
        Advanced learning from attack with multiple improvements
        """
        try:
            self.logger.info("Starting advanced learning from attack...")
            
            # 1. Extract attack pattern with attention fusion
            attack_pattern = self._extract_advanced_attack_pattern(attack_data)
            
            # 2. Update feature importance with attention weights
            self._update_advanced_feature_importance(attack_data)
            
            # 3. Generate signature with transfer learning
            new_signature = self._generate_advanced_signature(attack_pattern, attack_data)
            
            # 4. Proactive healing analysis
            self._analyze_proactive_healing_opportunities(attack_data)
            
            # 5. Predictive maintenance update
            self._update_predictive_maintenance(attack_data)
            
            # 6. Transfer learning update
            if self.transfer_learning_enabled:
                self._update_transfer_learning(attack_data)
            
            # 7. Save advanced learning data
            self._save_advanced_learning_data(attack_pattern, new_signature, attack_data)
            
            # 8. Update ML models with new knowledge
            self._update_advanced_ml_models(attack_data)
            
            self.logger.info("Advanced learning completed successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Error in advanced self-learning: {e}")
            return False
    
    def _extract_advanced_attack_pattern(self, attack_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract attack pattern with attention fusion and temporal analysis
        """
        try:
            pattern = {
                'timestamp': datetime.now().isoformat(),
                'threat_level': attack_data.get('threat_level', 'MEDIUM'),
                'validation_score': attack_data.get('validation_score', 0),
                'features': {},
                'temporal_patterns': {},
                'behavioral_patterns': {},
                'attention_weights': {}
            }
            
            # Extract host-based patterns
            if 'host_metrics' in attack_data:
                host_metrics = attack_data['host_metrics']
                
                # System resource patterns
                if 'system' in host_metrics:
                    system = host_metrics['system']
                    pattern['features']['cpu_usage'] = system.get('cpu', {}).get('percent', 0)
                    pattern['features']['memory_usage'] = system.get('memory', {}).get('percent', 0)
                    pattern['features']['disk_usage'] = system.get('disk', {}).get('percent', 0)
                
                # Process patterns with attention
                if 'processes' in host_metrics:
                    processes = host_metrics['processes']
                    suspicious_processes = [p for p in processes if p.get('is_suspicious', False)]
                    
                    pattern['behavioral_patterns']['suspicious_process_count'] = len(suspicious_processes)
                    pattern['behavioral_patterns']['total_process_count'] = len(processes)
                    pattern['behavioral_patterns']['suspicious_ratio'] = len(suspicious_processes) / max(len(processes), 1)
                    
                    # Process attention weights
                    if suspicious_processes:
                        cpu_weights = [p.get('cpu_percent', 0) for p in suspicious_processes]
                        memory_weights = [p.get('memory_percent', 0) for p in suspicious_processes]
                        
                        pattern['attention_weights']['cpu_attention'] = np.mean(cpu_weights)
                        pattern['attention_weights']['memory_attention'] = np.mean(memory_weights)
            
            # Extract network patterns
            if 'network_metrics' in attack_data:
                network_metrics = attack_data['network_metrics']
                
                if 'features' in network_metrics:
                    features = network_metrics['features']
                    pattern['features']['total_events'] = features.get('total_events', 0)
                    pattern['features']['foreign_connections'] = features.get('foreign_connections', 0)
                    pattern['features']['unique_ports'] = len(features.get('unique_ports', []))
                    pattern['features']['suspicious_patterns'] = len(features.get('suspicious_patterns', []))
                    
                    # Network attention weights
                    pattern['attention_weights']['network_attention'] = features.get('anomaly_score', 0) / 100
            
            # Temporal pattern analysis
            pattern['temporal_patterns'] = self._analyze_temporal_patterns(attack_data)
            
            # Behavioral pattern analysis
            pattern['behavioral_patterns'].update(self._analyze_behavioral_patterns(attack_data))
            
            return pattern
            
        except Exception as e:
            self.logger.error(f"Error extracting advanced attack pattern: {e}")
            return {}
    
    def _analyze_temporal_patterns(self, attack_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze temporal patterns in the attack"""
        temporal_patterns = {}
        
        current_time = datetime.now()
        temporal_patterns['hour'] = current_time.hour
        temporal_patterns['day_of_week'] = current_time.weekday()
        temporal_patterns['is_weekend'] = current_time.weekday() >= 5
        temporal_patterns['is_business_hours'] = 9 <= current_time.hour <= 17
        
        # Cyclical encoding
        temporal_patterns['hour_sin'] = np.sin(2 * np.pi * current_time.hour / 24)
        temporal_patterns['hour_cos'] = np.cos(2 * np.pi * current_time.hour / 24)
        temporal_patterns['day_sin'] = np.sin(2 * np.pi * current_time.weekday() / 7)
        temporal_patterns['day_cos'] = np.cos(2 * np.pi * current_time.weekday() / 7)
        
        return temporal_patterns
    
    def _analyze_behavioral_patterns(self, attack_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze behavioral patterns in the attack"""
        behavioral_patterns = {}
        
        # Resource usage patterns
        if 'host_metrics' in attack_data and 'system' in attack_data['host_metrics']:
            system = attack_data['host_metrics']['system']
            cpu = system.get('cpu', {}).get('percent', 0)
            memory = system.get('memory', {}).get('percent', 0)
            
            behavioral_patterns['high_resource_usage'] = cpu > 80 or memory > 80
            behavioral_patterns['resource_spike'] = cpu > 90 or memory > 90
            behavioral_patterns['resource_anomaly'] = abs(cpu - memory) > 50
        
        # Network behavior patterns
        if 'network_metrics' in attack_data and 'features' in attack_data['network_metrics']:
            features = attack_data['network_metrics']['features']
            total_events = features.get('total_events', 0)
            foreign_connections = features.get('foreign_connections', 0)
            
            behavioral_patterns['high_network_activity'] = total_events > 100
            behavioral_patterns['suspicious_connections'] = foreign_connections > 10
            behavioral_patterns['network_anomaly'] = foreign_connections / max(total_events, 1) > 0.5
        
        return behavioral_patterns
    
    def _update_advanced_feature_importance(self, attack_data: Dict[str, Any]):
        """Update feature importance with attention mechanisms"""
        try:
            # Extract features from attack data
            features = self._extract_features_from_attack(attack_data)
            
            # Update feature importance with attention weights
            for feature_name, value in features.items():
                if feature_name not in self.feature_importance:
                    self.feature_importance[feature_name] = 0.0
                
                # Update with attention-weighted importance
                attention_weight = self.attention_weights.get(feature_name, 1.0)
                self.feature_importance[feature_name] = (
                    0.7 * self.feature_importance[feature_name] + 
                    0.3 * (value * attention_weight)
                )
            
            # Normalize feature importance
            total_importance = sum(self.feature_importance.values())
            if total_importance > 0:
                for feature in self.feature_importance:
                    self.feature_importance[feature] /= total_importance
            
        except Exception as e:
            self.logger.error(f"Error updating advanced feature importance: {e}")
    
    def _extract_features_from_attack(self, attack_data: Dict[str, Any]) -> Dict[str, float]:
        """Extract features from attack data for importance calculation"""
        features = {}
        
        # Host metrics features
        if 'host_metrics' in attack_data:
            host_metrics = attack_data['host_metrics']
            
            if 'system' in host_metrics:
                system = host_metrics['system']
                features['cpu_usage'] = system.get('cpu', {}).get('percent', 0)
                features['memory_usage'] = system.get('memory', {}).get('percent', 0)
                features['disk_usage'] = system.get('disk', {}).get('percent', 0)
            
            if 'processes' in host_metrics:
                processes = host_metrics['processes']
                features['process_count'] = len(processes)
                features['suspicious_process_count'] = sum(1 for p in processes if p.get('is_suspicious', False))
        
        # Network metrics features
        if 'network_metrics' in attack_data:
            network_metrics = attack_data['network_metrics']
            
            if 'features' in network_metrics:
                network_features = network_metrics['features']
                features['total_events'] = network_features.get('total_events', 0)
                features['foreign_connections'] = network_features.get('foreign_connections', 0)
                features['unique_ports'] = len(network_features.get('unique_ports', []))
        
        return features
    
    def _generate_advanced_signature(self, attack_pattern: Dict[str, Any], 
                                   attack_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate advanced signature with transfer learning and attention fusion
        """
        try:
            signature = {
                'id': f"sig_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                'timestamp': datetime.now().isoformat(),
                'threat_level': attack_pattern.get('threat_level', 'MEDIUM'),
                'confidence': attack_pattern.get('validation_score', 0),
                'features': attack_pattern.get('features', {}),
                'behavioral_patterns': attack_pattern.get('behavioral_patterns', {}),
                'temporal_patterns': attack_pattern.get('temporal_patterns', {}),
                'attention_weights': attack_pattern.get('attention_weights', {}),
                'transfer_learning_info': {},
                'proactive_indicators': {}
            }
            
            # Transfer learning information
            if self.transfer_learning_enabled:
                signature['transfer_learning_info'] = {
                    'source_domain_similarity': self._calculate_domain_similarity(attack_data),
                    'adaptation_confidence': self._calculate_adaptation_confidence(attack_data),
                    'cross_domain_features': self._extract_cross_domain_features(attack_data)
                }
            
            # Proactive indicators
            signature['proactive_indicators'] = {
                'early_warning_signs': self._identify_early_warning_signs(attack_data),
                'predictive_factors': self._identify_predictive_factors(attack_data),
                'maintenance_triggers': self._identify_maintenance_triggers(attack_data)
            }
            
            return signature
            
        except Exception as e:
            self.logger.error(f"Error generating advanced signature: {e}")
            return {}
    
    def _calculate_domain_similarity(self, attack_data: Dict[str, Any]) -> float:
        """Calculate similarity with source domain for transfer learning"""
        # Simplified domain similarity calculation
        similarity_score = 0.5  # Default similarity
        
        # Analyze feature similarity
        if 'host_metrics' in attack_data:
            host_features = self._extract_features_from_attack(attack_data)
            if host_features:
                # Calculate similarity with known patterns
                similarity_score = min(1.0, len(host_features) / 10.0)
        
        return similarity_score
    
    def _calculate_adaptation_confidence(self, attack_data: Dict[str, Any]) -> float:
        """Calculate confidence in domain adaptation"""
        # Simplified adaptation confidence
        confidence = 0.7  # Default confidence
        
        # Adjust based on feature quality
        if 'network_metrics' in attack_data:
            network_features = attack_data['network_metrics'].get('features', {})
            if network_features:
                confidence = min(1.0, confidence + 0.1)
        
        return confidence
    
    def _extract_cross_domain_features(self, attack_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract features that work across domains"""
        cross_domain_features = {}
        
        # Universal features that work across domains
        if 'host_metrics' in attack_data:
            host_metrics = attack_data['host_metrics']
            if 'system' in host_metrics:
                system = host_metrics['system']
                cross_domain_features['resource_utilization'] = {
                    'cpu': system.get('cpu', {}).get('percent', 0),
                    'memory': system.get('memory', {}).get('percent', 0)
                }
        
        return cross_domain_features
    
    def _identify_early_warning_signs(self, attack_data: Dict[str, Any]) -> List[str]:
        """Identify early warning signs for proactive healing"""
        early_warnings = []
        
        # Resource-based early warnings
        if 'host_metrics' in attack_data and 'system' in attack_data['host_metrics']:
            system = attack_data['host_metrics']['system']
            cpu = system.get('cpu', {}).get('percent', 0)
            memory = system.get('memory', {}).get('percent', 0)
            
            if cpu > 70:
                early_warnings.append("High CPU usage detected")
            if memory > 70:
                early_warnings.append("High memory usage detected")
        
        # Network-based early warnings
        if 'network_metrics' in attack_data and 'features' in attack_data['network_metrics']:
            features = attack_data['network_metrics']['features']
            foreign_connections = features.get('foreign_connections', 0)
            
            if foreign_connections > 5:
                early_warnings.append("Unusual foreign connections detected")
        
        return early_warnings
    
    def _identify_predictive_factors(self, attack_data: Dict[str, Any]) -> List[str]:
        """Identify predictive factors for future attacks"""
        predictive_factors = []
        
        # Temporal factors
        current_time = datetime.now()
        if current_time.hour < 6 or current_time.hour > 22:
            predictive_factors.append("Off-hours activity pattern")
        
        # Behavioral factors
        if 'host_metrics' in attack_data and 'processes' in attack_data['host_metrics']:
            processes = attack_data['host_metrics']['processes']
            suspicious_count = sum(1 for p in processes if p.get('is_suspicious', False))
            
            if suspicious_count > 0:
                predictive_factors.append("Suspicious process patterns")
        
        return predictive_factors
    
    def _identify_maintenance_triggers(self, attack_data: Dict[str, Any]) -> List[str]:
        """Identify maintenance triggers for proactive healing"""
        maintenance_triggers = []
        
        # System health triggers
        if 'host_metrics' in attack_data and 'system' in attack_data['host_metrics']:
            system = attack_data['host_metrics']['system']
            disk_usage = system.get('disk', {}).get('percent', 0)
            
            if disk_usage > 80:
                maintenance_triggers.append("High disk usage - cleanup recommended")
        
        # Performance triggers
        if 'network_metrics' in attack_data and 'features' in attack_data['network_metrics']:
            features = attack_data['network_metrics']['features']
            total_events = features.get('total_events', 0)
            
            if total_events > 1000:
                maintenance_triggers.append("High network activity - monitoring recommended")
        
        return maintenance_triggers
    
    def _analyze_proactive_healing_opportunities(self, attack_data: Dict[str, Any]):
        """Analyze opportunities for proactive healing"""
        try:
            # Update proactive thresholds
            self._update_proactive_thresholds(attack_data)
            
            # Schedule predictive maintenance
            self._schedule_predictive_maintenance(attack_data)
            
            # Update proactive healing models
            self._update_proactive_models(attack_data)
            
        except Exception as e:
            self.logger.error(f"Error analyzing proactive healing opportunities: {e}")
    
    def _update_proactive_thresholds(self, attack_data: Dict[str, Any]):
        """Update proactive healing thresholds based on attack patterns"""
        # Update thresholds based on attack characteristics
        if 'host_metrics' in attack_data and 'system' in attack_data['host_metrics']:
            system = attack_data['host_metrics']['system']
            cpu = system.get('cpu', {}).get('percent', 0)
            memory = system.get('memory', {}).get('percent', 0)
            
            # Adjust thresholds based on observed patterns
            self.proactive_thresholds['cpu_warning'] = min(80, cpu * 0.8)
            self.proactive_thresholds['memory_warning'] = min(80, memory * 0.8)
    
    def _schedule_predictive_maintenance(self, attack_data: Dict[str, Any]):
        """Schedule predictive maintenance based on attack patterns"""
        # Schedule maintenance based on temporal patterns
        current_time = datetime.now()
        
        # Schedule based on attack timing
        if current_time.hour < 6:  # Night attacks
            self.maintenance_schedule['night_maintenance'] = current_time + timedelta(hours=2)
        elif current_time.hour > 18:  # Evening attacks
            self.maintenance_schedule['evening_maintenance'] = current_time + timedelta(hours=1)
        else:  # Day attacks
            self.maintenance_schedule['day_maintenance'] = current_time + timedelta(minutes=30)
    
    def _update_proactive_models(self, attack_data: Dict[str, Any]):
        """Update proactive healing models"""
        # Update models based on attack characteristics
        attack_type = attack_data.get('threat_level', 'MEDIUM')
        
        if attack_type == 'HIGH':
            # High-threat attacks require immediate proactive measures
            self.prediction_models['immediate_proactive'] = True
        elif attack_type == 'MEDIUM':
            # Medium-threat attacks require scheduled proactive measures
            self.prediction_models['scheduled_proactive'] = True
    
    def _update_predictive_maintenance(self, attack_data: Dict[str, Any]):
        """Update predictive maintenance based on attack patterns"""
        try:
            # Analyze attack patterns for maintenance insights
            maintenance_insights = self._analyze_maintenance_insights(attack_data)
            
            # Update predictive models
            self._update_predictive_models(maintenance_insights)
            
        except Exception as e:
            self.logger.error(f"Error updating predictive maintenance: {e}")
    
    def _analyze_maintenance_insights(self, attack_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze maintenance insights from attack patterns"""
        insights = {
            'system_health': 'good',
            'performance_impact': 'low',
            'maintenance_priority': 'normal',
            'recommended_actions': []
        }
        
        # Analyze system health
        if 'host_metrics' in attack_data and 'system' in attack_data['host_metrics']:
            system = attack_data['host_metrics']['system']
            cpu = system.get('cpu', {}).get('percent', 0)
            memory = system.get('memory', {}).get('percent', 0)
            
            if cpu > 90 or memory > 90:
                insights['system_health'] = 'poor'
                insights['maintenance_priority'] = 'high'
                insights['recommended_actions'].append('System resource optimization needed')
            elif cpu > 70 or memory > 70:
                insights['system_health'] = 'fair'
                insights['maintenance_priority'] = 'medium'
                insights['recommended_actions'].append('Monitor system resources')
        
        return insights
    
    def _update_predictive_models(self, maintenance_insights: Dict[str, Any]):
        """Update predictive models based on maintenance insights"""
        # Update models based on insights
        if maintenance_insights['maintenance_priority'] == 'high':
            self.prediction_models['urgent_maintenance'] = True
        elif maintenance_insights['maintenance_priority'] == 'medium':
            self.prediction_models['scheduled_maintenance'] = True
    
    def _update_transfer_learning(self, attack_data: Dict[str, Any]):
        """Update transfer learning based on new attack data"""
        try:
            # Add to target domain data
            self.target_domain_data.append(attack_data)
            
            # Update domain adaptation models
            self._update_domain_adaptation_models()
            
        except Exception as e:
            self.logger.error(f"Error updating transfer learning: {e}")
    
    def _update_domain_adaptation_models(self):
        """Update domain adaptation models"""
        # Simplified domain adaptation update
        if len(self.target_domain_data) > 10:
            # Update adaptation models when enough target data is available
            self.domain_adaptation = True
    
    def _save_advanced_learning_data(self, attack_pattern: Dict[str, Any], 
                                   signature: Dict[str, Any], attack_data: Dict[str, Any]):
        """Save advanced learning data with all components"""
        try:
            # Save attack pattern
            pattern_file = f"{self.learning_path}/patterns/pattern_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(pattern_file, 'w') as f:
                json.dump(attack_pattern, f, indent=2)
            
            # Save signature
            signature_file = f"{self.learning_path}/signatures/signature_{signature['id']}.json"
            with open(signature_file, 'w') as f:
                json.dump(signature, f, indent=2)
            
            # Save prediction data
            prediction_data = {
                'timestamp': datetime.now().isoformat(),
                'proactive_thresholds': self.proactive_thresholds,
                'maintenance_schedule': self.maintenance_schedule,
                'prediction_models': self.prediction_models
            }
            
            prediction_file = f"{self.learning_path}/predictions/prediction_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(prediction_file, 'w') as f:
                json.dump(prediction_data, f, indent=2)
            
            # Save proactive data
            proactive_data = {
                'timestamp': datetime.now().isoformat(),
                'early_warning_signs': self._identify_early_warning_signs(attack_data),
                'predictive_factors': self._identify_predictive_factors(attack_data),
                'maintenance_triggers': self._identify_maintenance_triggers(attack_data)
            }
            
            proactive_file = f"{self.learning_path}/proactive/proactive_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(proactive_file, 'w') as f:
                json.dump(proactive_data, f, indent=2)
            
            self.logger.info("Advanced learning data saved successfully")
            
        except Exception as e:
            self.logger.error(f"Error saving advanced learning data: {e}")
    
    def _update_advanced_ml_models(self, attack_data: Dict[str, Any]):
        """Update ML models with new knowledge"""
        try:
            # Update feature importance
            self._update_feature_importance_from_attack(attack_data)
            
            # Update attention weights
            self._update_attention_weights(attack_data)
            
            # Update pattern recognition models
            self._update_pattern_recognition_models(attack_data)
            
        except Exception as e:
            self.logger.error(f"Error updating advanced ML models: {e}")
    
    def _update_feature_importance_from_attack(self, attack_data: Dict[str, Any]):
        """Update feature importance based on attack data"""
        # Extract features and update importance
        features = self._extract_features_from_attack(attack_data)
        
        for feature_name, value in features.items():
            if feature_name not in self.feature_importance:
                self.feature_importance[feature_name] = 0.0
            
            # Update with exponential moving average
            alpha = 0.1  # Learning rate
            self.feature_importance[feature_name] = (
                (1 - alpha) * self.feature_importance[feature_name] + 
                alpha * value
            )
    
    def _update_attention_weights(self, attack_data: Dict[str, Any]):
        """Update attention weights based on attack patterns"""
        # Update attention weights based on attack characteristics
        threat_level = attack_data.get('threat_level', 'MEDIUM')
        
        if threat_level == 'HIGH':
            # High-threat attacks get higher attention weights
            for feature in self.attention_weights:
                self.attention_weights[feature] = min(1.0, self.attention_weights[feature] * 1.1)
        elif threat_level == 'LOW':
            # Low-threat attacks get lower attention weights
            for feature in self.attention_weights:
                self.attention_weights[feature] = max(0.1, self.attention_weights[feature] * 0.9)
    
    def _update_pattern_recognition_models(self, attack_data: Dict[str, Any]):
        """Update pattern recognition models"""
        # Update models based on attack patterns
        attack_pattern = self._extract_advanced_attack_pattern(attack_data)
        
        # Update pattern database
        pattern_id = f"pattern_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.attack_patterns[pattern_id] = attack_pattern
    
    def get_advanced_learning_stats(self) -> Dict[str, Any]:
        """Get advanced learning statistics"""
        return {
            'total_patterns_learned': len(self.attack_patterns),
            'total_signatures_generated': len(self.signature_database),
            'feature_importance': self.feature_importance,
            'attention_weights': self.attention_weights,
            'proactive_thresholds': self.proactive_thresholds,
            'maintenance_schedule': self.maintenance_schedule,
            'prediction_models': self.prediction_models,
            'transfer_learning_enabled': self.transfer_learning_enabled,
            'domain_adaptation': self.domain_adaptation,
            'attention_fusion': self.attention_fusion,
            'learning_active': True
        }
