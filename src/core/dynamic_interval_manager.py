"""
Dynamic Monitoring Intervals
Adaptive monitoring system that adjusts intervals based on system state
"""

import time
import logging
import threading
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
import statistics
from collections import deque


@dataclass
class IntervalProfile:
    """Monitoring interval profile for different system states"""
    name: str
    base_interval: float
    min_interval: float
    max_interval: float
    adjustment_factor: float
    conditions: List[Dict[str, Any]]
    priority: int = 1


class DynamicIntervalManager:
    """
    Dynamic monitoring interval manager with:
    - Adaptive intervals based on system state
    - Multiple interval profiles
    - Smooth transitions
    - Performance optimization
    - Learning from patterns
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Configuration
        self.base_interval = config.get('base_interval', 30.0)
        self.min_interval = config.get('min_interval', 5.0)
        self.max_interval = config.get('max_interval', 300.0)
        self.adjustment_step = config.get('adjustment_step', 0.1)
        self.smooth_transition = config.get('smooth_transition', True)
        
        # Current state
        self.current_interval = self.base_interval
        self.target_interval = self.base_interval
        self.last_adjustment = time.time()
        
        # Interval profiles
        self.profiles = {}
        self.active_profile = None
        
        # Performance tracking
        self.interval_history = deque(maxlen=100)
        self.performance_history = deque(maxlen=50)
        self.adjustment_history = deque(maxlen=20)
        
        # Learning parameters
        self.learning_enabled = config.get('learning_enabled', True)
        self.performance_threshold = config.get('performance_threshold', 0.8)
        self.stability_window = config.get('stability_window', 10)
        
        # Threading
        self.lock = threading.RLock()
        self.adjustment_thread = None
        self.running = False
        
        # Initialize profiles
        self._initialize_profiles()
        self._start_adjustment_thread()
        
        self.logger.info("[DYNAMIC-INTERVAL] Dynamic interval manager initialized")
    
    def _initialize_profiles(self):
        """Initialize predefined interval profiles"""
        try:
            # Normal operation profile
            self.profiles['normal'] = IntervalProfile(
                name='normal',
                base_interval=30.0,
                min_interval=15.0,
                max_interval=60.0,
                adjustment_factor=0.1,
                conditions=[
                    {'metric': 'anomaly_score', 'operator': '<', 'value': 30},
                    {'metric': 'threat_level', 'operator': '==', 'value': 'LOW'},
                    {'metric': 'cpu_usage', 'operator': '<', 'value': 70}
                ]
            )
            
            # High activity profile
            self.profiles['high_activity'] = IntervalProfile(
                name='high_activity',
                base_interval=15.0,
                min_interval=5.0,
                max_interval=30.0,
                adjustment_factor=0.2,
                conditions=[
                    {'metric': 'anomaly_score', 'operator': '>=', 'value': 50},
                    {'metric': 'threat_level', 'operator': 'in', 'value': ['MEDIUM', 'HIGH']},
                    {'metric': 'cpu_usage', 'operator': '>=', 'value': 70}
                ]
            )
            
            # Critical profile
            self.profiles['critical'] = IntervalProfile(
                name='critical',
                base_interval=5.0,
                min_interval=2.0,
                max_interval=10.0,
                adjustment_factor=0.5,
                conditions=[
                    {'metric': 'anomaly_score', 'operator': '>=', 'value': 80},
                    {'metric': 'threat_level', 'operator': '==', 'value': 'CRITICAL'},
                    {'metric': 'cpu_usage', 'operator': '>=', 'value': 90}
                ]
            )
            
            # Low activity profile
            self.profiles['low_activity'] = IntervalProfile(
                name='low_activity',
                base_interval=60.0,
                min_interval=30.0,
                max_interval=300.0,
                adjustment_factor=0.05,
                conditions=[
                    {'metric': 'anomaly_score', 'operator': '<', 'value': 20},
                    {'metric': 'threat_level', 'operator': '==', 'value': 'LOW'},
                    {'metric': 'cpu_usage', 'operator': '<', 'value': 50},
                    {'metric': 'memory_usage', 'operator': '<', 'value': 60}
                ]
            )
            
            # Maintenance profile
            self.profiles['maintenance'] = IntervalProfile(
                name='maintenance',
                base_interval=120.0,
                min_interval=60.0,
                max_interval=600.0,
                adjustment_factor=0.02,
                conditions=[
                    {'metric': 'maintenance_mode', 'operator': '==', 'value': True}
                ]
            )
            
            self.logger.info(f"[DYNAMIC-INTERVAL] Initialized {len(self.profiles)} interval profiles")
            
        except Exception as e:
            self.logger.error(f"[DYNAMIC-INTERVAL] Error initializing profiles: {e}")
    
    def update_system_state(self, metrics: Dict[str, Any]):
        """Update system state and adjust interval accordingly"""
        try:
            with self.lock:
                # Determine appropriate profile
                new_profile = self._determine_profile(metrics)
                
                # Update active profile if changed
                if new_profile != self.active_profile:
                    self.active_profile = new_profile
                    self.logger.info(f"[DYNAMIC-INTERVAL] Switched to profile: {new_profile}")
                
                # Calculate target interval
                if self.active_profile:
                    self.target_interval = self._calculate_target_interval(metrics)
                else:
                    self.target_interval = self.base_interval
                
                # Record metrics for learning
                self._record_metrics(metrics)
                
                # Log interval change if significant
                if abs(self.target_interval - self.current_interval) > 5.0:
                    self.logger.info(f"[DYNAMIC-INTERVAL] Target interval: {self.target_interval:.1f}s (current: {self.current_interval:.1f}s)")
                
        except Exception as e:
            self.logger.error(f"[DYNAMIC-INTERVAL] Error updating system state: {e}")
    
    def _determine_profile(self, metrics: Dict[str, Any]) -> Optional[str]:
        """Determine which profile best matches current system state"""
        try:
            best_profile = None
            best_score = 0
            
            for profile_name, profile in self.profiles.items():
                score = self._calculate_profile_score(profile, metrics)
                if score > best_score:
                    best_score = score
                    best_profile = profile_name
            
            # Only switch if score is above threshold
            if best_score >= 0.7:
                return best_profile
            
            return None
            
        except Exception as e:
            self.logger.error(f"[DYNAMIC-INTERVAL] Error determining profile: {e}")
            return None
    
    def _calculate_profile_score(self, profile: IntervalProfile, metrics: Dict[str, Any]) -> float:
        """Calculate how well a profile matches current metrics"""
        try:
            score = 0.0
            total_conditions = len(profile.conditions)
            
            for condition in profile.conditions:
                metric_name = condition['metric']
                operator = condition['operator']
                expected_value = condition['value']
                
                if metric_name in metrics:
                    actual_value = metrics[metric_name]
                    
                    if self._evaluate_condition(actual_value, operator, expected_value):
                        score += 1.0
            
            return score / total_conditions if total_conditions > 0 else 0.0
            
        except Exception as e:
            self.logger.error(f"[DYNAMIC-INTERVAL] Error calculating profile score: {e}")
            return 0.0
    
    def _evaluate_condition(self, actual_value: Any, operator: str, expected_value: Any) -> bool:
        """Evaluate a condition"""
        try:
            if operator == '==':
                return actual_value == expected_value
            elif operator == '!=':
                return actual_value != expected_value
            elif operator == '>':
                return actual_value > expected_value
            elif operator == '>=':
                return actual_value >= expected_value
            elif operator == '<':
                return actual_value < expected_value
            elif operator == '<=':
                return actual_value <= expected_value
            elif operator == 'in':
                return actual_value in expected_value
            elif operator == 'not_in':
                return actual_value not in expected_value
            else:
                return False
                
        except Exception as e:
            self.logger.error(f"[DYNAMIC-INTERVAL] Error evaluating condition: {e}")
            return False
    
    def _calculate_target_interval(self, metrics: Dict[str, Any]) -> float:
        """Calculate target interval based on current profile and metrics"""
        try:
            if not self.active_profile:
                return self.base_interval
            
            profile = self.profiles[self.active_profile]
            base_interval = profile.base_interval
            
            # Adjust based on specific metrics
            adjustments = []
            
            # Anomaly score adjustment
            if 'anomaly_score' in metrics:
                anomaly_score = metrics['anomaly_score']
                if anomaly_score > 80:
                    adjustments.append(0.3)  # Reduce interval by 30%
                elif anomaly_score > 60:
                    adjustments.append(0.1)  # Reduce interval by 10%
                elif anomaly_score < 20:
                    adjustments.append(-0.2)  # Increase interval by 20%
            
            # CPU usage adjustment
            if 'cpu_usage' in metrics:
                cpu_usage = metrics['cpu_usage']
                if cpu_usage > 90:
                    adjustments.append(0.4)  # Reduce interval by 40%
                elif cpu_usage > 80:
                    adjustments.append(0.2)  # Reduce interval by 20%
                elif cpu_usage < 30:
                    adjustments.append(-0.3)  # Increase interval by 30%
            
            # Memory usage adjustment
            if 'memory_usage' in metrics:
                memory_usage = metrics['memory_usage']
                if memory_usage > 90:
                    adjustments.append(0.3)  # Reduce interval by 30%
                elif memory_usage < 40:
                    adjustments.append(-0.2)  # Increase interval by 20%
            
            # Threat level adjustment
            if 'threat_level' in metrics:
                threat_level = metrics['threat_level']
                if threat_level == 'CRITICAL':
                    adjustments.append(0.5)  # Reduce interval by 50%
                elif threat_level == 'HIGH':
                    adjustments.append(0.3)  # Reduce interval by 30%
                elif threat_level == 'MEDIUM':
                    adjustments.append(0.1)  # Reduce interval by 10%
            
            # Calculate final adjustment
            if adjustments:
                avg_adjustment = statistics.mean(adjustments)
                adjusted_interval = base_interval * (1 - avg_adjustment)
            else:
                adjusted_interval = base_interval
            
            # Apply profile limits
            adjusted_interval = max(profile.min_interval, min(profile.max_interval, adjusted_interval))
            
            # Apply global limits
            adjusted_interval = max(self.min_interval, min(self.max_interval, adjusted_interval))
            
            return adjusted_interval
            
        except Exception as e:
            self.logger.error(f"[DYNAMIC-INTERVAL] Error calculating target interval: {e}")
            return self.base_interval
    
    def _record_metrics(self, metrics: Dict[str, Any]):
        """Record metrics for learning and analysis"""
        try:
            # Record interval history
            self.interval_history.append({
                'timestamp': time.time(),
                'interval': self.current_interval,
                'target_interval': self.target_interval,
                'profile': self.active_profile,
                'metrics': metrics.copy()
            })
            
            # Record performance metrics
            if 'response_time' in metrics:
                self.performance_history.append({
                    'timestamp': time.time(),
                    'response_time': metrics['response_time'],
                    'interval': self.current_interval
                })
            
        except Exception as e:
            self.logger.error(f"[DYNAMIC-INTERVAL] Error recording metrics: {e}")
    
    def _start_adjustment_thread(self):
        """Start background thread for smooth interval adjustments"""
        try:
            self.running = True
            
            def adjustment_worker():
                while self.running:
                    try:
                        self._smooth_adjustment()
                        time.sleep(1.0)  # Check every second
                    except Exception as e:
                        self.logger.error(f"[DYNAMIC-INTERVAL] Adjustment thread error: {e}")
                        time.sleep(1.0)
            
            self.adjustment_thread = threading.Thread(target=adjustment_worker, daemon=True)
            self.adjustment_thread.start()
            
        except Exception as e:
            self.logger.error(f"[DYNAMIC-INTERVAL] Error starting adjustment thread: {e}")
    
    def _smooth_adjustment(self):
        """Smoothly adjust current interval towards target"""
        try:
            with self.lock:
                if not self.smooth_transition:
                    self.current_interval = self.target_interval
                    return
                
                # Calculate adjustment step
                diff = self.target_interval - self.current_interval
                
                if abs(diff) < 0.1:  # Close enough
                    self.current_interval = self.target_interval
                    return
                
                # Smooth adjustment
                adjustment = diff * self.adjustment_step
                self.current_interval += adjustment
                
                # Record adjustment
                self.adjustment_history.append({
                    'timestamp': time.time(),
                    'old_interval': self.current_interval - adjustment,
                    'new_interval': self.current_interval,
                    'target_interval': self.target_interval,
                    'adjustment': adjustment
                })
                
        except Exception as e:
            self.logger.error(f"[DYNAMIC-INTERVAL] Error in smooth adjustment: {e}")
    
    def get_current_interval(self) -> float:
        """Get current monitoring interval"""
        with self.lock:
            return self.current_interval
    
    def get_target_interval(self) -> float:
        """Get target monitoring interval"""
        with self.lock:
            return self.target_interval
    
    def get_active_profile(self) -> Optional[str]:
        """Get currently active profile"""
        with self.lock:
            return self.active_profile
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get interval management statistics"""
        try:
            with self.lock:
                stats = {
                    'current_interval': self.current_interval,
                    'target_interval': self.target_interval,
                    'active_profile': self.active_profile,
                    'base_interval': self.base_interval,
                    'min_interval': self.min_interval,
                    'max_interval': self.max_interval,
                    'interval_history_size': len(self.interval_history),
                    'performance_history_size': len(self.performance_history),
                    'adjustment_history_size': len(self.adjustment_history)
                }
                
                # Calculate average interval
                if self.interval_history:
                    intervals = [entry['interval'] for entry in self.interval_history]
                    stats['average_interval'] = statistics.mean(intervals)
                    stats['interval_variance'] = statistics.variance(intervals) if len(intervals) > 1 else 0
                
                # Calculate performance correlation
                if len(self.performance_history) > 5:
                    response_times = [entry['response_time'] for entry in self.performance_history]
                    intervals = [entry['interval'] for entry in self.performance_history]
                    if len(response_times) > 1 and len(intervals) > 1:
                        try:
                            correlation = statistics.correlation(response_times, intervals)
                            stats['performance_correlation'] = correlation
                        except:
                            stats['performance_correlation'] = 0
                
                return stats
                
        except Exception as e:
            self.logger.error(f"[DYNAMIC-INTERVAL] Error getting statistics: {e}")
            return {}
    
    def learn_from_patterns(self):
        """Learn optimal intervals from historical patterns"""
        try:
            if not self.learning_enabled or len(self.interval_history) < 20:
                return
            
            with self.lock:
                # Analyze performance vs interval correlation
                performance_data = []
                for entry in self.interval_history:
                    if 'response_time' in entry.get('metrics', {}):
                        performance_data.append({
                            'interval': entry['interval'],
                            'response_time': entry['metrics']['response_time'],
                            'anomaly_score': entry['metrics'].get('anomaly_score', 0)
                        })
                
                if len(performance_data) < 10:
                    return
                
                # Find optimal interval for different anomaly levels
                anomaly_ranges = [
                    (0, 30, 'low'),
                    (30, 60, 'medium'),
                    (60, 100, 'high')
                ]
                
                optimizations = {}
                for min_anomaly, max_anomaly, level in anomaly_ranges:
                    level_data = [
                        d for d in performance_data
                        if min_anomaly <= d['anomaly_score'] < max_anomaly
                    ]
                    
                    if len(level_data) >= 5:
                        # Find interval with best performance
                        best_interval = min(level_data, key=lambda x: x['response_time'])['interval']
                        optimizations[level] = best_interval
                
                # Apply optimizations to profiles
                if optimizations:
                    self._apply_optimizations(optimizations)
                    self.logger.info(f"[DYNAMIC-INTERVAL] Applied optimizations: {optimizations}")
                
        except Exception as e:
            self.logger.error(f"[DYNAMIC-INTERVAL] Error learning from patterns: {e}")
    
    def _apply_optimizations(self, optimizations: Dict[str, float]):
        """Apply learned optimizations to profiles"""
        try:
            # Update profile base intervals based on learned optimizations
            if 'low' in optimizations:
                if 'low_activity' in self.profiles:
                    self.profiles['low_activity'].base_interval = optimizations['low']
            
            if 'medium' in optimizations:
                if 'normal' in self.profiles:
                    self.profiles['normal'].base_interval = optimizations['medium']
            
            if 'high' in optimizations:
                if 'high_activity' in self.profiles:
                    self.profiles['high_activity'].base_interval = optimizations['high']
                
        except Exception as e:
            self.logger.error(f"[DYNAMIC-INTERVAL] Error applying optimizations: {e}")
    
    def add_custom_profile(self, profile: IntervalProfile):
        """Add custom interval profile"""
        try:
            with self.lock:
                self.profiles[profile.name] = profile
                self.logger.info(f"[DYNAMIC-INTERVAL] Added custom profile: {profile.name}")
                
        except Exception as e:
            self.logger.error(f"[DYNAMIC-INTERVAL] Error adding custom profile: {e}")
    
    def remove_profile(self, profile_name: str):
        """Remove interval profile"""
        try:
            with self.lock:
                if profile_name in self.profiles:
                    del self.profiles[profile_name]
                    if self.active_profile == profile_name:
                        self.active_profile = None
                    self.logger.info(f"[DYNAMIC-INTERVAL] Removed profile: {profile_name}")
                
        except Exception as e:
            self.logger.error(f"[DYNAMIC-INTERVAL] Error removing profile: {e}")
    
    def shutdown(self):
        """Shutdown dynamic interval manager"""
        try:
            self.running = False
            if self.adjustment_thread:
                self.adjustment_thread.join(timeout=5.0)
            
            self.logger.info("[DYNAMIC-INTERVAL] Dynamic interval manager shutdown")
            
        except Exception as e:
            self.logger.error(f"[DYNAMIC-INTERVAL] Error during shutdown: {e}")
