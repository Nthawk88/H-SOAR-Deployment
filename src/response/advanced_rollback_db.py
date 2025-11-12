"""
Advanced Rollback Database Management
Handles state tracking, rollback history, and performance metrics
"""

import sqlite3
import json
import threading
from datetime import datetime
from typing import Dict, List, Any, Optional
import logging

class AdvancedRollbackDatabase:
    """Database management for advanced rollback system"""
    
    def __init__(self, db_path: str = "logs/advanced_rollback.db"):
        self.db_path = db_path
        self.lock = threading.Lock()
        self.logger = logging.getLogger(__name__)
        self._initialize_database()
    
    def _initialize_database(self):
        """Initialize database with required tables"""
        try:
            with self.lock:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                # System state tracking table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS system_state (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        component TEXT NOT NULL,
                        state_data TEXT NOT NULL,
                        state_type TEXT NOT NULL,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        status TEXT DEFAULT 'active',
                        checksum TEXT
                    )
                ''')
                
                # Rollback history table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS rollback_history (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        rollback_id TEXT NOT NULL,
                        component TEXT NOT NULL,
                        rollback_type TEXT NOT NULL,
                        strategy TEXT NOT NULL,
                        success BOOLEAN NOT NULL,
                        duration REAL NOT NULL,
                        error_message TEXT,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        threat_data TEXT,
                        metrics TEXT
                    )
                ''')
                
                # Component dependencies table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS component_dependencies (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        component TEXT NOT NULL,
                        dependency TEXT NOT NULL,
                        priority INTEGER DEFAULT 1,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Performance metrics table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS rollback_metrics (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        component TEXT NOT NULL,
                        metric_name TEXT NOT NULL,
                        metric_value REAL NOT NULL,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Create indexes for better performance
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_component_state ON system_state(component, timestamp)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_rollback_history ON rollback_history(rollback_id, component)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_metrics ON rollback_metrics(component, metric_name, timestamp)')
                
                conn.commit()
                conn.close()
                
                self.logger.info("Advanced rollback database initialized successfully")
                
        except Exception as e:
            self.logger.error(f"Failed to initialize database: {e}")
            raise
    
    def save_system_state(self, component: str, state_data: Dict[str, Any], 
                         state_type: str = "backup", checksum: str = None) -> bool:
        """Save system state for rollback"""
        try:
            with self.lock:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT INTO system_state (component, state_data, state_type, checksum)
                    VALUES (?, ?, ?, ?)
                ''', (component, json.dumps(state_data), state_type, checksum))
                
                conn.commit()
                conn.close()
                
                self.logger.debug(f"Saved state for component: {component}")
                return True
                
        except Exception as e:
            self.logger.error(f"Failed to save system state: {e}")
            return False
    
    def get_latest_state(self, component: str, state_type: str = "backup") -> Optional[Dict[str, Any]]:
        """Get latest state for component"""
        try:
            with self.lock:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT state_data FROM system_state 
                    WHERE component = ? AND state_type = ? AND status = 'active'
                    ORDER BY timestamp DESC LIMIT 1
                ''', (component, state_type))
                
                result = cursor.fetchone()
                conn.close()
                
                if result:
                    return json.loads(result[0])
                return None
                
        except Exception as e:
            self.logger.error(f"Failed to get latest state: {e}")
            return None
    
    def log_rollback_attempt(self, rollback_id: str, component: str, 
                           rollback_type: str, strategy: str, success: bool,
                           duration: float, error_message: str = None,
                           threat_data: Dict[str, Any] = None,
                           metrics: Dict[str, Any] = None) -> bool:
        """Log rollback attempt"""
        try:
            with self.lock:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT INTO rollback_history 
                    (rollback_id, component, rollback_type, strategy, success, 
                     duration, error_message, threat_data, metrics)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (rollback_id, component, rollback_type, strategy, success,
                      duration, json.dumps(threat_data) if threat_data else None,
                      json.dumps(metrics) if metrics else None, error_message))
                
                conn.commit()
                conn.close()
                
                self.logger.debug(f"Logged rollback attempt: {rollback_id}")
                return True
                
        except Exception as e:
            self.logger.error(f"Failed to log rollback attempt: {e}")
            return False
    
    def get_rollback_history(self, component: str = None, limit: int = 100) -> List[Dict[str, Any]]:
        """Get rollback history"""
        try:
            with self.lock:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                if component:
                    cursor.execute('''
                        SELECT * FROM rollback_history 
                        WHERE component = ? 
                        ORDER BY timestamp DESC LIMIT ?
                    ''', (component, limit))
                else:
                    cursor.execute('''
                        SELECT * FROM rollback_history 
                        ORDER BY timestamp DESC LIMIT ?
                    ''', (limit,))
                
                results = cursor.fetchall()
                conn.close()
                
                # Convert to list of dictionaries
                columns = [description[0] for description in cursor.description]
                return [dict(zip(columns, row)) for row in results]
                
        except Exception as e:
            self.logger.error(f"Failed to get rollback history: {e}")
            return []
    
    def save_component_dependency(self, component: str, dependency: str, priority: int = 1) -> bool:
        """Save component dependency"""
        try:
            with self.lock:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT OR REPLACE INTO component_dependencies 
                    (component, dependency, priority)
                    VALUES (?, ?, ?)
                ''', (component, dependency, priority))
                
                conn.commit()
                conn.close()
                
                self.logger.debug(f"Saved dependency: {component} -> {dependency}")
                return True
                
        except Exception as e:
            self.logger.error(f"Failed to save component dependency: {e}")
            return False
    
    def get_component_dependencies(self, component: str) -> List[str]:
        """Get component dependencies"""
        try:
            with self.lock:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT dependency FROM component_dependencies 
                    WHERE component = ? 
                    ORDER BY priority ASC
                ''', (component,))
                
                results = cursor.fetchall()
                conn.close()
                
                return [row[0] for row in results]
                
        except Exception as e:
            self.logger.error(f"Failed to get component dependencies: {e}")
            return []
    
    def save_performance_metric(self, component: str, metric_name: str, metric_value: float) -> bool:
        """Save performance metric"""
        try:
            with self.lock:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT INTO rollback_metrics (component, metric_name, metric_value)
                    VALUES (?, ?, ?)
                ''', (component, metric_name, metric_value))
                
                conn.commit()
                conn.close()
                
                return True
                
        except Exception as e:
            self.logger.error(f"Failed to save performance metric: {e}")
            return False
    
    def get_performance_metrics(self, component: str = None, metric_name: str = None, 
                               hours: int = 24) -> Dict[str, Any]:
        """Get performance metrics"""
        try:
            with self.lock:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                query = '''
                    SELECT component, metric_name, AVG(metric_value) as avg_value,
                           MIN(metric_value) as min_value, MAX(metric_value) as max_value,
                           COUNT(*) as count
                    FROM rollback_metrics 
                    WHERE timestamp >= datetime('now', '-{} hours')
                '''.format(hours)
                
                params = []
                if component:
                    query += ' AND component = ?'
                    params.append(component)
                if metric_name:
                    query += ' AND metric_name = ?'
                    params.append(metric_name)
                
                query += ' GROUP BY component, metric_name'
                
                cursor.execute(query, params)
                results = cursor.fetchall()
                conn.close()
                
                metrics = {}
                for row in results:
                    comp, metric, avg_val, min_val, max_val, count = row
                    if comp not in metrics:
                        metrics[comp] = {}
                    metrics[comp][metric] = {
                        'average': avg_val,
                        'minimum': min_val,
                        'maximum': max_val,
                        'count': count
                    }
                
                return metrics
                
        except Exception as e:
            self.logger.error(f"Failed to get performance metrics: {e}")
            return {}
    
    def cleanup_old_data(self, days: int = 30) -> bool:
        """Cleanup old data"""
        try:
            with self.lock:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                # Cleanup old system states
                cursor.execute('''
                    DELETE FROM system_state 
                    WHERE timestamp < datetime('now', '-{} days')
                '''.format(days))
                
                # Cleanup old rollback history
                cursor.execute('''
                    DELETE FROM rollback_history 
                    WHERE timestamp < datetime('now', '-{} days')
                '''.format(days))
                
                # Cleanup old metrics
                cursor.execute('''
                    DELETE FROM rollback_metrics 
                    WHERE timestamp < datetime('now', '-{} days')
                '''.format(days))
                
                conn.commit()
                conn.close()
                
                self.logger.info(f"Cleaned up data older than {days} days")
                return True
                
        except Exception as e:
            self.logger.error(f"Failed to cleanup old data: {e}")
            return False
