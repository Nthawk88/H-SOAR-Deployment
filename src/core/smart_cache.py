"""
Smart Caching System
Intelligent caching with TTL, LRU, and adaptive strategies
"""

import time
import threading
import json
import hashlib
import logging
from typing import Dict, List, Any, Optional, Callable, Union
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timedelta
import pickle
import os


@dataclass
class CacheEntry:
    """Cache entry with metadata"""
    data: Any
    timestamp: float
    ttl: float
    access_count: int = 0
    last_access: float = 0.0
    size: int = 0
    priority: int = 1
    
    def __post_init__(self):
        if self.last_access == 0.0:
            self.last_access = self.timestamp
        if self.size == 0:
            self.size = len(str(self.data))


class SmartCache:
    """
    Smart caching system with:
    - TTL-based expiration
    - LRU eviction
    - Size-based limits
    - Adaptive strategies
    - Performance metrics
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Cache configuration
        self.max_size = config.get('max_size', 1000)  # Max entries
        self.max_memory = config.get('max_memory', 100 * 1024 * 1024)  # 100MB
        self.default_ttl = config.get('default_ttl', 300)  # 5 minutes
        self.cleanup_interval = config.get('cleanup_interval', 60)  # 1 minute
        
        # Cache storage
        self.cache = OrderedDict()
        self.cache_lock = threading.RLock()
        
        # Performance tracking
        self.stats = {
            'hits': 0,
            'misses': 0,
            'evictions': 0,
            'expirations': 0,
            'total_requests': 0,
            'total_size': 0,
            'hit_rate': 0.0
        }
        
        # Adaptive strategies
        self.adaptive_enabled = config.get('adaptive_enabled', True)
        self.access_patterns = {}
        self.popularity_threshold = config.get('popularity_threshold', 5)
        
        # Initialize
        self._start_cleanup_thread()
        self.logger.info("[SMART-CACHE] Smart caching system initialized")
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get value from cache"""
        try:
            with self.cache_lock:
                self.stats['total_requests'] += 1
                
                if key in self.cache:
                    entry = self.cache[key]
                    
                    # Check if expired
                    if time.time() - entry.timestamp > entry.ttl:
                        del self.cache[key]
                        self.stats['expirations'] += 1
                        self.stats['misses'] += 1
                        return default
                    
                    # Update access info
                    entry.access_count += 1
                    entry.last_access = time.time()
                    
                    # Move to end (LRU)
                    self.cache.move_to_end(key)
                    
                    # Update stats
                    self.stats['hits'] += 1
                    self._update_hit_rate()
                    
                    # Track access pattern
                    if self.adaptive_enabled:
                        self._track_access_pattern(key)
                    
                    return entry.data
                else:
                    self.stats['misses'] += 1
                    self._update_hit_rate()
                    return default
                    
        except Exception as e:
            self.logger.error(f"[SMART-CACHE] Error getting key {key}: {e}")
            return default
    
    def set(self, key: str, value: Any, ttl: Optional[float] = None, priority: int = 1) -> bool:
        """Set value in cache"""
        try:
            with self.cache_lock:
                # Calculate TTL
                if ttl is None:
                    ttl = self.default_ttl
                
                # Calculate size
                size = self._calculate_size(value)
                
                # Check if we need to evict
                self._check_and_evict(size)
                
                # Create cache entry
                entry = CacheEntry(
                    data=value,
                    timestamp=time.time(),
                    ttl=ttl,
                    priority=priority,
                    size=size
                )
                
                # Store in cache
                self.cache[key] = entry
                self.stats['total_size'] += size
                
                # Move to end (LRU)
                self.cache.move_to_end(key)
                
                return True
                
        except Exception as e:
            self.logger.error(f"[SMART-CACHE] Error setting key {key}: {e}")
            return False
    
    def delete(self, key: str) -> bool:
        """Delete key from cache"""
        try:
            with self.cache_lock:
                if key in self.cache:
                    entry = self.cache[key]
                    self.stats['total_size'] -= entry.size
                    del self.cache[key]
                    return True
                return False
                
        except Exception as e:
            self.logger.error(f"[SMART-CACHE] Error deleting key {key}: {e}")
            return False
    
    def clear(self):
        """Clear all cache entries"""
        try:
            with self.cache_lock:
                self.cache.clear()
                self.stats['total_size'] = 0
                self.logger.info("[SMART-CACHE] Cache cleared")
                
        except Exception as e:
            self.logger.error(f"[SMART-CACHE] Error clearing cache: {e}")
    
    def get_or_set(self, key: str, factory: Callable, ttl: Optional[float] = None, priority: int = 1) -> Any:
        """Get value or set using factory function"""
        try:
            # Try to get from cache first
            value = self.get(key)
            if value is not None:
                return value
            
            # Generate value using factory
            value = factory()
            
            # Store in cache
            self.set(key, value, ttl, priority)
            
            return value
            
        except Exception as e:
            self.logger.error(f"[SMART-CACHE] Error in get_or_set for key {key}: {e}")
            return factory()
    
    def cache_function(self, ttl: Optional[float] = None, priority: int = 1):
        """Decorator for caching function results"""
        def decorator(func):
            def wrapper(*args, **kwargs):
                # Generate cache key
                cache_key = self._generate_cache_key(func.__name__, args, kwargs)
                
                # Try to get from cache
                result = self.get(cache_key)
                if result is not None:
                    return result
                
                # Execute function
                result = func(*args, **kwargs)
                
                # Store in cache
                self.set(cache_key, result, ttl, priority)
                
                return result
            
            return wrapper
        return decorator
    
    def _calculate_size(self, value: Any) -> int:
        """Calculate size of value"""
        try:
            if isinstance(value, (str, bytes)):
                return len(value)
            elif isinstance(value, (int, float, bool)):
                return 8
            elif isinstance(value, (list, tuple, dict)):
                return len(str(value))
            else:
                return len(pickle.dumps(value))
        except:
            return 1024  # Default size
    
    def _generate_cache_key(self, func_name: str, args: tuple, kwargs: dict) -> str:
        """Generate cache key from function name and arguments"""
        try:
            # Create hash of arguments
            key_data = {
                'func': func_name,
                'args': args,
                'kwargs': sorted(kwargs.items())
            }
            key_str = json.dumps(key_data, sort_keys=True, default=str)
            return hashlib.md5(key_str.encode()).hexdigest()
        except:
            return f"{func_name}_{hash(str(args) + str(kwargs))}"
    
    def _check_and_evict(self, new_size: int):
        """Check if eviction is needed and perform it"""
        try:
            # Check memory limit
            if self.stats['total_size'] + new_size > self.max_memory:
                self._evict_by_memory()
            
            # Check size limit
            if len(self.cache) >= self.max_size:
                self._evict_by_count()
                
        except Exception as e:
            self.logger.error(f"[SMART-CACHE] Error in eviction check: {e}")
    
    def _evict_by_memory(self):
        """Evict entries to free memory"""
        try:
            target_size = self.max_memory * 0.8  # Free up 20%
            
            while self.stats['total_size'] > target_size and self.cache:
                # Remove least recently used entry
                key, entry = self.cache.popitem(last=False)
                self.stats['total_size'] -= entry.size
                self.stats['evictions'] += 1
                
        except Exception as e:
            self.logger.error(f"[SMART-CACHE] Error in memory eviction: {e}")
    
    def _evict_by_count(self):
        """Evict entries to reduce count"""
        try:
            target_count = int(self.max_size * 0.8)  # Keep 80%
            
            while len(self.cache) > target_count:
                # Remove least recently used entry
                key, entry = self.cache.popitem(last=False)
                self.stats['total_size'] -= entry.size
                self.stats['evictions'] += 1
                
        except Exception as e:
            self.logger.error(f"[SMART-CACHE] Error in count eviction: {e}")
    
    def _track_access_pattern(self, key: str):
        """Track access patterns for adaptive strategies"""
        try:
            if key not in self.access_patterns:
                self.access_patterns[key] = {
                    'access_times': [],
                    'frequency': 0,
                    'last_access': 0
                }
            
            pattern = self.access_patterns[key]
            pattern['access_times'].append(time.time())
            pattern['frequency'] += 1
            pattern['last_access'] = time.time()
            
            # Keep only recent access times
            cutoff_time = time.time() - 3600  # 1 hour
            pattern['access_times'] = [t for t in pattern['access_times'] if t > cutoff_time]
            
        except Exception as e:
            self.logger.error(f"[SMART-CACHE] Error tracking access pattern: {e}")
    
    def _update_hit_rate(self):
        """Update hit rate statistics"""
        try:
            total = self.stats['hits'] + self.stats['misses']
            if total > 0:
                self.stats['hit_rate'] = self.stats['hits'] / total
        except Exception as e:
            self.logger.error(f"[SMART-CACHE] Error updating hit rate: {e}")
    
    def _start_cleanup_thread(self):
        """Start background cleanup thread"""
        try:
            def cleanup_worker():
                while True:
                    try:
                        self._cleanup_expired()
                        time.sleep(self.cleanup_interval)
                    except Exception as e:
                        self.logger.error(f"[SMART-CACHE] Cleanup error: {e}")
                        time.sleep(self.cleanup_interval)
            
            cleanup_thread = threading.Thread(target=cleanup_worker, daemon=True)
            cleanup_thread.start()
            
        except Exception as e:
            self.logger.error(f"[SMART-CACHE] Error starting cleanup thread: {e}")
    
    def _cleanup_expired(self):
        """Clean up expired entries"""
        try:
            with self.cache_lock:
                current_time = time.time()
                expired_keys = []
                
                for key, entry in self.cache.items():
                    if current_time - entry.timestamp > entry.ttl:
                        expired_keys.append(key)
                
                for key in expired_keys:
                    entry = self.cache[key]
                    self.stats['total_size'] -= entry.size
                    del self.cache[key]
                    self.stats['expirations'] += 1
                
                if expired_keys:
                    self.logger.debug(f"[SMART-CACHE] Cleaned up {len(expired_keys)} expired entries")
                    
        except Exception as e:
            self.logger.error(f"[SMART-CACHE] Error in cleanup: {e}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        try:
            with self.cache_lock:
                return {
                    **self.stats,
                    'cache_size': len(self.cache),
                    'memory_usage_mb': self.stats['total_size'] / (1024 * 1024),
                    'memory_limit_mb': self.max_memory / (1024 * 1024),
                    'memory_usage_percent': (self.stats['total_size'] / self.max_memory) * 100
                }
        except Exception as e:
            self.logger.error(f"[SMART-CACHE] Error getting stats: {e}")
            return {}
    
    def get_popular_keys(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get most popular cache keys"""
        try:
            with self.cache_lock:
                popular = []
                for key, entry in self.cache.items():
                    if entry.access_count >= self.popularity_threshold:
                        popular.append({
                            'key': key,
                            'access_count': entry.access_count,
                            'last_access': entry.last_access,
                            'size': entry.size
                        })
                
                # Sort by access count
                popular.sort(key=lambda x: x['access_count'], reverse=True)
                return popular[:limit]
                
        except Exception as e:
            self.logger.error(f"[SMART-CACHE] Error getting popular keys: {e}")
            return []
    
    def optimize_cache(self):
        """Optimize cache based on access patterns"""
        try:
            if not self.adaptive_enabled:
                return
            
            with self.cache_lock:
                # Adjust TTL based on access patterns
                for key, entry in self.cache.items():
                    if key in self.access_patterns:
                        pattern = self.access_patterns[key]
                        
                        # Increase TTL for frequently accessed items
                        if pattern['frequency'] > 10:
                            entry.ttl = min(entry.ttl * 1.5, 3600)  # Max 1 hour
                        elif pattern['frequency'] < 2:
                            entry.ttl = max(entry.ttl * 0.8, 60)  # Min 1 minute
                
                self.logger.info("[SMART-CACHE] Cache optimized based on access patterns")
                
        except Exception as e:
            self.logger.error(f"[SMART-CACHE] Error optimizing cache: {e}")
    
    def save_to_disk(self, filepath: str):
        """Save cache to disk"""
        try:
            with self.cache_lock:
                cache_data = {
                    'cache': dict(self.cache),
                    'stats': self.stats,
                    'timestamp': time.time()
                }
                
                with open(filepath, 'wb') as f:
                    pickle.dump(cache_data, f)
                
                self.logger.info(f"[SMART-CACHE] Cache saved to {filepath}")
                
        except Exception as e:
            self.logger.error(f"[SMART-CACHE] Error saving cache: {e}")
    
    def load_from_disk(self, filepath: str):
        """Load cache from disk"""
        try:
            if not os.path.exists(filepath):
                return False
            
            with open(filepath, 'rb') as f:
                cache_data = pickle.load(f)
            
            with self.cache_lock:
                self.cache = OrderedDict(cache_data['cache'])
                self.stats.update(cache_data['stats'])
            
            self.logger.info(f"[SMART-CACHE] Cache loaded from {filepath}")
            return True
            
        except Exception as e:
            self.logger.error(f"[SMART-CACHE] Error loading cache: {e}")
            return False
