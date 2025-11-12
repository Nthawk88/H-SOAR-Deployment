"""
Parallel Model Inference Engine
High-performance parallel model inference with load balancing
"""

import time
import threading
import logging
import queue
from typing import Dict, List, Any, Optional, Callable, Tuple
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
import multiprocessing as mp
import numpy as np
from collections import defaultdict
import statistics


@dataclass
class ModelTask:
    """Model inference task"""
    task_id: str
    model_name: str
    model: Any
    features: List[float]
    priority: int = 1
    timestamp: float = 0.0
    callback: Optional[Callable] = None
    
    def __post_init__(self):
        if self.timestamp == 0.0:
            self.timestamp = time.time()


@dataclass
class InferenceResult:
    """Model inference result"""
    task_id: str
    model_name: str
    score: float
    prediction: bool
    confidence: float
    inference_time: float
    timestamp: float
    error: Optional[str] = None


class ParallelModelInferenceEngine:
    """
    Parallel model inference engine with:
    - Multi-threaded/process inference
    - Load balancing
    - Priority queuing
    - Performance monitoring
    - Error handling and recovery
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Configuration
        self.max_workers = config.get('max_workers', min(8, mp.cpu_count()))
        self.max_process_workers = config.get('max_process_workers', min(4, mp.cpu_count()))
        self.batch_size = config.get('batch_size', 10)
        self.timeout = config.get('timeout', 30.0)
        self.retry_attempts = config.get('retry_attempts', 2)
        
        # Execution pools
        self.thread_pool = ThreadPoolExecutor(max_workers=self.max_workers)
        self.process_pool = ProcessPoolExecutor(max_workers=self.max_process_workers)
        
        # Task management
        self.task_queue = queue.PriorityQueue()
        self.active_tasks = {}
        self.completed_tasks = {}
        self.failed_tasks = {}
        
        # Model management
        self.models = {}
        self.model_load_times = {}
        self.model_performance = defaultdict(list)
        
        # Performance tracking
        self.stats = {
            'total_inferences': 0,
            'successful_inferences': 0,
            'failed_inferences': 0,
            'average_inference_time': 0.0,
            'throughput': 0.0,
            'queue_size': 0,
            'active_tasks': 0
        }
        
        # Load balancing
        self.model_loads = defaultdict(int)
        self.load_balancing_enabled = config.get('load_balancing_enabled', True)
        
        # Threading
        self.lock = threading.RLock()
        self.running = False
        self.worker_threads = []
        
        # Initialize
        self._start_worker_threads()
        self.logger.info(f"[PARALLEL-INFERENCE] Parallel inference engine initialized with {self.max_workers} workers")
    
    def register_model(self, name: str, model: Any, model_type: str = 'thread'):
        """Register a model for inference"""
        try:
            with self.lock:
                self.models[name] = {
                    'model': model,
                    'type': model_type,  # 'thread' or 'process'
                    'load_time': 0.0,
                    'inference_count': 0,
                    'error_count': 0
                }
                
                # Measure model load time
                start_time = time.time()
                try:
                    # Test model with dummy data
                    dummy_features = [0.0] * 10  # Assume 10 features
                    self._run_model_inference(model, dummy_features)
                    self.model_load_times[name] = time.time() - start_time
                except:
                    self.model_load_times[name] = 0.0
                
                self.logger.info(f"[PARALLEL-INFERENCE] Registered model: {name} ({model_type})")
                
        except Exception as e:
            self.logger.error(f"[PARALLEL-INFERENCE] Error registering model {name}: {e}")
    
    def submit_inference(self, model_name: str, features: List[float], 
                        priority: int = 1, callback: Optional[Callable] = None) -> str:
        """Submit inference task"""
        try:
            if model_name not in self.models:
                raise ValueError(f"Model {model_name} not registered")
            
            # Generate task ID
            task_id = f"{model_name}_{int(time.time() * 1000)}_{len(self.active_tasks)}"
            
            # Create task
            task = ModelTask(
                task_id=task_id,
                model_name=model_name,
                model=self.models[model_name]['model'],
                features=features,
                priority=priority,
                callback=callback
            )
            
            # Submit to queue
            with self.lock:
                self.task_queue.put((priority, task))
                self.active_tasks[task_id] = task
                self.stats['queue_size'] = self.task_queue.qsize()
            
            self.logger.debug(f"[PARALLEL-INFERENCE] Submitted task {task_id} for model {model_name}")
            return task_id
            
        except Exception as e:
            self.logger.error(f"[PARALLEL-INFERENCE] Error submitting inference: {e}")
            return ""
    
    def submit_batch_inference(self, tasks: List[Tuple[str, List[float], int]]) -> List[str]:
        """Submit multiple inference tasks"""
        try:
            task_ids = []
            for model_name, features, priority in tasks:
                task_id = self.submit_inference(model_name, features, priority)
                if task_id:
                    task_ids.append(task_id)
            
            self.logger.info(f"[PARALLEL-INFERENCE] Submitted batch of {len(task_ids)} tasks")
            return task_ids
            
        except Exception as e:
            self.logger.error(f"[PARALLEL-INFERENCE] Error submitting batch: {e}")
            return []
    
    def get_result(self, task_id: str, timeout: Optional[float] = None) -> Optional[InferenceResult]:
        """Get inference result"""
        try:
            start_time = time.time()
            timeout = timeout or self.timeout
            
            while time.time() - start_time < timeout:
                with self.lock:
                    if task_id in self.completed_tasks:
                        result = self.completed_tasks[task_id]
                        del self.completed_tasks[task_id]
                        return result
                    elif task_id in self.failed_tasks:
                        result = self.failed_tasks[task_id]
                        del self.failed_tasks[task_id]
                        return result
                
                time.sleep(0.01)  # Small delay to avoid busy waiting
            
            self.logger.warning(f"[PARALLEL-INFERENCE] Timeout waiting for result {task_id}")
            return None
            
        except Exception as e:
            self.logger.error(f"[PARALLEL-INFERENCE] Error getting result: {e}")
            return None
    
    def get_results(self, task_ids: List[str], timeout: Optional[float] = None) -> Dict[str, InferenceResult]:
        """Get multiple inference results"""
        try:
            results = {}
            timeout = timeout or self.timeout
            start_time = time.time()
            
            while len(results) < len(task_ids) and time.time() - start_time < timeout:
                for task_id in task_ids:
                    if task_id not in results:
                        result = self.get_result(task_id, 0.1)  # Short timeout for batch
                        if result:
                            results[task_id] = result
                
                if len(results) < len(task_ids):
                    time.sleep(0.01)
            
            return results
            
        except Exception as e:
            self.logger.error(f"[PARALLEL-INFERENCE] Error getting results: {e}")
            return {}
    
    def _start_worker_threads(self):
        """Start worker threads for processing tasks"""
        try:
            self.running = True
            
            # Start thread workers
            for i in range(self.max_workers):
                worker = threading.Thread(target=self._worker_thread, args=(i,), daemon=True)
                worker.start()
                self.worker_threads.append(worker)
            
            self.logger.info(f"[PARALLEL-INFERENCE] Started {self.max_workers} worker threads")
            
        except Exception as e:
            self.logger.error(f"[PARALLEL-INFERENCE] Error starting worker threads: {e}")
    
    def _worker_thread(self, worker_id: int):
        """Worker thread for processing inference tasks"""
        try:
            while self.running:
                try:
                    # Get task from queue
                    priority, task = self.task_queue.get(timeout=1.0)
                    
                    with self.lock:
                        self.stats['active_tasks'] += 1
                        self.stats['queue_size'] = self.task_queue.qsize()
                    
                    # Process task
                    result = self._process_task(task, worker_id)
                    
                    # Store result
                    with self.lock:
                        if result.error:
                            self.failed_tasks[task.task_id] = result
                            self.stats['failed_inferences'] += 1
                        else:
                            self.completed_tasks[task.task_id] = result
                            self.stats['successful_inferences'] += 1
                        
                        self.stats['total_inferences'] += 1
                        self.stats['active_tasks'] -= 1
                        
                        # Update model performance
                        self.model_performance[task.model_name].append(result.inference_time)
                        if len(self.model_performance[task.model_name]) > 100:
                            self.model_performance[task.model_name] = self.model_performance[task.model_name][-100:]
                        
                        # Update model stats
                        self.models[task.model_name]['inference_count'] += 1
                        if result.error:
                            self.models[task.model_name]['error_count'] += 1
                    
                    # Call callback if provided
                    if task.callback:
                        try:
                            task.callback(result)
                        except Exception as e:
                            self.logger.error(f"[PARALLEL-INFERENCE] Callback error: {e}")
                    
                    # Remove from active tasks
                    with self.lock:
                        if task.task_id in self.active_tasks:
                            del self.active_tasks[task.task_id]
                    
                    self.task_queue.task_done()
                    
                except queue.Empty:
                    continue
                except Exception as e:
                    self.logger.error(f"[PARALLEL-INFERENCE] Worker {worker_id} error: {e}")
                    time.sleep(0.1)
            
        except Exception as e:
            self.logger.error(f"[PARALLEL-INFERENCE] Worker thread {worker_id} error: {e}")
    
    def _process_task(self, task: ModelTask, worker_id: int) -> InferenceResult:
        """Process a single inference task"""
        try:
            start_time = time.time()
            
            # Determine execution method
            model_info = self.models[task.model_name]
            model_type = model_info['type']
            
            # Run inference
            if model_type == 'process':
                result = self._run_process_inference(task)
            else:
                result = self._run_thread_inference(task)
            
            inference_time = time.time() - start_time
            
            return InferenceResult(
                task_id=task.task_id,
                model_name=task.model_name,
                score=result.get('score', 0.0),
                prediction=result.get('prediction', False),
                confidence=result.get('confidence', 0.0),
                inference_time=inference_time,
                timestamp=time.time(),
                error=result.get('error')
            )
            
        except Exception as e:
            self.logger.error(f"[PARALLEL-INFERENCE] Error processing task {task.task_id}: {e}")
            return InferenceResult(
                task_id=task.task_id,
                model_name=task.model_name,
                score=0.0,
                prediction=False,
                confidence=0.0,
                inference_time=0.0,
                timestamp=time.time(),
                error=str(e)
            )
    
    def _run_thread_inference(self, task: ModelTask) -> Dict[str, Any]:
        """Run inference in thread pool"""
        try:
            future = self.thread_pool.submit(self._run_model_inference, task.model, task.features)
            return future.result(timeout=self.timeout)
            
        except Exception as e:
            return {'error': str(e), 'score': 0.0, 'prediction': False, 'confidence': 0.0}
    
    def _run_process_inference(self, task: ModelTask) -> Dict[str, Any]:
        """Run inference in process pool"""
        try:
            future = self.process_pool.submit(self._run_model_inference, task.model, task.features)
            return future.result(timeout=self.timeout)
            
        except Exception as e:
            return {'error': str(e), 'score': 0.0, 'prediction': False, 'confidence': 0.0}
    
    def _run_model_inference(self, model: Any, features: List[float]) -> Dict[str, Any]:
        """Run model inference (static method for process pool)"""
        try:
            if hasattr(model, 'predict'):
                prediction = model.predict([features])[0]
                score = float(prediction) if isinstance(prediction, (int, float)) else 0.0
            elif hasattr(model, 'decision_function'):
                score = float(model.decision_function([features])[0])
                prediction = score > 0.5
            elif hasattr(model, 'score'):
                result = model.score(features)
                score = result.get('ai_score', 0.0)
                prediction = result.get('ai_alert', False)
            else:
                score = 0.0
                prediction = False
            
            return {
                'score': score,
                'prediction': prediction,
                'confidence': abs(score)
            }
            
        except Exception as e:
            return {'error': str(e), 'score': 0.0, 'prediction': False, 'confidence': 0.0}
    
    def run_ensemble_inference(self, features: List[float], model_names: Optional[List[str]] = None) -> Dict[str, Any]:
        """Run ensemble inference across multiple models"""
        try:
            if model_names is None:
                model_names = list(self.models.keys())
            
            # Submit tasks for all models
            task_ids = []
            for model_name in model_names:
                task_id = self.submit_inference(model_name, features, priority=1)
                if task_id:
                    task_ids.append(task_id)
            
            # Wait for all results
            results = self.get_results(task_ids, timeout=self.timeout)
            
            # Combine results
            ensemble_result = self._combine_ensemble_results(results)
            
            self.logger.debug(f"[PARALLEL-INFERENCE] Ensemble inference completed with {len(results)} models")
            return ensemble_result
            
        except Exception as e:
            self.logger.error(f"[PARALLEL-INFERENCE] Error in ensemble inference: {e}")
            return {'error': str(e), 'ensemble_score': 0.0, 'ensemble_prediction': False}
    
    def _combine_ensemble_results(self, results: Dict[str, InferenceResult]) -> Dict[str, Any]:
        """Combine ensemble results"""
        try:
            if not results:
                return {'ensemble_score': 0.0, 'ensemble_prediction': False, 'model_count': 0}
            
            # Extract scores and predictions
            scores = []
            predictions = []
            confidences = []
            
            for result in results.values():
                if not result.error:
                    scores.append(result.score)
                    predictions.append(result.prediction)
                    confidences.append(result.confidence)
            
            if not scores:
                return {'ensemble_score': 0.0, 'ensemble_prediction': False, 'model_count': 0}
            
            # Calculate ensemble metrics
            ensemble_score = statistics.mean(scores)
            ensemble_prediction = sum(predictions) > len(predictions) / 2  # Majority vote
            ensemble_confidence = statistics.mean(confidences)
            
            # Calculate agreement
            agreement = sum(predictions) / len(predictions) if predictions else 0.0
            
            return {
                'ensemble_score': ensemble_score,
                'ensemble_prediction': ensemble_prediction,
                'ensemble_confidence': ensemble_confidence,
                'model_count': len(scores),
                'agreement': agreement,
                'individual_results': {
                    result.model_name: {
                        'score': result.score,
                        'prediction': result.prediction,
                        'confidence': result.confidence,
                        'inference_time': result.inference_time
                    }
                    for result in results.values()
                }
            }
            
        except Exception as e:
            self.logger.error(f"[PARALLEL-INFERENCE] Error combining ensemble results: {e}")
            return {'error': str(e), 'ensemble_score': 0.0, 'ensemble_prediction': False}
    
    def get_performance_stats(self) -> Dict[str, Any]:
        """Get performance statistics"""
        try:
            with self.lock:
                stats = self.stats.copy()
                
                # Calculate average inference time
                if self.stats['total_inferences'] > 0:
                    total_time = sum(
                        sum(times) for times in self.model_performance.values()
                    )
                    stats['average_inference_time'] = total_time / self.stats['total_inferences']
                
                # Calculate throughput
                if self.stats['total_inferences'] > 0:
                    stats['throughput'] = self.stats['total_inferences'] / max(1, time.time() - self.start_time)
                
                # Add model-specific stats
                stats['model_stats'] = {}
                for model_name, model_info in self.models.items():
                    stats['model_stats'][model_name] = {
                        'inference_count': model_info['inference_count'],
                        'error_count': model_info['error_count'],
                        'error_rate': model_info['error_count'] / max(1, model_info['inference_count']),
                        'average_inference_time': statistics.mean(self.model_performance[model_name]) if self.model_performance[model_name] else 0.0
                    }
                
                return stats
                
        except Exception as e:
            self.logger.error(f"[PARALLEL-INFERENCE] Error getting performance stats: {e}")
            return {}
    
    def optimize_load_balancing(self):
        """Optimize load balancing based on model performance"""
        try:
            if not self.load_balancing_enabled:
                return
            
            with self.lock:
                # Analyze model performance
                model_performance = {}
                for model_name, times in self.model_performance.items():
                    if times:
                        model_performance[model_name] = {
                            'avg_time': statistics.mean(times),
                            'std_time': statistics.stdev(times) if len(times) > 1 else 0.0,
                            'count': len(times)
                        }
                
                # Adjust model types based on performance
                for model_name, perf in model_performance.items():
                    if perf['avg_time'] > 1.0 and perf['std_time'] < 0.5:  # Slow but consistent
                        # Move to process pool
                        if self.models[model_name]['type'] == 'thread':
                            self.models[model_name]['type'] = 'process'
                            self.logger.info(f"[PARALLEL-INFERENCE] Moved {model_name} to process pool")
                    elif perf['avg_time'] < 0.1 and perf['count'] > 10:  # Fast and reliable
                        # Move to thread pool
                        if self.models[model_name]['type'] == 'process':
                            self.models[model_name]['type'] = 'thread'
                            self.logger.info(f"[PARALLEL-INFERENCE] Moved {model_name} to thread pool")
                
        except Exception as e:
            self.logger.error(f"[PARALLEL-INFERENCE] Error optimizing load balancing: {e}")
    
    def shutdown(self):
        """Shutdown parallel inference engine"""
        try:
            self.running = False
            
            # Wait for active tasks to complete
            self.task_queue.join()
            
            # Shutdown thread pool
            self.thread_pool.shutdown(wait=True)
            
            # Shutdown process pool
            self.process_pool.shutdown(wait=True)
            
            # Wait for worker threads
            for worker in self.worker_threads:
                worker.join(timeout=5.0)
            
            self.logger.info("[PARALLEL-INFERENCE] Parallel inference engine shutdown")
            
        except Exception as e:
            self.logger.error(f"[PARALLEL-INFERENCE] Error during shutdown: {e}")
    
    def __init__(self, config: Dict[str, Any]):
        # ... existing initialization code ...
        self.start_time = time.time()  # Add this line
