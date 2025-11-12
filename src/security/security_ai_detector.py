from typing import List, Dict, Any
import os
import pickle

from sklearn.ensemble import IsolationForest


class SecurityAIDetector:
    """Unsupervised security anomaly detector using IsolationForest.

    Trains on baseline feature vectors and outputs anomaly score (higher=worse).
    """

    def __init__(self, model_path: str = "models/security_iforest.pkl", threshold: float = 0.85):
        self.model_path = model_path
        self.threshold = threshold
        self.model: IsolationForest = None
        self.is_trained = False
        self._load()

    def _load(self):
        try:
            if os.path.exists(self.model_path):
                with open(self.model_path, 'rb') as f:
                    self.model = pickle.load(f)
                self.is_trained = True
        except Exception:
            self.model = None
            self.is_trained = False

    def save(self):
        try:
            os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
            with open(self.model_path, 'wb') as f:
                pickle.dump(self.model, f)
        except Exception:
            pass

    def train_baseline(self, feature_vectors: List[List[float]]) -> bool:
        try:
            if not feature_vectors:
                return False
            self.model = IsolationForest(n_estimators=200, contamination=0.05, random_state=42)
            self.model.fit(feature_vectors)
            self.is_trained = True
            self.save()
            return True
        except Exception:
            return False

    def score(self, features: List[float]) -> Dict[str, Any]:
        if not self.is_trained or not self.model:
            return {"ai_security_available": False, "ai_score": 0.0, "ai_alert": False}
        try:
            # IsolationForest decision_function: higher means more normal; convert to anomaly
            df = float(self.model.decision_function([features])[0])
            # map to 0..1 anomaly score (approx): 1 - sigmoid-like transform
            # This is heuristic; for demo we linearly invert across plausible range
            ai_score = max(0.0, min(1.0, 0.5 - df))
            ai_alert = ai_score >= self.threshold
            return {"ai_security_available": True, "ai_score": ai_score, "ai_alert": ai_alert}
        except Exception:
            return {"ai_security_available": False, "ai_score": 0.0, "ai_alert": False}


