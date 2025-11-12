from typing import List, Dict, Any
from collections import deque
from datetime import datetime, timedelta


class SecurityCorrelator:
    """Correlates security indicators over a sliding time window to reduce noise.

    It aggregates simple indicators (process/file/network/dns/ai) and computes
    an incident score. If the score crosses thresholds, it returns a structured
    alert with a concise explanation.
    """

    def __init__(self, window_seconds: int = 120):
        self.window_seconds = window_seconds
        self.events = deque()

    def add_cycle(self, now_iso: str, indicators: List[str], ai_score: float = 0.0, severity_hint: str = "LOW"):
        try:
            now = datetime.fromisoformat(now_iso)
        except Exception:
            now = datetime.now()
        self.events.append({
            "ts": now,
            "indicators": list(indicators or []),
            "ai_score": float(ai_score or 0.0),
            "severity_hint": severity_hint or "LOW"
        })
        # drop old
        cutoff = now - timedelta(seconds=self.window_seconds)
        while self.events and self.events[0]["ts"] < cutoff:
            self.events.popleft()

    def summarize(self) -> Dict[str, Any]:
        indicators: List[str] = []
        ai_scores: List[float] = []
        for ev in self.events:
            indicators.extend(ev["indicators"])
            ai_scores.append(ev["ai_score"])

        unique_indicators = list(dict.fromkeys(indicators))  # keep order
        ai_max = max(ai_scores) if ai_scores else 0.0

        # Simple scoring: count categories
        cat_score = 0
        cats = {
            "process": any("process" in i.lower() for i in unique_indicators),
            "file": any("file" in i.lower() for i in unique_indicators),
            "network": any("network" in i.lower() or "port" in i.lower() or "outbound" in i.lower() for i in unique_indicators),
            "dns": any("dns" in i.lower() for i in unique_indicators),
            "ai": ai_max >= 0.85
        }
        cat_score = sum(1 for v in cats.values() if v)

        # Determine severity
        if cat_score >= 3 or (cats["ai"] and (cats["file"] or cats["network"])):
            sev = "CRITICAL"
        elif cat_score == 2 or ai_max >= 0.9:
            sev = "HIGH"
        elif cat_score == 1:
            sev = "MEDIUM"
        else:
            sev = "LOW"

        explanation_parts = []
        if cats["process"]:
            explanation_parts.append("process indicator")
        if cats["file"]:
            explanation_parts.append("file change")
        if cats["network"]:
            explanation_parts.append("network pattern")
        if cats["dns"]:
            explanation_parts.append("dns pattern")
        if cats["ai"]:
            explanation_parts.append(f"AI score={ai_max:.2f}")

        return {
            "severity": sev,
            "ai_max": ai_max,
            "unique_indicators": unique_indicators,
            "explanation": ", ".join(explanation_parts) if explanation_parts else "no indicators"
        }


