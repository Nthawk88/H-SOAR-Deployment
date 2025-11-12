import json
import os
from datetime import datetime
from typing import Any, Dict, List, Tuple


class SecurityIDS:
    """Minimal rule-based security IDS.

    This module provides lightweight heuristic checks over host and network
    metrics to flag basic security-relevant conditions (e.g., suspicious processes,
    possible port scan, high foreign connections, critical file changes).
    """

    def __init__(self, config_path: str = "config/security_rules.json"):
        self.rules = self._load_rules(config_path)
        self.config_path = config_path
        self.initialized_at = datetime.now().isoformat()

    def _load_rules(self, config_path: str) -> Dict[str, Any]:
        default_rules: Dict[str, Any] = {
            "suspicious_process_names": [
                # Exact binary/command names (lowercase)
                "nc", "netcat", "ncat", "mimikatz", "mshta", "wget", "curl", "powershell"
            ],
            "process_allowlist_prefixes": [
                # Common Windows processes that include 'sync'/'experience' etc.
                "onedrive.", "onedrive.sync.", "filesynchelper", "shellexperiencehost",
                "startexperiencehost", "startmenuexperiencehost", "phoneexperiencehost"
            ],
            "critical_files": ["/etc/passwd", "/etc/hosts", "C:/Windows/System32/drivers/etc/hosts"],
            "port_scan_min_unique_ports": 50,
            "ddos_min_total_events": 1000,
            "ddos_min_foreign_connections": 50,
            "suspicious_dns_patterns": ["Suspicious DNS query", "DNS tunnel", "base64"],
            "high_outbound_connections": 30,
            "high_remote_high_port_count": 20,
            "severity_weights": {
                "process": 2,
                "file": 3,
                "network": 2,
                "dns": 2
            },
            "severity_thresholds": {
                "LOW": 2,
                "MEDIUM": 6,  # Increased from 4 to 6 to reduce false positives
                "HIGH": 8,    # Increased from 6 to 8
                "CRITICAL": 10 # Increased from 8 to 10
            }
        }

        try:
            if os.path.exists(config_path):
                with open(config_path, "r", encoding="utf-8") as f:
                    user_cfg = json.load(f)
                # shallow merge
                merged = {**default_rules, **user_cfg}
                if "severity_weights" in user_cfg:
                    merged["severity_weights"] = {**default_rules["severity_weights"], **user_cfg["severity_weights"]}
                if "severity_thresholds" in user_cfg:
                    merged["severity_thresholds"] = {**default_rules["severity_thresholds"], **user_cfg["severity_thresholds"]}
                return merged
        except Exception:
            pass
        return default_rules

    def _score_to_severity(self, score: int) -> str:
        th = self.rules.get("severity_thresholds", {})
        # Order matters from highest to lowest
        if score >= th.get("CRITICAL", 8):
            return "CRITICAL"
        if score >= th.get("HIGH", 6):
            return "HIGH"
        if score >= th.get("MEDIUM", 4):
            return "MEDIUM"
        return "LOW"

    def _check_process_indicators(self, host_metrics: Dict[str, Any]) -> Tuple[int, List[str]]:
        indicators: List[str] = []
        weight = self.rules["severity_weights"].get("process", 2)
        score = 0
        suspicious_names = set(n.lower() for n in self.rules.get("suspicious_process_names", []))
        allowlist_prefixes = [p.lower() for p in self.rules.get("process_allowlist_prefixes", [])]
        hits = 0

        for proc in host_metrics.get("processes", []) or []:
            name = str(proc.get("name", "")).lower()
            # skip allowlisted common benign processes
            if any(name.startswith(pref) for pref in allowlist_prefixes):
                continue
            # Tokenize name by non-alphanumeric boundaries; match exact tokens only
            tokens = [t for t in ''.join([c if c.isalnum() else ' ' for c in name]).split() if t]
            # allow benign shell: plain powershell.exe without '-enc' is allowed
            if name.startswith('powershell') and '-enc' not in name:
                pass
            elif any(tok in suspicious_names for tok in tokens):
                indicators.append(f"Suspicious process: {proc.get('name')}")
                hits += 1
                # cap process score to avoid CRITICAL from many benign matches
                if hits <= 2:
                    score += weight
            # very high cpu for a single proc could be beaconing/miner
            # But exclude legitimate Windows processes
            try:
                cpu_percent = float(proc.get("cpu_percent", 0))
                process_name = proc.get('name', '').lower()
                
                # Whitelist untuk process Windows yang legitimate
                legitimate_processes = [
                    'system idle process', 'svchost.exe', 'explorer.exe', 'dwm.exe',
                    'winlogon.exe', 'csrss.exe', 'smss.exe', 'lsass.exe', 'services.exe',
                    'msmpeng.exe', 'windows defender', 'antimalware service executable',
                    'chrome.exe', 'firefox.exe', 'edge.exe', 'notepad.exe', 'calc.exe'
                ]
                
                # Skip jika process legitimate
                is_legitimate = any(legit in process_name for legit in legitimate_processes)
                
                if cpu_percent > 90.0 and not is_legitimate:  # Increased threshold to 90%
                    indicators.append(f"High CPU process: {proc.get('name')} ({proc.get('cpu_percent')}%)")
                    score += 1
                elif cpu_percent > 150.0:  # Very high CPU even for legitimate processes
                    indicators.append(f"Extremely high CPU process: {proc.get('name')} ({proc.get('cpu_percent')}%)")
                    score += 0.5  # Lower score for legitimate processes
            except Exception:
                pass
        return score, indicators

    def _check_file_indicators(self, host_metrics: Dict[str, Any]) -> Tuple[int, List[str]]:
        indicators: List[str] = []
        weight = self.rules["severity_weights"].get("file", 3)
        score = 0
        critical_files = set(self.rules.get("critical_files", []))
        files = host_metrics.get("critical_files", {}) or {}
        for path, meta in files.items():
            # only count if FIM actually detected change; ignore placeholders
            if not meta or not meta.get("fim_detected"):
                continue
            if path in critical_files:
                mod_ts = str(meta.get("modified", ""))
                indicators.append(f"Critical file changed: {path} at {mod_ts}")
                score += weight
        return score, indicators

    def _check_network_indicators(self, network_metrics: Dict[str, Any]) -> Tuple[int, List[str]]:
        indicators: List[str] = []
        weight = self.rules["severity_weights"].get("network", 2)
        score = 0
        feats = (network_metrics or {}).get("features", {})

        total_events = int(feats.get("total_events", 0) or 0)
        foreign_connections = int(feats.get("foreign_connections", 0) or 0)
        unique_ports = feats.get("unique_ports", []) or []

        # DDoS-ish volume
        if total_events >= int(self.rules.get("ddos_min_total_events", 1000)) and foreign_connections >= int(self.rules.get("ddos_min_foreign_connections", 50)):
            indicators.append(f"High network volume: events={total_events}, foreign={foreign_connections}")
            score += weight

        # Port scan: many unique ports
        try:
            num_unique_ports = len(set(unique_ports))
            if num_unique_ports >= int(self.rules.get("port_scan_min_unique_ports", 50)):
                indicators.append(f"Possible port scan: unique_ports={num_unique_ports}")
                score += weight
        except Exception:
            pass

        # Many outbound connections
        if foreign_connections >= int(self.rules.get("high_outbound_connections", 30)):
            indicators.append(f"High outbound connections: {foreign_connections}")
            score += 1

        # High remote high port count (if present as pattern)
        suspicious_patterns = feats.get("suspicious_patterns", []) or []
        high_port_hits = len([p for p in suspicious_patterns if "High port number" in str(p)])
        if high_port_hits >= int(self.rules.get("high_remote_high_port_count", 20)):
            indicators.append(f"Many high remote ports observed: {high_port_hits}")
            score += 1

        return score, indicators

    def _check_dns_indicators(self, network_metrics: Dict[str, Any]) -> Tuple[int, List[str]]:
        indicators: List[str] = []
        weight = self.rules["severity_weights"].get("dns", 2)
        score = 0
        patterns = [p.lower() for p in self.rules.get("suspicious_dns_patterns", [])]
        feats = (network_metrics or {}).get("features", {})
        suspicious = feats.get("suspicious_patterns", []) or []
        for p in suspicious:
            lp = str(p).lower()
            if any(sig in lp for sig in patterns):
                indicators.append(f"Suspicious DNS pattern: {p}")
                score += weight
        return score, indicators

    def analyze(self, host_metrics: Dict[str, Any], network_metrics: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze metrics and return security assessment.

        Returns dict:
        {
          "is_security_threat": bool,
          "severity": "LOW|MEDIUM|HIGH|CRITICAL",
          "indicators": [str, ...],
          "score": int,
          "explanation": str,
          "timestamp": iso str
        }
        """
        total_score = 0
        all_indicators: List[str] = []

        s, ind = self._check_process_indicators(host_metrics or {})
        total_score += s
        all_indicators.extend(ind)

        s, ind = self._check_file_indicators(host_metrics or {})
        total_score += s
        all_indicators.extend(ind)

        s, ind = self._check_network_indicators(network_metrics or {})
        total_score += s
        all_indicators.extend(ind)

        s, ind = self._check_dns_indicators(network_metrics or {})
        total_score += s
        all_indicators.extend(ind)

        severity = self._score_to_severity(total_score)
        is_threat = severity in ("MEDIUM", "HIGH", "CRITICAL") and len(all_indicators) > 0

        explanation = "; ".join(all_indicators[:5])  # keep concise

        return {
            "is_security_threat": is_threat,
            "severity": severity,
            "indicators": all_indicators,
            "score": total_score,
            "explanation": explanation,
            "timestamp": datetime.now().isoformat(),
        }

    def get_status(self) -> Dict[str, Any]:
        return {
            "initialized": True,
            "config_path": self.config_path,
            "initialized_at": self.initialized_at
        }


