from typing import Dict, Any, List
import math


class SecurityFeatureExtractor:
    """Derive compact security features from host and network metrics.

    Features include counts and simple statistics suitable for unsupervised
    anomaly detection (IsolationForest). No DPI required.
    """

    def extract(self, host_metrics: Dict[str, Any], network_metrics: Dict[str, Any]) -> List[float]:
        h = host_metrics or {}
        n = network_metrics or {}
        feats = []

        # Host features
        cpu = float(((h.get('system') or {}).get('cpu') or {}).get('percent', 0.0) or 0.0)
        mem = float(((h.get('system') or {}).get('memory') or {}).get('percent', 0.0) or 0.0)
        proc_list = h.get('processes') or []
        proc_count = float(len(proc_list))
        high_cpu_proc = float(sum(1 for p in proc_list if float(p.get('cpu_percent', 0) or 0) > 50.0))

        # Suspicious token count from legacy flag (if provided)
        suspicious_count = float(sum(1 for p in proc_list if p.get('is_suspicious')))

        # File integrity signals (use fim_detected markers if present)
        crit = (h.get('critical_files') or {})
        fim_changes = float(sum(1 for _, meta in crit.items() if isinstance(meta, dict) and meta.get('fim_detected')))

        # Network features
        nf = (n.get('features') or {})
        total_events = float(nf.get('total_events', 0) or 0)
        foreign_conn = float(nf.get('foreign_connections', 0) or 0)
        unique_ports = float(len(set(nf.get('unique_ports') or [])))
        dns_susp = float(len(nf.get('suspicious_patterns') or []))

        feats.extend([
            cpu, mem, proc_count, high_cpu_proc, suspicious_count,
            fim_changes, total_events, foreign_conn, unique_ports, dns_susp
        ])

        # Normalize simple bounded features (optional simple scaling)
        def norm01(x, maxv):
            try:
                return min(max(x / maxv, 0.0), 1.0)
            except Exception:
                return 0.0

        scaled = [
            norm01(cpu, 100.0), norm01(mem, 100.0), norm01(proc_count, 1000.0),
            norm01(high_cpu_proc, 50.0), norm01(suspicious_count, 50.0),
            norm01(fim_changes, 50.0), norm01(total_events, 10000.0),
            norm01(foreign_conn, 1000.0), norm01(unique_ports, 1000.0), norm01(dns_susp, 100.0)
        ]

        return feats + scaled


