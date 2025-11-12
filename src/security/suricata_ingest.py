import json
from typing import Dict, Any, List, Iterable


class SuricataIngest:
    """Minimal Suricata eve.json ingestion (tail read, in-batch parse).

    This does not do file tailing; it parses up to N events from the file
    path provided by config each monitoring cycle (best-effort, safe if missing).
    """

    def __init__(self, eve_path: str, max_events: int = 500):
        self.eve_path = eve_path
        self.max_events = max_events

    def _read_lines(self) -> Iterable[str]:
        try:
            with open(self.eve_path, "r", encoding="utf-8", errors="ignore") as f:
                for i, line in enumerate(f):
                    if i >= self.max_events:
                        break
                    yield line.strip()
        except FileNotFoundError:
            return []
        except Exception:
            return []

    def parse_events(self) -> Dict[str, Any]:
        alerts: List[Dict[str, Any]] = []
        dns: int = 0
        http: int = 0
        tls: int = 0
        total: int = 0
        for line in self._read_lines():
            try:
                ev = json.loads(line)
                total += 1
                if ev.get("event_type") == "alert":
                    alerts.append({
                        "signature": ev.get("alert", {}).get("signature"),
                        "severity": ev.get("alert", {}).get("severity"),
                        "src_ip": ev.get("src_ip"),
                        "dest_ip": ev.get("dest_ip"),
                        "proto": ev.get("proto")
                    })
                elif ev.get("event_type") == "dns":
                    dns += 1
                elif ev.get("event_type") == "http":
                    http += 1
                elif ev.get("event_type") == "tls":
                    tls += 1
            except Exception:
                continue

        return {
            "total_events": total,
            "alerts": alerts,
            "dns_events": dns,
            "http_events": http,
            "tls_events": tls
        }


