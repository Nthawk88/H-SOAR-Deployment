import hashlib
import json
import os
from datetime import datetime
from typing import Dict, Any, List


class FileIntegrityMonitor:
    """Simple File Integrity Monitoring (FIM) with JSON baseline.

    Maintains a baseline of file paths -> sha256 hash + modified time.
    Detects changes by recomputing current hashes and comparing to baseline.
    """

    def __init__(self, baseline_path: str = "learning_data/signatures/fim_baseline.json"):
        self.baseline_path = baseline_path
        self.baseline = self._load_baseline()

    def _load_baseline(self) -> Dict[str, Any]:
        try:
            if os.path.exists(self.baseline_path):
                with open(self.baseline_path, "r", encoding="utf-8") as f:
                    return json.load(f)
        except Exception:
            pass
        return {"files": {}, "created_at": datetime.now().isoformat()}

    def _save_baseline(self):
        os.makedirs(os.path.dirname(self.baseline_path), exist_ok=True)
        with open(self.baseline_path, "w", encoding="utf-8") as f:
            json.dump(self.baseline, f, indent=2)

    def _sha256_file(self, path: str) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()

    def _stat_ts(self, path: str) -> str:
        try:
            mtime = os.path.getmtime(path)
            return datetime.fromtimestamp(mtime).isoformat()
        except Exception:
            return ""

    def build_baseline(self, paths: List[str]) -> Dict[str, Any]:
        files: Dict[str, Any] = {}
        for p in paths:
            if os.path.exists(p) and os.path.isfile(p):
                try:
                    files[p] = {
                        "sha256": self._sha256_file(p),
                        "modified": self._stat_ts(p)
                    }
                except Exception:
                    continue
        self.baseline = {"files": files, "created_at": datetime.now().isoformat()}
        self._save_baseline()
        return self.baseline

    def check_changes(self, paths: List[str]) -> Dict[str, Any]:
        changes: List[Dict[str, Any]] = []
        missing: List[str] = []
        new_files: List[str] = []
        baseline_files = self.baseline.get("files", {})

        for p in paths:
            if not os.path.exists(p):
                if p in baseline_files:
                    missing.append(p)
                continue
            if not os.path.isfile(p):
                continue
            try:
                cur_hash = self._sha256_file(p)
                cur_mod = self._stat_ts(p)
                base_ent = baseline_files.get(p)
                if not base_ent:
                    new_files.append(p)
                else:
                    if base_ent.get("sha256") != cur_hash:
                        changes.append({
                            "path": p,
                            "from": base_ent.get("sha256"),
                            "to": cur_hash,
                            "modified": cur_mod
                        })
            except Exception:
                continue

        return {
            "changes": changes,
            "missing": missing,
            "new_files": new_files,
            "timestamp": datetime.now().isoformat()
        }


