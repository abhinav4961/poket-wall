"""
Behavioral AI IDS — lightweight anomaly detection for Pi Zero 2W.
Pure Python, zero runtime dependencies. Pre-trained model.
"""

import json
import math
import os
import time
from collections import defaultdict, deque
from threading import Lock

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "ai_model.json")

FEATURE_NAMES = [
    "conn_rate",
    "unique_ports",
    "unique_hosts",
    "avg_request_len",
    "error_rate",
    "special_char_ratio",
    "burst_count",
    "protocol_anomalies",
]
NUM_FEATURES = len(FEATURE_NAMES)


class FeatureExtractor:
    """Tracks rolling behavioral features per IP."""

    WINDOW_SEC = 60

    def __init__(self):
        self._lock = Lock()
        self._connections: dict[str, deque] = defaultdict(lambda: deque())
        self._port_sets: dict[str, set] = defaultdict(set)
        self._host_sets: dict[str, set] = defaultdict(set)
        self._request_lengths: dict[str, deque] = defaultdict(lambda: deque())
        self._errors: dict[str, int] = defaultdict(int)
        self._total_requests: dict[str, int] = defaultdict(int)
        self._special_chars: dict[str, int] = defaultdict(int)
        self._burst_times: dict[str, deque] = defaultdict(lambda: deque())
        self._protocol_anomalies: dict[str, int] = defaultdict(int)
        self._last_scores: dict[str, dict] = {}

    def record_connection(self, ip: str, dest_port: int, dest_host: str = "", request_len: int = 0):
        now = time.time()
        with self._lock:
            self._connections[ip].append(now)
            self._port_sets[ip].add(dest_port)
            if dest_host:
                self._host_sets[ip].add(dest_host)
            if request_len > 0:
                self._request_lengths[ip].append(request_len)

    def record_error(self, ip: str):
        with self._lock:
            self._errors[ip] += 1

    def record_request(self, ip: str, raw_request: str = ""):
        SPECIAL_CHARS = set("../'\"<>%;()|&`\\x00")
        char_count = sum(1 for c in raw_request if c in SPECIAL_CHARS)
        with self._lock:
            self._total_requests[ip] += 1
            self._special_chars[ip] += char_count

            now = time.time()
            bt = self._burst_times[ip]
            bt.append(now)
            while bt and bt[0] < now - 1:
                bt.popleft()

    def record_protocol_anomaly(self, ip: str):
        with self._lock:
            self._protocol_anomalies[ip] += 1

    def get_features(self, ip: str) -> dict[str, float]:
        print(f"[FEAT-DEBUG] get_features for {ip}")
        now = time.time()
        window_start = now - self.WINDOW_SEC

        with self._lock:
            print(f"[FEAT-DEBUG] acquired lock for {ip}")
            conns = self._connections[ip]
            while conns and conns[0] < window_start:
                conns.popleft()

            bt = self._burst_times[ip]
            while bt and bt[0] < window_start:
                bt.popleft()

            rl = self._request_lengths[ip]

            conn_count = len(conns)
            conn_rate = conn_count / max(self.WINDOW_SEC, 1)
            unique_ports = len(self._port_sets[ip])
            unique_hosts = len(self._host_sets[ip])
            avg_req_len = sum(rl) / len(rl) if rl else 0
            total_req = max(self._total_requests[ip], 1)
            error_rate = self._errors[ip] / total_req
            total_chars_in_requests = sum(
                len(r) for r in ["" for _ in range(total_req)]
            )
            special_char_ratio = self._special_chars[ip] / total_req
            burst_count = len(bt)
            proto_anom = self._protocol_anomalies[ip]

            if conn_count < 2:
                self._port_sets[ip] = set()
                self._host_sets[ip] = set()
                while self._request_lengths[ip] and self._request_lengths[ip][0] < window_start:
                    self._request_lengths[ip].popleft()
                self._errors[ip] = 0
                self._total_requests[ip] = 0
                self._special_chars[ip] = 0

        return {
            "conn_rate": conn_rate,
            "unique_ports": unique_ports,
            "unique_hosts": unique_hosts,
            "avg_request_len": avg_req_len,
            "error_rate": error_rate,
            "special_char_ratio": special_char_ratio,
            "burst_count": burst_count,
            "protocol_anomalies": proto_anom,
        }

    def get_feature_vector(self, ip: str) -> list[float]:
        feats = self.get_features(ip)
        return [feats[name] for name in FEATURE_NAMES]

    def update_score(self, ip: str, score: float):
        with self._lock:
            self._last_scores[ip] = {
                "score": score,
                "timestamp": time.time(),
                "features": self.get_features(ip),
            }

    def get_score(self, ip: str) -> float:
        with self._lock:
            entry = self._last_scores.get(ip)
            if entry and time.time() - entry["timestamp"] < self.WINDOW_SEC * 2:
                return entry["score"]
            return 0.0


class IsolationForest:
    """Pure Python Isolation Forest — no numpy/sklearn at runtime."""

    def __init__(self):
        self.trees: list[dict] = []
        self.sample_size: int = 256
        self.contamination: float = 0.05

    def _path_length(self, x: list[float], tree: dict, depth: int = 0) -> float:
        if tree["type"] == "leaf":
            return depth + self._c(len(tree["indices"]))

        feature_idx = tree["feature"]
        split_val = tree["split"]

        if x[feature_idx] < split_val:
            return self._path_length(x, tree["left"], depth + 1)
        else:
            return self._path_length(x, tree["right"], depth + 1)

    def _c(self, n: int) -> float:
        if n <= 1:
            return 0
        if n == 2:
            return 1
        return 2.0 * (math.log(n - 1) + 0.5772156649) - 2.0 * (n - 1) / n

    def score(self, x: list[float]) -> float:
        """Returns anomaly score 0..1. Higher = more anomalous."""
        if not self.trees:
            return 0.0

        avg_path = sum(self._path_length(x, t) for t in self.trees) / len(self.trees)
        c_n = self._c(self.sample_size)
        if c_n == 0:
            return 0.5

        score = 2 ** (-avg_path / c_n)
        return min(1.0, max(0.0, score))

    def load(self, path: str = MODEL_PATH):
        """Load pre-trained model from JSON."""
        if not os.path.exists(path):
            print(f"[AI] Model file not found at {path} — using baseline only")
            return False

        try:
            with open(path) as f:
                data = json.load(f)
            self.trees = data["trees"]
            self.sample_size = data.get("sample_size", 256)
            self.contamination = data.get("contamination", 0.05)
            print(f"[AI] Model loaded: {len(self.trees)} trees")
            return True
        except Exception as e:
            print(f"[AI] Failed to load model: {e}")
            return False


class RollingBaseline:
    """Adaptive baseline that learns normal traffic over 24h."""

    def __init__(self):
        self._scores: deque = deque(maxlen=10000)
        self._start_time = time.time()
        self._warmup_sec = 3600
        self._mean = 0.3
        self._std = 0.15
        self._lock = Lock()

    def add_score(self, score: float):
        with self._lock:
            self._scores.append(score)
            if len(self._scores) > 100 and time.time() - self._start_time > self._warmup_sec:
                scores = list(self._scores)
                n = len(scores)
                self._mean = sum(scores) / n
                variance = sum((s - self._mean) ** 2 for s in scores) / n
                self._std = math.sqrt(variance) if variance > 0 else 0.01

    def get_threshold(self) -> float:
        return self._mean + 2.5 * max(self._std, 0.05)

    def get_stats(self) -> dict:
        with self._lock:
            return {
                "mean": round(self._mean, 3),
                "std": round(self._std, 3),
                "threshold": round(self.get_threshold(), 3),
                "samples": len(self._scores),
                "warmed_up": time.time() - self._start_time > self._warmup_sec,
            }


class DecisionEngine:
    """Combines all IDS signals into a final verdict."""

    def __init__(self):
        self.ai_weight = 0.4
        self.reputation_weight = 0.3
        self.geo_weight = 0.2
        self.behavior_weight = 0.1

        self.threshold_block = 0.7
        self.threshold_warn = 0.5

    def combine(
        self,
        ai_score: float,
        reputation_score: float,
        geo_blocked: bool,
        behavior_anomaly: float,
    ) -> tuple[str, str, float]:
        """Returns (verdict, reason, combined_score)."""
        if geo_blocked:
            return ("BLOCK", "Geo-blocked country", 1.0)

        combined = (
            ai_score * self.ai_weight
            + reputation_score * self.reputation_weight
            + behavior_anomaly * self.behavior_weight
        )

        if ai_score > 0.85:
            combined = max(combined, 0.75)

        if combined >= self.threshold_block:
            return ("BLOCK", f"AI anomaly score: {ai_score:.2f}, combined: {combined:.2f}", combined)
        elif combined >= self.threshold_warn:
            return ("WARN", f"Suspicious behavior: {combined:.2f}", combined)

        return ("ALLOW", "Clean", combined)


class AIEngine:
    """Main AI IDS engine — orchestrates feature extraction, model, and decisions."""

    def __init__(self):
        self.extractor = FeatureExtractor()
        self.model = IsolationForest()
        self.baseline = RollingBaseline()
        self.decision = DecisionEngine()
        self._lock = Lock()

        model_loaded = self.model.load()
        if model_loaded:
            print("[AI] Behavioral IDS ready")
        else:
            print("[AI] Using adaptive baseline only (no pre-trained model)")

    def record(self, ip: str, dest_port: int = 0, dest_host: str = "", request: str = "", request_len: int = 0):
        self.extractor.record_connection(ip, dest_port, dest_host, request_len)
        if request:
            self.extractor.record_request(ip, request)

    def record_error(self, ip: str):
        self.extractor.record_error(ip)

    def record_anomaly(self, ip: str):
        self.extractor.record_protocol_anomaly(ip)

    def check_ip(self, ip: str, reputation_score: float = 0.0, geo_blocked: bool = False) -> tuple[str, str, float]:
        print(f"[AI-DEBUG] check_ip called for {ip}")
        features = self.extractor.get_feature_vector(ip)
        print(f"[AI-DEBUG] got features for {ip}")
        ai_score = self.model.score(features)
        print(f"[AI-DEBUG] score={ai_score} for {ip}")
        self.baseline.add_score(ai_score)
        self.extractor.update_score(ip, ai_score)

        behavior_anomaly = ai_score
        if not self.model.trees:
            behavior_anomaly = ai_score if ai_score > self.baseline.get_threshold() else 0.0

        verdict, reason, combined = self.decision.combine(
            ai_score, reputation_score, geo_blocked, behavior_anomaly
        )
        print(f"[AI-DEBUG] verdict={verdict} for {ip}")

        return verdict, reason, combined

    def get_ai_stats(self) -> dict:
        return {
            "baseline": self.baseline.get_stats(),
            "model_loaded": bool(self.model.trees),
            "tree_count": len(self.model.trees),
        }

    def get_ip_details(self, ip: str) -> dict:
        features = self.extractor.get_features(ip)
        score = self.extractor.get_score(ip)
        return {
            "ai_score": round(score, 3),
            "features": {k: round(v, 2) for k, v in features.items()},
        }
