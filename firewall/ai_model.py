"""
Behavioral AI IDS — batch log analyzer for Pi Zero 2W.
Pure Python, zero runtime dependencies. Pre-trained model.
Runs periodic analysis on collected logs, not per-connection.
"""

import json
import math
import os
import time
from collections import defaultdict, deque
from threading import Lock, Thread

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

SPECIAL_CHARS = set("../'\"<>%;()|&`\\x00")


class FeatureExtractor:
    """Accumulates per-IP stats for batch analysis."""

    def __init__(self):
        self._lock = Lock()
        self._connections = defaultdict(list)
        self._port_sets = defaultdict(set)
        self._host_sets = defaultdict(set)
        self._request_lengths = defaultdict(list)
        self._errors = defaultdict(int)
        self._total_requests = defaultdict(int)
        self._special_chars = defaultdict(int)
        self._burst_times = defaultdict(list)
        self._protocol_anomalies = defaultdict(int)

    def record_connection(self, ip, dest_port=0, dest_host="", request_len=0):
        with self._lock:
            self._connections[ip].append(time.time())
            if dest_port:
                self._port_sets[ip].add(dest_port)
            if dest_host:
                self._host_sets[ip].add(dest_host)
            if request_len > 0:
                self._request_lengths[ip].append(request_len)

    def record_error(self, ip):
        with self._lock:
            self._errors[ip] += 1

    def record_request(self, ip, raw_request=""):
        char_count = sum(1 for c in raw_request if c in SPECIAL_CHARS)
        with self._lock:
            self._total_requests[ip] += 1
            self._special_chars[ip] += char_count
            self._burst_times[ip].append(time.time())

    def record_protocol_anomaly(self, ip):
        with self._lock:
            self._protocol_anomalies[ip] += 1

    def get_features(self, ip, window_sec=60):
        now = time.time()
        window_start = now - window_sec
        with self._lock:
            conns = [t for t in self._connections[ip] if t >= window_start]
            bursts = [t for t in self._burst_times[ip] if t >= window_start]
            req_lens = [l for l in self._request_lengths[ip] if l > 0]

            total_req = self._total_requests[ip]
            if total_req == 0:
                total_req = 1

            return {
                "conn_rate": len(conns) / max(window_sec, 1),
                "unique_ports": len(self._port_sets[ip]),
                "unique_hosts": len(self._host_sets[ip]),
                "avg_request_len": sum(req_lens) / len(req_lens) if req_lens else 0,
                "error_rate": self._errors[ip] / total_req,
                "special_char_ratio": self._special_chars[ip] / total_req,
                "burst_count": len(bursts),
                "protocol_anomalies": self._protocol_anomalies[ip],
            }

    def get_feature_vector(self, ip):
        feats = self.get_features(ip)
        return [feats[name] for name in FEATURE_NAMES]

    def get_all_ips(self):
        with self._lock:
            return set(self._connections.keys())

    def reset_window(self, window_sec=60):
        now = time.time()
        cutoff = now - window_sec * 2
        with self._lock:
            ips_to_remove = []
            for ip in list(self._connections.keys()):
                self._connections[ip] = [t for t in self._connections[ip] if t >= cutoff]
                self._burst_times[ip] = [t for t in self._burst_times[ip] if t >= cutoff]
                self._request_lengths[ip] = [l for l in self._request_lengths[ip] if l > 0][-1000:]
                if not self._connections[ip]:
                    ips_to_remove.append(ip)

            for ip in ips_to_remove:
                del self._connections[ip]
                del self._port_sets[ip]
                del self._host_sets[ip]
                del self._request_lengths[ip]
                del self._errors[ip]
                del self._total_requests[ip]
                del self._special_chars[ip]
                del self._burst_times[ip]
                del self._protocol_anomalies[ip]


class IsolationForest:
    """Pure Python Isolation Forest — no numpy/sklearn at runtime."""

    def __init__(self):
        self.trees = []
        self.sample_size = 256
        self.contamination = 0.05

    def _path_length(self, x, tree, depth=0):
        if tree["type"] == "leaf":
            return depth + self._c(len(tree["indices"]))
        if x[tree["feature"]] < tree["split"]:
            return self._path_length(x, tree["left"], depth + 1)
        return self._path_length(x, tree["right"], depth + 1)

    def _c(self, n):
        if n <= 1:
            return 0
        if n == 2:
            return 1
        return 2.0 * (math.log(n - 1) + 0.5772156649) - 2.0 * (n - 1) / n

    def score(self, x):
        if not self.trees:
            return 0.0
        avg_path = sum(self._path_length(x, t) for t in self.trees) / len(self.trees)
        c_n = self._c(self.sample_size)
        if c_n == 0:
            return 0.5
        return min(1.0, max(0.0, 2 ** (-avg_path / c_n)))

    def load(self, path=MODEL_PATH):
        if not os.path.exists(path):
            print(f"[AI] Model file not found at {path}")
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
    """Adaptive baseline that learns normal traffic over time."""

    def __init__(self):
        self._scores = []
        self._start_time = time.time()
        self._warmup_sec = 300
        self._mean = 0.3
        self._std = 0.15
        self._lock = Lock()

    def add_scores(self, scores):
        with self._lock:
            self._scores.extend(scores)
            if len(self._scores) > 100 and time.time() - self._start_time > self._warmup_sec:
                n = len(self._scores)
                self._mean = sum(self._scores) / n
                variance = sum((s - self._mean) ** 2 for s in self._scores) / n
                self._std = math.sqrt(variance) if variance > 0 else 0.01

    def get_threshold(self):
        return self._mean + 2.0 * max(self._std, 0.05)

    def get_stats(self):
        with self._lock:
            return {
                "mean": round(self._mean, 3),
                "std": round(self._std, 3),
                "threshold": round(self.get_threshold(), 3),
                "samples": len(self._scores),
                "warmed_up": time.time() - self._start_time > self._warmup_sec,
            }


class DecisionEngine:
    """Combines all IDS signals into a final verdict with suggestions."""

    def __init__(self):
        self.threshold_block = 0.55
        self.threshold_warn = 0.40

    def combine(self, ai_score, geo_blocked=False):
        if geo_blocked:
            return "BLOCK", "Geo-blocked country", 1.0, ["Enable geo-blocking for suspicious regions"]

        if ai_score >= self.threshold_block:
            suggestions = self._generate_suggestions(ai_score)
            return "BLOCK", f"AI anomaly score: {ai_score:.2f}", ai_score, suggestions
        elif ai_score >= self.threshold_warn:
            suggestions = self._generate_suggestions(ai_score)
            return "WARN", f"Suspicious behavior: {ai_score:.2f}", ai_score, suggestions
        return "ALLOW", "Clean", ai_score, []

    def _generate_suggestions(self, score):
        suggestions = []
        if score > 0.85:
            suggestions.append("Critical threat — permanent block recommended")
        if score > 0.7:
            suggestions.append("High risk — consider permanent block")
        if score > 0.5:
            suggestions.append("Monitor closely — repeated warnings should trigger auto-block")
        return suggestions


class AIEngine:
    """Batch AI IDS — analyzes traffic periodically, not per-connection."""

    def __init__(self, analysis_interval=30, block_callback=None):
        self.extractor = FeatureExtractor()
        self.model = IsolationForest()
        self.baseline = RollingBaseline()
        self.decision = DecisionEngine()
        self._lock = Lock()
        self._block_callback = block_callback

        self._alerts = deque(maxlen=200)
        self._ip_scores = {}
        self._running = False
        self._interval = analysis_interval
        self._stats = {"total_analyses": 0, "total_alerts": 0, "total_blocked": 0}

        model_loaded = self.model.load()
        if model_loaded:
            print("[AI] Batch analyzer ready")
        else:
            print("[AI] Using adaptive baseline only")

    def start_background(self):
        self._running = True
        t = Thread(target=self._analysis_loop, daemon=True)
        t.start()
        print(f"[AI] Batch analysis every {self._interval}s — auto-block enabled")

    def stop(self):
        self._running = False

    def record(self, ip, dest_port=0, dest_host="", request="", request_len=0):
        self.extractor.record_connection(ip, dest_port, dest_host, request_len)
        if request:
            self.extractor.record_request(ip, request)

    def record_error(self, ip):
        self.extractor.record_error(ip)

    def record_anomaly(self, ip):
        self.extractor.record_protocol_anomaly(ip)

    def _analysis_loop(self):
        while self._running:
            time.sleep(self._interval)
            self._run_analysis()

    def _run_analysis(self):
        try:
            all_ips = self.extractor.get_all_ips()
            if not all_ips:
                return

            scores = []
            for ip in all_ips:
                features = self.extractor.get_feature_vector(ip)
                ai_score = self.model.score(features)
                scores.append(ai_score)

                with self._lock:
                    self._ip_scores[ip] = ai_score

                verdict, reason, combined, suggestions = self.decision.combine(ai_score)
                if verdict == "BLOCK":
                    alert = {
                        "timestamp": time.time(),
                        "ip": ip,
                        "score": ai_score,
                        "verdict": verdict,
                        "reason": reason,
                        "features": self.extractor.get_features(ip),
                        "suggestions": suggestions,
                    }
                    with self._lock:
                        self._alerts.append(alert)
                    self._stats["total_alerts"] += 1

                    # AUTO-BLOCK: Call back to IDS engine to block this IP
                    if self._block_callback:
                        self._block_callback(ip)
                        self._stats["total_blocked"] += 1

                    print(f"[AI-BLOCK] {ip} score={ai_score:.2f} {reason}")

                elif verdict == "WARN":
                    alert = {
                        "timestamp": time.time(),
                        "ip": ip,
                        "score": ai_score,
                        "verdict": verdict,
                        "reason": reason,
                        "features": self.extractor.get_features(ip),
                        "suggestions": suggestions,
                    }
                    with self._lock:
                        self._alerts.append(alert)
                    self._stats["total_alerts"] += 1
                    print(f"[AI-WARN] {ip} score={ai_score:.2f} {reason}")

            self.baseline.add_scores(scores)
            self.extractor.reset_window()
            self._stats["total_analyses"] += 1

        except Exception as e:
            print(f"[AI] Analysis error: {e}")

    def get_ai_stats(self):
        return {
            "baseline": self.baseline.get_stats(),
            "model_loaded": bool(self.model.trees),
            "tree_count": len(self.model.trees),
            "interval_sec": self._interval,
            "analyses_run": self._stats["total_analyses"],
            "total_alerts": self._stats["total_alerts"],
            "total_blocked": self._stats["total_blocked"],
        }

    def get_alerts(self, limit=50):
        with self._lock:
            return list(self._alerts)[-limit:]

    def get_suspicious_ips(self, threshold=0.4):
        with self._lock:
            return {ip: score for ip, score in self._ip_scores.items() if score >= threshold}

    def get_ip_score(self, ip):
        return self._ip_scores.get(ip, 0.0)

    def get_ip_details(self, ip):
        features = self.extractor.get_features(ip)
        with self._lock:
            score = self._ip_scores.get(ip, 0.0)
        _, reason, _, suggestions = self.decision.combine(score)
        return {
            "ai_score": round(score, 3),
            "features": {k: round(v, 2) for k, v in features.items()},
            "verdict_reason": reason,
            "suggestions": suggestions,
        }
