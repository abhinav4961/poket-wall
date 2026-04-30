"""
Train the AI model — run on your dev machine, NOT on the Pi.
Generates ai_model.json from synthetic traffic data.
Usage: python3 train_model.py
"""

import json
import math
import random

SEED = 42
NUM_TREES = 100
SAMPLE_SIZE = 256
CONTAMINATION = 0.05
NUM_TRAINING_SAMPLES = 5000

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


def generate_normal_traffic(n: int) -> list[list[float]]:
    data = []
    for _ in range(n):
        conn_rate = random.gauss(0.05, 0.03)
        unique_ports = max(0, random.gauss(1.0, 0.5))
        unique_hosts = max(0, random.gauss(1.0, 0.5))
        avg_request_len = max(0, random.gauss(200, 100))
        error_rate = max(0, random.gauss(0.02, 0.01))
        special_char_ratio = max(0, random.gauss(0.01, 0.005))
        burst_count = max(0, random.gauss(1.0, 0.5))
        protocol_anomalies = max(0, random.gauss(0.0, 0.1))

        data.append([
            max(0, conn_rate),
            max(0, unique_ports),
            max(0, unique_hosts),
            max(0, avg_request_len),
            max(0, min(1, error_rate)),
            max(0, min(1, special_char_ratio)),
            max(0, burst_count),
            max(0, protocol_anomalies),
        ])
    return data


def generate_attack_traffic(n: int) -> list[list[float]]:
    attack_types = [
        # Port scanner
        lambda: [
            random.uniform(5, 30),
            random.uniform(20, 100),
            random.uniform(1, 5),
            random.uniform(50, 150),
            random.uniform(0.8, 1.0),
            random.uniform(0, 0.05),
            random.uniform(5, 30),
            random.uniform(0, 0.5),
        ],
        # SQLi / XSS attacker
        lambda: [
            random.uniform(0.5, 5),
            random.uniform(1, 5),
            random.uniform(1, 10),
            random.uniform(500, 3000),
            random.uniform(0.3, 0.8),
            random.uniform(0.1, 0.5),
            random.uniform(1, 5),
            random.uniform(0, 2),
        ],
        # Brute force
        lambda: [
            random.uniform(10, 50),
            random.uniform(1, 3),
            random.uniform(0.5, 2),
            random.uniform(100, 300),
            random.uniform(0.5, 0.95),
            random.uniform(0, 0.05),
            random.uniform(10, 50),
            random.uniform(0, 0.2),
        ],
        # DDoS
        lambda: [
            random.uniform(50, 200),
            random.uniform(1, 3),
            random.uniform(0.5, 2),
            random.uniform(20, 80),
            random.uniform(0.1, 0.5),
            random.uniform(0, 0.02),
            random.uniform(50, 200),
            random.uniform(0, 0.1),
        ],
        # Slow scanner
        lambda: [
            random.uniform(0.1, 0.5),
            random.uniform(5, 20),
            random.uniform(1, 5),
            random.uniform(100, 500),
            random.uniform(0.5, 0.9),
            random.uniform(0.05, 0.2),
            random.uniform(0, 1),
            random.uniform(0, 1),
        ],
    ]

    data = []
    for _ in range(n):
        attack_fn = random.choice(attack_types)
        data.append(attack_fn())
    return data


class IsolationTree:
    def __init__(self):
        self.tree = None

    def fit(self, data: list[list[float]], max_depth: int) -> dict:
        indices = list(range(len(data)))
        return self._build(data, indices, 0, max_depth)

    def _build(self, data, indices, depth, max_depth):
        if len(indices) <= 1 or depth >= max_depth:
            return {"type": "leaf", "indices": indices}

        n_features = len(data[0])
        feature = random.randint(0, n_features - 1)

        values = [data[i][feature] for i in indices]
        min_val = min(values)
        max_val = max(values)

        if min_val == max_val:
            return {"type": "leaf", "indices": indices}

        split = random.uniform(min_val, max_val)

        left = [i for i in indices if data[i][feature] < split]
        right = [i for i in indices if data[i][feature] >= split]

        if not left or not right:
            return {"type": "leaf", "indices": indices}

        return {
            "type": "split",
            "feature": feature,
            "split": split,
            "left": self._build(data, left, depth + 1, max_depth),
            "right": self._build(data, right, depth + 1, max_depth),
        }


def train():
    random.seed(SEED)
    print("[TRAIN] Generating synthetic traffic data...")

    normal = generate_normal_traffic(NUM_TRAINING_SAMPLES)
    attacks = generate_attack_traffic(int(NUM_TRAINING_SAMPLES * CONTAMINATION))
    data = normal + attacks
    random.shuffle(data)

    max_depth = int(math.ceil(math.log2(SAMPLE_SIZE)))
    print(f"[TRAIN] Training {NUM_TREES} isolation trees (max_depth={max_depth})...")

    trees = []
    for i in range(NUM_TREES):
        sample = random.sample(data, min(SAMPLE_SIZE, len(data)))
        tree = IsolationTree()
        trees.append(tree.fit(sample, max_depth))
        if (i + 1) % 20 == 0:
            print(f"[TRAIN] Tree {i + 1}/{NUM_TREES}")

    model = {
        "trees": trees,
        "sample_size": SAMPLE_SIZE,
        "contamination": CONTAMINATION,
        "feature_names": FEATURE_NAMES,
        "num_features": len(FEATURE_NAMES),
    }

    output_path = "ai_model.json"
    with open(output_path, "w") as f:
        json.dump(model, f)

    print(f"\n[TRAIN] Model saved to {output_path}")
    print(f"[TRAIN] File size: {len(json.dumps(model))} bytes")

    test_normal = [0.05, 1.0, 1.0, 200, 0.02, 0.01, 1.0, 0.0]
    test_attack = [20.0, 50.0, 3.0, 200, 0.9, 0.3, 20.0, 1.0]

    def score(x):
        def c(n):
            if n <= 1: return 0
            if n == 2: return 1
            return 2.0 * (math.log(n - 1) + 0.5772156649) - 2.0 * (n - 1) / n

        def path_length(x, tree, d=0):
            if tree["type"] == "leaf":
                return d + c(len(tree["indices"]))
            if x[tree["feature"]] < tree["split"]:
                return path_length(x, tree["left"], d + 1)
            return path_length(x, tree["right"], d + 1)

        avg = sum(path_length(x, t) for t in trees) / len(trees)
        cn = c(SAMPLE_SIZE)
        return 2 ** (-avg / cn) if cn else 0.5

    normal_score = score(test_normal)
    attack_score = score(test_attack)
    print(f"\n[TRAIN] Validation:")
    print(f"  Normal traffic score:  {normal_score:.4f}")
    print(f"  Attack traffic score:  {attack_score:.4f}")
    print(f"  Separation: {attack_score - normal_score:.4f}")


if __name__ == "__main__":
    train()
