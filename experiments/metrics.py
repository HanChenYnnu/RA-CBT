"""Metric computation for RA-CBT experiments."""

from __future__ import annotations

from statistics import median
from typing import Any


def _percentile(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = min(len(ordered) - 1, max(0, int(round((len(ordered) - 1) * p))))
    return float(ordered[idx])


def compute_metrics(events: list[dict[str, Any]]) -> dict[str, float]:
    attacks = [e for e in events if e.get("traffic") == "attack"]
    benign = [e for e in events if e.get("traffic") == "benign"]

    attack_success = sum(1 for e in attacks if e.get("status") == 200)
    attack_total = max(1, len(attacks))
    attack_success_rate = attack_success / attack_total

    cost_leakage_tokens = float(
        sum(int(e.get("usage_tokens", 0)) for e in attacks if e.get("status") == 200)
    )

    benign_reject = sum(1 for e in benign if int(e.get("status", 0)) >= 400)
    benign_total = max(1, len(benign))
    false_reject_rate = benign_reject / benign_total

    throttle_count = sum(1 for e in events if e.get("decision") == "throttle")
    throttle_rate = throttle_count / max(1, len(events))

    latencies = [float(e.get("latency_ms", 0.0)) for e in events]
    latency_p50 = median(latencies) if latencies else 0.0
    latency_p95 = _percentile(latencies, 0.95)

    return {
        "attack_success_rate": attack_success_rate,
        "cost_leakage_tokens": cost_leakage_tokens,
        "false_reject_rate": false_reject_rate,
        "throttle_rate": throttle_rate,
        "latency_p50": latency_p50,
        "latency_p95": latency_p95,
    }
