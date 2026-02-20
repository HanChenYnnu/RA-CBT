"""Risk scoring and adaptive budget calibration helpers."""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from pathlib import Path
from statistics import median
from typing import Any


@dataclass
class RiskPolicy:
    weights: dict[str, float]
    tau_allow: float
    tau_deny: float
    k: float


def _ua_major(ua: str) -> str:
    parts = ua.split("/")
    if len(parts) < 2:
        return ua
    return f"{parts[0]}/{parts[1].split('.')[0]}"


class RiskEngine:
    def __init__(self, policy: RiskPolicy) -> None:
        self.policy = policy
        self._rpm_hist: dict[str, list[float]] = {}
        self._tpm_hist: dict[str, list[float]] = {}

    def _rolling_median(
        self,
        store: dict[str, list[float]],
        sub: str,
        default: float = 1.0,
    ) -> float:
        vals = store.get(sub, [])
        return float(median(vals)) if vals else default

    def _append_hist(self, store: dict[str, list[float]], sub: str, value: float) -> None:
        vals = store.setdefault(sub, [])
        vals.append(float(value))
        if len(vals) > 120:
            del vals[0]

    def score(
        self,
        *,
        sub: str,
        token_ctx: dict[str, Any],
        current_ctx: dict[str, Any],
        current_rpm: float,
        current_tpm: float,
        bucket_pressure: float,
    ) -> tuple[float, dict[str, float]]:
        token_ua = str(token_ctx.get("ua", ""))
        current_ua = str(current_ctx.get("ua", ""))

        f_asn_change = (
            1.0 if str(token_ctx.get("asn", "")) != str(current_ctx.get("asn", "")) else 0.0
        )
        f_country_change = (
            1.0 if str(token_ctx.get("country", "")) != str(current_ctx.get("country", "")) else 0.0
        )
        f_device_change = (
            1.0
            if str(token_ctx.get("device_id", "")) != str(current_ctx.get("device_id", ""))
            else 0.0
        )
        f_ua_major_change = 1.0 if _ua_major(token_ua) != _ua_major(current_ua) else 0.0

        rpm_med = max(
            1e-6,
            self._rolling_median(self._rpm_hist, sub, default=max(1.0, current_rpm)),
        )
        tpm_med = max(
            1e-6,
            self._rolling_median(self._tpm_hist, sub, default=max(1.0, current_tpm)),
        )
        f_rpm_ratio = min(5.0, current_rpm / rpm_med)
        f_tpm_ratio = min(5.0, current_tpm / tpm_med)
        f_bucket_pressure = min(1.0, max(0.0, bucket_pressure))

        features = {
            "f_asn_change": f_asn_change,
            "f_country_change": f_country_change,
            "f_device_change": f_device_change,
            "f_ua_major_change": f_ua_major_change,
            "f_rpm_ratio": f_rpm_ratio,
            "f_tpm_ratio": f_tpm_ratio,
            "f_bucket_pressure": f_bucket_pressure,
        }

        raw = 0.0
        for key, value in features.items():
            raw += float(self.policy.weights.get(key, 0.0)) * float(value)
        score = max(0.0, min(1.0, raw))

        self._append_hist(self._rpm_hist, sub, current_rpm)
        self._append_hist(self._tpm_hist, sub, current_tpm)
        return score, features

    def scale_factor(self, risk: float) -> float:
        return float(math.exp(-self.policy.k * max(0.0, min(1.0, risk))))


def load_risk_policy(policy_path: str | Path | None = None) -> RiskPolicy:
    path = Path(policy_path) if policy_path else Path("gateway/policy/risk.json")
    if not path.exists():
        return RiskPolicy(
            weights={
                "f_asn_change": 0.3,
                "f_country_change": 0.2,
                "f_device_change": 0.1,
                "f_ua_major_change": 0.15,
                "f_rpm_ratio": 0.05,
                "f_tpm_ratio": 0.1,
                "f_bucket_pressure": 0.1,
            },
            tau_allow=0.45,
            tau_deny=0.8,
            k=1.2,
        )

    data = json.loads(path.read_text(encoding="utf-8"))
    calibration_path = Path("gateway/policy/calibration.json")
    if calibration_path.exists():
        calib = json.loads(calibration_path.read_text(encoding="utf-8"))
        data["tau_allow"] = float(calib.get("tau_allow", data.get("tau_allow", 0.45)))
        data["tau_deny"] = float(calib.get("tau_deny", data.get("tau_deny", 0.8)))

    return RiskPolicy(
        weights={k: float(v) for k, v in dict(data.get("weights", {})).items()},
        tau_allow=float(data.get("tau_allow", 0.45)),
        tau_deny=float(data.get("tau_deny", 0.8)),
        k=float(data.get("k", 1.2)),
    )
