import json
import subprocess
from pathlib import Path

from gateway.risk_engine import RiskEngine, RiskPolicy


def test_risk_score_increases_on_drift_and_burst() -> None:
    policy = RiskPolicy(
        weights={
            "f_asn_change": 0.4,
            "f_country_change": 0.2,
            "f_device_change": 0.1,
            "f_ua_major_change": 0.1,
            "f_rpm_ratio": 0.05,
            "f_tpm_ratio": 0.1,
            "f_bucket_pressure": 0.05,
        },
        tau_allow=0.4,
        tau_deny=0.8,
        k=1.2,
    )
    engine = RiskEngine(policy)
    low, _ = engine.score(
        sub="u1",
        token_ctx={"asn": "AS1", "country": "US", "ua": "Browser/120", "device_id": "A"},
        current_ctx={"asn": "AS1", "country": "US", "ua": "Browser/120", "device_id": "A"},
        current_rpm=1.0,
        current_tpm=10.0,
        bucket_pressure=0.1,
    )
    high, _ = engine.score(
        sub="u1",
        token_ctx={"asn": "AS1", "country": "US", "ua": "Browser/120", "device_id": "A"},
        current_ctx={"asn": "AS9", "country": "DE", "ua": "Evil/9", "device_id": "B"},
        current_rpm=4.0,
        current_tpm=100.0,
        bucket_pressure=0.95,
    )
    assert high > low


def test_calibration_script_outputs_thresholds(tmp_path: Path) -> None:
    inp = tmp_path / "requests.jsonl"
    out = tmp_path / "calibration.json"
    rows = [
        {"risk": 0.10, "decision": "allow", "traffic": "benign"},
        {"risk": 0.20, "decision": "allow", "traffic": "benign"},
        {"risk": 0.30, "decision": "throttle", "traffic": "benign"},
        {"risk": 0.90, "decision": "deny", "traffic": "attack"},
    ]
    inp.write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")

    subprocess.run(
        [
            "python",
            "scripts/calibrate_quantiles.py",
            "--input",
            str(inp),
            "--output",
            str(out),
            "--alpha",
            "0.01",
            "--beta",
            "0.05",
        ],
        check=True,
    )

    data = json.loads(out.read_text(encoding="utf-8"))
    assert "tau_allow" in data
    assert "tau_deny" in data
    assert data["tau_deny"] >= data["tau_allow"]
