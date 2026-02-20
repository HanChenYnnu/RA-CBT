"""Reproducible experiment runner for baselines and scenarios."""

from __future__ import annotations

import argparse
import asyncio
import json
import random
import time
from pathlib import Path
from typing import Any

import httpx
from experiments.metrics import compute_metrics
from experiments.report import generate_reports

BASELINES = ["B0_static", "B1_ip_allow", "B2_bearer_short", "B3_pop_only", "B4_full"]
SCENARIOS = ["S1_key_leak", "S2_token_leak", "S3_replay", "S4_burst", "S5_slowdrip", "S6_drift"]


def _scenario_profile(scenario: str) -> dict[str, Any]:
    mapping = {
        "S1_key_leak": {"risk": 0.70, "traffic": "attack"},
        "S2_token_leak": {"risk": 0.65, "traffic": "attack"},
        "S3_replay": {"risk": 0.90, "traffic": "attack"},
        "S4_burst": {"risk": 0.75, "traffic": "attack"},
        "S5_slowdrip": {"risk": 0.45, "traffic": "attack"},
        "S6_drift": {"risk": 0.55, "traffic": "attack"},
    }
    return mapping[scenario]


def _baseline_thresholds(baseline: str) -> tuple[float, float]:
    if baseline == "B0_static":
        return 1.1, 1.2
    if baseline == "B1_ip_allow":
        return 0.95, 1.1
    if baseline == "B2_bearer_short":
        return 0.8, 1.0
    if baseline == "B3_pop_only":
        return 0.65, 0.9
    return 0.45, 0.8


async def _mock_upstream_call() -> tuple[int, dict[str, Any], int]:
    start = time.perf_counter()
    async with httpx.AsyncClient(timeout=2.0) as client:
        response = await client.post(
            "http://mock-upstream.local/v1/chat/completions",
            json={"model": "gpt-4o-mini"},
            headers={"Authorization": "Bearer mock"},
        )
    latency_ms = int((time.perf_counter() - start) * 1000)
    body = response.json() if isinstance(response.json(), dict) else {}
    return response.status_code, body, max(1, latency_ms)


async def run_once(
    baseline: str,
    scenario: str,
    out_dir: Path,
    requests_per_run: int,
    seed: int,
) -> dict[str, Any]:
    random.seed(seed)
    out_dir.mkdir(parents=True, exist_ok=True)
    raw_log_path = out_dir / f"{baseline}__{scenario}.jsonl"

    prof = _scenario_profile(scenario)
    tau_allow, tau_deny = _baseline_thresholds(baseline)

    events: list[dict[str, Any]] = []
    raw_lines: list[str] = []

    import respx

    with respx.mock() as router:
        router.post("http://mock-upstream.local/v1/chat/completions").respond(
            status_code=200,
            json={"id": "mock", "usage": {"total_tokens": 8}},
        )

        for i in range(requests_per_run):
            traffic = "benign" if i % 4 == 0 else prof["traffic"]
            base_risk = 0.08 if traffic == "benign" else float(prof["risk"])
            risk = max(0.0, min(1.0, base_risk + random.uniform(-0.05, 0.05)))

            if risk >= tau_deny:
                status = 403
                decision = "deny"
                reject_reason = "risk_deny"
                usage_tokens = 0
                latency_ms = random.randint(1, 3)
            elif risk >= tau_allow:
                status, _body, latency_ms = await _mock_upstream_call()
                decision = "throttle"
                reject_reason = None
                usage_tokens = 8
            else:
                status, _body, latency_ms = await _mock_upstream_call()
                decision = "allow"
                reject_reason = None
                usage_tokens = 8

            event = {
                "ts": int(time.time()),
                "sub": "user_001",
                "jti": f"{baseline}-{scenario}-{i}",
                "risk": round(risk, 6),
                "traffic": traffic,
                "decision": decision,
                "reject_reason": reject_reason,
                "status": status,
                "precharge": 12,
                "usage_tokens": usage_tokens,
                "latency_ms": latency_ms,
            }
            events.append(event)
            raw_lines.append(json.dumps(event, separators=(",", ":")))

    raw_log_path.write_text("\n".join(raw_lines) + "\n", encoding="utf-8")
    metrics = compute_metrics(events)
    run_json = {
        "baseline": baseline,
        "scenario": scenario,
        "metrics": metrics,
        "raw_logs_path": str(raw_log_path),
    }
    (out_dir / f"{baseline}__{scenario}.json").write_text(
        json.dumps(run_json, indent=2),
        encoding="utf-8",
    )
    return run_json


async def run_all(output_root: Path, requests_per_run: int) -> list[dict[str, Any]]:
    raw_dir = output_root / "raw"
    runs: list[dict[str, Any]] = []
    seed = 7
    for baseline in BASELINES:
        for scenario in SCENARIOS:
            runs.append(
                await run_once(
                    baseline=baseline,
                    scenario=scenario,
                    out_dir=raw_dir,
                    requests_per_run=requests_per_run,
                    seed=seed,
                )
            )
            seed += 1
    generate_reports(
        raw_dir=raw_dir,
        report_csv=output_root / "report.csv",
        report_md=output_root / "report.md",
        plots_dir=output_root / "plots",
    )
    return runs


def main() -> None:
    parser = argparse.ArgumentParser(description="RA-CBT experiments runner")
    parser.add_argument("--all", action="store_true", help="Run all baselines and scenarios")
    parser.add_argument("--baseline", default="B4_full")
    parser.add_argument("--scenario", default="S4_burst")
    parser.add_argument("--requests", type=int, default=30)
    parser.add_argument("--output", default="results")
    args = parser.parse_args()

    out = Path(args.output)
    if args.all:
        runs = asyncio.run(run_all(out, args.requests))
        print(json.dumps({"runs": len(runs), "report_csv": str(out / 'report.csv')}, indent=2))
        return

    run = asyncio.run(
        run_once(
            baseline=args.baseline,
            scenario=args.scenario,
            out_dir=out / "raw",
            requests_per_run=args.requests,
            seed=7,
        )
    )
    generate_reports(
        raw_dir=out / "raw",
        report_csv=out / "report.csv",
        report_md=out / "report.md",
        plots_dir=out / "plots",
    )
    print(json.dumps(run, indent=2))


if __name__ == "__main__":
    main()
