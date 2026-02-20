"""Quantile calibration for risk thresholds from request logs."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def _quantile(values: list[float], q: float) -> float:
    if not values:
        return 0.5
    ordered = sorted(values)
    q = max(0.0, min(1.0, q))
    idx = int(round((len(ordered) - 1) * q))
    return float(ordered[idx])


def calibrate(
    *,
    input_path: Path,
    output_path: Path,
    alpha: float,
    beta: float,
    benign_only: bool,
) -> dict[str, float | str]:
    risks: list[float] = []
    if input_path.exists():
        for raw in input_path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line:
                continue
            item = json.loads(line)
            if benign_only and item.get("traffic") != "benign":
                continue
            if item.get("decision") not in {"allow", "throttle"}:
                continue
            risks.append(float(item.get("risk", 0.0)))

    tau_allow = _quantile(risks, 1.0 - beta)
    tau_deny = max(tau_allow, _quantile(risks, 1.0 - alpha))
    output = {
        "tau_allow": tau_allow,
        "tau_deny": tau_deny,
        "alpha": alpha,
        "beta": beta,
        "count": len(risks),
        "source": str(input_path),
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(output, indent=2), encoding="utf-8")
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description="Calibrate risk quantiles")
    parser.add_argument("--input", default="gateway/logs/requests.jsonl")
    parser.add_argument("--output", default="gateway/policy/calibration.json")
    parser.add_argument("--alpha", type=float, default=0.01)
    parser.add_argument("--beta", type=float, default=0.05)
    parser.add_argument("--all-traffic", action="store_true")
    args = parser.parse_args()

    result = calibrate(
        input_path=Path(args.input),
        output_path=Path(args.output),
        alpha=args.alpha,
        beta=args.beta,
        benign_only=not args.all_traffic,
    )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
