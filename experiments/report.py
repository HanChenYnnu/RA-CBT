"""Aggregate experiment outputs into reports and simple plots."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any


def _load_runs(raw_dir: Path) -> list[dict[str, Any]]:
    return [json.loads(path.read_text(encoding="utf-8")) for path in sorted(raw_dir.glob("*.json"))]


def _write_svg_bar(
    path: Path,
    title: str,
    labels: list[str],
    values: list[float],
    y_max: float = 1.0,
) -> None:
    width, height, margin = 800, 320, 40
    chart_w, chart_h = width - 2 * margin, height - 2 * margin
    n = max(1, len(values))
    bar_w, gap = chart_w / n * 0.6, chart_w / n

    bars: list[str] = []
    texts: list[str] = []
    for i, (label, val) in enumerate(zip(labels, values, strict=False)):
        x = margin + i * gap + (gap - bar_w) / 2
        h = 0 if y_max <= 0 else chart_h * min(1.0, max(0.0, val / y_max))
        y = margin + chart_h - h
        bars.append(
            f'<rect x="{x:.1f}" y="{y:.1f}" width="{bar_w:.1f}" '
            f'height="{h:.1f}" fill="#4e79a7"/>'
        )
        texts.append(
            f'<text x="{x + bar_w/2:.1f}" y="{height - 8}" font-size="10" '
            f'text-anchor="middle">{label}</text>'
        )

    axis = (
        f'<line x1="{margin}" y1="{margin+chart_h}" '
        f'x2="{margin+chart_w}" y2="{margin+chart_h}" stroke="black"/>'
    )
    svg = (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}">'
        f'<rect width="100%" height="100%" fill="white"/>'
        f'<text x="{width/2}" y="20" font-size="16" text-anchor="middle">{title}</text>'
        f'{axis}{"".join(bars)}{"".join(texts)}</svg>'
    )
    path.write_text(svg, encoding="utf-8")


def generate_reports(raw_dir: Path, report_csv: Path, report_md: Path, plots_dir: Path) -> None:
    runs = _load_runs(raw_dir)
    report_csv.parent.mkdir(parents=True, exist_ok=True)
    plots_dir.mkdir(parents=True, exist_ok=True)

    with report_csv.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "baseline",
                "scenario",
                "attack_success_rate",
                "cost_leakage_tokens",
                "false_reject_rate",
                "throttle_rate",
                "latency_p50",
                "latency_p95",
                "raw_logs_path",
            ]
        )
        for run in runs:
            m = run["metrics"]
            writer.writerow(
                [
                    run["baseline"],
                    run["scenario"],
                    m["attack_success_rate"],
                    m["cost_leakage_tokens"],
                    m["false_reject_rate"],
                    m["throttle_rate"],
                    m["latency_p50"],
                    m["latency_p95"],
                    run["raw_logs_path"],
                ]
            )

    lines = [
        "# Experiment Report",
        "",
        "| baseline | scenario | attack_success_rate | false_reject_rate | throttle_rate |",
        "|---|---:|---:|---:|---:|",
    ]
    for run in runs:
        m = run["metrics"]
        lines.append(
            "| "
            f"{run['baseline']} | {run['scenario']} | {m['attack_success_rate']:.3f} | "
            f"{m['false_reject_rate']:.3f} | {m['throttle_rate']:.3f} |"
        )
    report_md.write_text("\n".join(lines) + "\n", encoding="utf-8")

    labels = [f"{r['baseline']}:{r['scenario']}" for r in runs]
    _write_svg_bar(
        plots_dir / "attack_success_rate.svg",
        "Attack Success Rate",
        labels,
        [float(r["metrics"]["attack_success_rate"]) for r in runs],
        y_max=1.0,
    )
    max_cost = max([float(r["metrics"]["cost_leakage_tokens"]) for r in runs] + [1.0])
    _write_svg_bar(
        plots_dir / "cost_leakage_tokens.svg",
        "Cost Leakage Tokens",
        labels,
        [float(r["metrics"]["cost_leakage_tokens"]) for r in runs],
        y_max=max_cost,
    )
    _write_svg_bar(
        plots_dir / "throttle_rate.svg",
        "Throttle Rate",
        labels,
        [float(r["metrics"]["throttle_rate"]) for r in runs],
        y_max=1.0,
    )
