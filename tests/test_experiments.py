from pathlib import Path

from experiments.runner import run_all


def test_runner_all_produces_report_and_plots(tmp_path: Path) -> None:
    import asyncio

    output = tmp_path / "results"
    runs = asyncio.run(run_all(output, requests_per_run=8))
    assert len(runs) == 30  # 5 baselines * 6 scenarios

    report_csv = output / "report.csv"
    report_md = output / "report.md"
    plots = output / "plots"

    assert report_csv.exists()
    assert report_md.exists()
    assert (plots / "attack_success_rate.svg").exists()
    assert (plots / "cost_leakage_tokens.svg").exists()
    assert (plots / "throttle_rate.svg").exists()
