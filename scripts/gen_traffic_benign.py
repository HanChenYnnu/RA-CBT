"""Generate benign gateway traffic for calibration."""

from __future__ import annotations

import argparse
import pathlib
import subprocess
import sys


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate benign traffic samples")
    parser.add_argument("--n", type=int, default=50, help="Number of benign requests")
    args = parser.parse_args()

    root = pathlib.Path(__file__).resolve().parents[1]
    subprocess.run(
        [
            sys.executable,
            str(root / "scripts" / "bench_simple.py"),
            "--mode",
            "benign",
            "--n",
            str(args.n),
        ],
        check=True,
    )


if __name__ == "__main__":
    main()
