"""Generate attack-like gateway traffic for quick local checks."""

from __future__ import annotations

import argparse
import pathlib
import subprocess
import sys


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate attack traffic samples")
    parser.add_argument("--n", type=int, default=50, help="Number of attack requests")
    args = parser.parse_args()

    root = pathlib.Path(__file__).resolve().parents[1]
    subprocess.run(
        [
            sys.executable,
            str(root / "scripts" / "bench_simple.py"),
            "--mode",
            "attack",
            "--n",
            str(args.n),
        ],
        check=True,
    )


if __name__ == "__main__":
    main()
