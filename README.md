# RA-CBT Stage Scaffold

Production-quality Python scaffold for the RA-CBT gateway project.

## Layout

- `gateway/`: FastAPI app, config, JWT/DPoP verification, context binding, risk engine, and budgeted proxy modules
- `client/`: local OpenAI-compatible client + DPoP helpers
- `scripts/`: scenario/benchmark helpers (`demo_dpop.py`, `bench_simple.py`, `calibrate_quantiles.py`)
- `experiments/`: reproducible experiment runner + metrics/report tooling
- `tests/`: pytest test suite

## Quickstart

```bash
make setup
make test
make lint
```

## Stage 6: Risk + calibration + adaptive budget

Risk features (MVP): ASN/country/device/UA-major change, RPM/TPM ratio vs rolling median, and bucket pressure.

Decision policy:
- `risk >= tau_deny`: deny (`risk_deny`)
- `tau_allow <= risk < tau_deny`: throttle (adaptive budget + lower `max_tokens`)
- otherwise: allow

Adaptive budget scaling:
- `rpm_eff = base_rpm * exp(-k*risk)`
- `tpm_eff = base_tpm * exp(-k*risk)`
- `burst_eff = base_burst * exp(-k*risk)`

## Calibration and traffic workflow

1) Generate benign traffic:

```bash
python scripts/bench_simple.py --mode benign --n 50
```

2) Calibrate quantile thresholds from request logs:

```bash
python scripts/calibrate_quantiles.py \
  --input gateway/logs/requests.jsonl \
  --output gateway/policy/calibration.json \
  --alpha 0.01 --beta 0.05
```

3) Run attack traffic and observe deny/throttle behavior:

```bash
python scripts/bench_simple.py --mode attack --n 50
```

## Stage 7: Experiments runner

Run all baselines (`B0..B4`) across scenarios (`S1..S6`) and aggregate report outputs:

```bash
python -m experiments.runner --all --output results
```

This produces:
- `results/report.csv`
- `results/report.md`
- plot artifacts in `results/plots/` (attack success, leakage, throttle rate)

## Logging

Each request appends JSONL to `gateway/logs/requests.jsonl` with:
`ts, sub, jti, risk, decision, reject_reason, precharge, usage, latency_ms, traffic`.

## Stage 8: One-command end-to-end run

Run the full local pipeline:

```bash
make all
```

Pipeline steps:
1. start gateway in background
2. generate benign traffic
3. calibrate thresholds
4. run all scenarios + baselines
5. generate `results/report.csv`, `results/report.md`, and plots
6. stop gateway

For a quick smoke run:

```bash
BENIGN_N=8 EXPERIMENT_REQUESTS=4 make all
```
