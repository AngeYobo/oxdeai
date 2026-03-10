# OxDeAI Benchmark Suite

This folder contains a reproducible, statistically meaningful benchmark suite for the OxDeAI core policy/verification engine.

Commands:
- `pnpm bench` (when script added in root package)
- `pnpm exec tsx bench/index.ts -- --scenario=all --workers=4 --duration=30`

Outputs:
- `bench/outputs/latest.json`
- `bench/outputs/run-<timestamp>.json`
