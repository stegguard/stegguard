# Benchmarks

`benchmark_scan.py` generates deterministic plain and suspicious text files in
a temporary directory. It records elapsed wall time and peak Python allocation
for representative sizes without retaining the inputs.

```bash
python benchmarks/benchmark_scan.py --sizes 1024 1048576
```

Benchmark numbers depend on Python, CPU, filesystem, optional dependencies, and
build mode. Record those fields with every published result. The configured
resource budgets in `docs/resource-limits.md` are safety ceilings, not latency
promises.

The current local reference and deliberately loose regression guardrail are in
[BASELINE.md](BASELINE.md).
