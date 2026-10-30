# Local Scan Baseline

Reference run for StegGuard 0.3.0 on CPython 3.12.3, Linux 6.18 under WSL2,
x86-64. The command used five timed repetitions after a warm-up and one
separate `tracemalloc` pass:

```bash
python benchmarks/benchmark_scan.py --sizes 1024 1048576 --repeat 5
```

| Plain text input | Median wall time | Peak traced Python allocation |
| ---: | ---: | ---: |
| 1 KiB | 0.000349 s | 1,060,513 bytes |
| 1 MiB | 0.275031 s | 7,390,920 bytes |

These are observations, not universal service-level promises. As a local
regression guardrail on comparable hardware, a 1 MiB plain-text scan should
remain below 1 second and 16 MiB of traced Python allocation. Publish a new
dated baseline when Python, platform, parser behavior, or benchmark methodology
changes.

