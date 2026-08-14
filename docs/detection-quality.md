# Detection Quality

StegGuard does not claim that a clean scan proves a file is safe or human-made.
Detection rules are measured by family, format, and corpus version. Keyed and
vendor-specific watermarks need their official verifier.

## Versioned contract corpus

`tests/corpus/manifest-v1.json` describes harmless generated cases. Payloads
are stored as escaped text or hexadecimal bytes, so the repository does not
need live malicious documents. Each case records its detector family, format,
expected outcome, origin, and license.

Run the baseline evaluation with:

```bash
python scripts/evaluate_detection.py tests/corpus/manifest-v1.json
```

The command publishes sample count, format coverage, true and false positives,
true and false negatives, precision, recall, false-positive rate, and
false-negative rate. Metrics with no applicable denominator are `null`, not a
convenient 100 percent.

The checked-in result from the current implementation is
[`detection-baseline-v1.json`](detection-baseline-v1.json). It records 10
synthetic cases across five families and four formats. The perfect smoke-set
score must not be generalized beyond those exact fixtures.

This small corpus is a compatibility smoke set, not a representative accuracy
study. Production claims require independently sourced, legally distributable
benign and adversarial samples for every claimed family, reviewed labels,
confidence intervals, and documented sampling bias.

## Adding a detector

1. Add at least one realistic benign negative and one harmless generated
   positive.
2. Record provenance and license for every case.
3. Add a focused unit test for exact evidence and a corpus case for aggregate
   behavior.
4. Run the evaluator and investigate every metric regression.
5. Run `benchmarks/benchmark_scan.py` if the parser visits bulk data.
6. Record unavoidable blind spots and false-positive tradeoffs in the pull
   request and changelog.

False-positive and false-negative reports use the dedicated issue form. Reduce
private files to a synthetic reproducer before adding them to the corpus.
