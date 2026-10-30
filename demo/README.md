# StegGuard Demo

This offline demonstration exercises the real StegGuard command-line interface
from detection through verification. It creates only deterministic synthetic
fixtures. The hidden text is the harmless word `DEMO`; no executable or
malicious payload is included.

## Run it

From the `stegguard-oss` directory:

```bash
python3 demo/run_demo.py
```

The command creates `demo-output/` and performs five steps:

1. Detects zero-width text, mixed line endings, trailing whitespace, and a
   Cyrillic homoglyph.
2. Decodes the zero-width text as `DEMO` without changing the source.
3. Writes a sanitized copy and records its before-and-after hashes and diff.
4. Scans the sanitized copy to verify that the demonstrated signals are gone.
5. Analyzes a synthetic PNG containing metadata, a private chunk, and an
   embedded provenance declaration.

The demo performs no network requests and does not require `c2patool`.

## Results

After a successful run, open:

- `demo-output/reports/detect.html` for the hidden-text report
- `demo-output/reports/watermark.html` for watermark and provenance findings
- `demo-output/summary.json` for the verification result and hashes

All generated files remain under `demo-output/`, which Git ignores. The runner
refuses to overwrite a nonempty output directory. Move an earlier run elsewhere
or choose a new location:

```bash
python3 demo/run_demo.py --output /tmp/stegguard-demo
```

To generate only the fixtures:

```bash
python3 demo/create_samples.py /tmp/stegguard-samples
```

Synthetic findings demonstrate the workflow, not real-world detection accuracy.
