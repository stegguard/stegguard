# Detection Contract Corpus

The versioned manifest contains only harmless, synthetic cases represented as
escaped text or hexadecimal bytes. The evaluator materializes each case in a
temporary directory and removes it afterward.

Every entry needs a stable ID, family, filename, payload encoding, expected
flagged state, origin, and license. Do not add malware, private samples, or
opaque binary files. See `docs/detection-quality.md` for the review process.

