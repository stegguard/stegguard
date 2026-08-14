# Resource Limits

StegGuard treats scanned files as untrusted. Every public scanning workflow can
accept a `ScanLimits` object or a mapping, and CLI commands expose the same
controls.

| Limit | Default | Purpose |
| --- | ---: | --- |
| `max_file_bytes` | 100 MiB | Caps a top-level file read |
| `max_decompressed_bytes` | 50 MiB | Caps decompressed PNG and nested content |
| `max_image_pixels` | 40 million | Rejects declared image dimensions before allocation |
| `max_archive_members` | 500 | Caps entries visited in a container |
| `max_nesting_depth` | 3 | Stops recursive containers and embedded media |
| `max_scan_seconds` | 30 seconds | Provides a cooperative per-scan deadline |
| `max_findings` | 10,000 | Caps accumulated evidence records |

Example:

```bash
stegguard detect upload.zip \
  --max-file-bytes 16777216 \
  --max-decompressed-bytes 33554432 \
  --max-archive-members 1000 \
  --max-nesting-depth 2 \
  --max-scan-seconds 10 \
  --max-findings 2000
```

Python callers can use:

```python
from stegguard import ScanLimits, scan_file

limits = ScanLimits(max_file_bytes=16 * 1024 * 1024, max_scan_seconds=10)
result = scan_file("upload.zip", limits=limits)
```

Some deadlines are cooperative checks between parser or analyzer stages. A
third-party analyzer receives its own timeout only when its adapter supports
one. Run StegGuard inside an operating-system sandbox with CPU, memory, process,
and filesystem quotas when scanning hostile files at service scale.

Limit exhaustion is not a clean result. Detector reports record an error and
the CLI exits with status `2`. Watermark results place recoverable nested errors
in `scan_errors` or `nested_scan_errors`.
