# StegGuard detection quality checklist

StegGuard 0.5.0 scanned 61 of 88 sample files through recursive directory discovery. Passing all 88 paths explicitly produced 10 flagged files and 0 incomplete files. The collection has no ground-truth labels for hidden payloads. Use these observations to reproduce specific failures and labeled fixtures to measure detection accuracy.

## First priority — missed content and scan coverage

- [x] **Account for every input.** Compare recursive discovery with an explicit inventory of the same directory, including dotfiles and extensionless files. Verify that scanned and skipped counts reconcile to 88 and that every skipped path has a reason. Recursive and explicit CLI scans each accounted for all 88 sample files with zero omitted paths. CLI regression coverage verifies individual skip reasons for excluded extensions and dependency paths.
- [x] **Route files by their actual format.** The explicit scan treated PPTX, EPUB, and SQLite as text. Identify supported containers from their signatures and internal structure. Verify that each sample reaches its format handler or receives an explicit unsupported status. PPTX and EPUB together generated 267 character hits from the text path. The 88-file CLI scans used archive handling for PPTX and EPUB and reported SQLite content inspection as unsupported.
- [x] **Decode UTF-16 text and preserve byte offsets.** A UTF-8 sentence containing U+200B was flagged, while its UTF-16 equivalent with a byte-order mark was clean. Test UTF-8 and both byte orders of marked UTF-16. Verify that each reports the same character and points to its original bytes.
- [x] **Inspect text inside document containers.** The DOCX nested scan visited a thumbnail, and the XLSX had no nested results. Add paired fixtures for Word body text, PowerPoint speaker notes, Excel cell text, EPUB chapters, and ODT paragraphs. Verify that a known marker is attributed to the correct member and text location, and that extraction respects existing scan limits. Positive and benign fixtures verify all five formats, and limit tests cover decompression and finding caps.

## Second priority — false alarms and severity

- [x] **Distinguish decoded text from incidental byte matches.** Verified hits landed inside compressed DOCX and ODT styles, compressed PDF font streams, and MP4 media data. Retest those examples alongside a labeled metadata field containing U+200B. Verify that the metadata finding names the field and that incidental matches alone do not escalate file severity. Compressed document and PDF fixtures and MP4 media bytes remain clean. The positive ZIP fixture identifies the archive comment.
- [x] **Handle ordinary MP4 padding.** The sample's eight-byte `free` box contained only its header and contributed a medium-risk structural finding. Verify that an empty padding box is informational and that a box with contents is assessed on the evidence present. Empty padding now produces an informational finding without flagging the file. Paired fixtures verify zero-filled and nonzero padding.
- [x] **Calibrate WAV echo detection against periodic audio.** The two-second 440 Hz tone received High severity from autocorrelation alone. Test steady tones alongside labeled echo examples, and verify both the analyzer result and the final file severity. The steady tone remains clean and the delayed-copy fixture flags echo at both the analyzer and file levels.
- [x] **Evaluate layout rules in context.** The visible CSS value `font-size: 0.875rem` and a Markdown explanation of `display: none` both received High severity. Verify that both pass, while an actual hidden element in an HTML or SVG fixture still produces a layout finding.
- [x] **Account for ordinary Unicode usage.** A Greek greeting received Medium and the emoji 👩‍💻 received Low. Test single-script prose and standard emoji sequences alongside labeled mixed-script identifiers and unexpected joiners. Verify the severity and preserve the character offsets for review. Greek prose and standard emoji stay clean. The mixed identifier and unexpected joiners retain original byte offsets.

## Reporting and regression checks

- [x] **Show which checks ran.** Seven top-level media files had an unchecked robust-watermark analyzer, yet the HTML reported 0 incomplete files. Separate file-processing failures from unavailable checks in the summary and file details. Verify that users can see the coverage of a clean JPEG, FLAC, or MP3 and the reason each check was skipped.
- [x] **Label summary counts by what they measure.** The report's “284 Total Threats” counts character and byte matches. The High-severity WAV contributed zero to that number. Show separate counts for flagged files, character and byte matches, and findings from other analyzers. Verify the HTML totals against the per-file results. HTML counts flagged files, character and byte matches, and watermark analyzer findings separately. Tests verify both top-level and nested findings.
- [x] **Measure final verdicts on labeled files.** Extend the ten-case, four-format detection baseline with paired positive and benign fixtures for the issues above. Exercise the installed CLI through directory and explicit-path scans. Check coverage, finding location, severity, exit status, and agreement between HTML and JSON. Report false positives and misses by format and detector family. The 38-case v2 baseline reports zero false positives, misses, and incomplete files. Both installed CLI input modes agreed with the labels and HTML severity counts.

## File admission and safe sanitization

- [x] Enforce one explicit format allowlist with separate detect, decode, and sanitize capabilities across direct, recursive, and findings-based input. Report unsupported formats and channels with a reason.
- [x] Verify content before selecting a handler. Test a renamed ZIP, unknown binary, PPTX, EPUB, and SQLite. Unknown or mismatched bytes must never reach a text rewriter.
- [x] Allow rewriting only for formats with preservation tests. Start with validated plain text. Keep structured documents, code, and media inspection-only until their format-specific tests pass.
- [x] Validate a temporary output before publishing or replacing a file. Test archive integrity, meaningful structure, and preservation of the original on validation failure.
- [x] Verify reports against a mixed fixture set. Reconcile inspected, skipped, unsupported, incomplete, sanitized, partially sanitized, and validation-failed outcomes. Show which checks ran and the reason for every skipped or failed operation.

Validated .txt and .log inputs now use the plain-text sanitizer. Archive, database,
binary, and identifiable structured-text fixtures exercise rejection before a
rewrite. Tests verify UTF-16 byte-order and line-ending preservation and confirm
that a corrupted staged output leaves the original intact. JSON and HTML expose
unsupported inspection outcomes, and findings-based sanitization accounts for
below-threshold inputs and unsupported operations. The shared capability policy
defines detection, decoding, and rewriting formats.
A mixed fixture reconciles direct and recursive scan results across HTML and JSON
and verifies completed, partial, unsupported, skipped, incomplete, and
validation-failed outcomes from findings-based processing.

Public sanitizer regression tests verify that inspection-only formats and
Latin-1 text are rejected without producing an output. Binary transformation
preservation tests exercise the internal rewrite engine directly.
