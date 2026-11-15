# Benchmarking

`caphe benchmark run` measures repeated normalization of one embedded synthetic Opengrep observation and checks byte-for-byte reproducibility. It is a harness smoke test, not evidence of broad security accuracy. Correlation, AI, and verification baselines are explicitly reported `not_run` until suitable corpora and validated models exist. The paper's numbers are not Caphe measurements.

The planned harness compares scanner-only normalization, deterministic graph correlation, bounded CPU inference, and inference plus independent verification. Fixtures must include vulnerable and clean negatives, distinct prompt-development/evaluation examples, fixed scanner outputs for reproducibility tests, and separately labeled live scanner runs.

Metrics are precision, recall, false positives/negatives, verified novel findings, inconclusive hypotheses, provenance completeness, CPU-seconds, peak RSS, wall time, graph/verification latency, token counts, cache hits, and additional independently verified findings per CPU-hour. The falsifiable hypothesis is whether bounded small-model inference improves verified security relationships over deterministic correlation at acceptable CPU cost.
