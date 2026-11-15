# Compiled AI in Caphe

Caphe follows Trooskens et al.'s central separation: probabilistic generation or semantic extraction must not control repeated orchestration. The paper's Security, Syntax, Execution, and Accuracy stages are recorded separately because structural validity is not semantic accuracy. A lock can currently be produced after Security and Syntax pass; Execution and Accuracy are explicitly recorded as `not_evaluated` unless later workflow-specific fixtures support them. Caphe does not represent those stages as successful.

Caphe intentionally differs from the paper's Code Foundry algorithm. It emits a typed data plan rather than generated source code, statically registers adapters instead of generated modules, and does not regenerate on failure. Future AI-assisted workflow enrichment must use a finite attempt count and retain every attempt in provenance.

Runtime model calls are permitted only as predeclared semantic task nodes with fixed prompts, schemas, token limits, timeouts, retry limits, and deterministic fallbacks. The implemented invariant validator requires `confidence: hypothesis` and an allowlisted verification strategy. The LLM cannot add tasks, choose the next task, create command lines, or confirm its own hypothesis.

Guaranteed today: canonical control-plane plans for identical normalized compilation inputs; fixed DAG dependencies; lock tamper detection; bounded task attempts; and immutable raw artifacts. Not guaranteed: identical external scanner output when databases, binaries, files, environment, or rules change; identical model semantics; or strong subprocess isolation.

Caphe does not reuse the paper's performance, security, token, or accuracy numbers as Caphe results.
