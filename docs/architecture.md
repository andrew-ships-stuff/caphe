# Architecture

Caphe separates compilation from execution. YAML is parsed into typed Go structures, checked against the static adapter registry and policy limits, normalized into a canonical task order, and hashed without timestamps. The resulting JSON lock is data rather than generated executable code.

```text
workflow YAML -> security/syntax gates -> canonical lock + digest
                                             |
                                             v
target -> fixed DAG scheduler -> adapters -> raw artifacts
                                  |             |
                                  v             v
                              findings -> SQLite evidence graph -> reports
```

The executor alone chooses runnable tasks from declared dependencies. Ready tasks are sorted by task ID before dispatch; concurrency can alter wall-clock ordering but not dependencies or normalized task order. Required dependency failure causes deterministic skipping. Dependencies named in `optionalNeeds` may fail without preventing the consumer. An `optionalNeed` must also appear in `needs`.

Raw scanner output is stored under SHA-256 content paths. SQLite stores executions, task results, findings, and graph nodes/edges. Finding-to-file joins use exact scanner locations and retain provenance; similarity is not used as proof. Scanner observations, derived relationships, hypotheses, and verification results are separate conceptual classes. The current database materializes scanner observations and exact source-file references; broader package/image/RBAC correlation is planned.

Trust boundaries are the workflow input, scanned repository, external scanner process, optional inference server, artifact store, and local database. Model output never enters the scheduler or executable argument construction path.
