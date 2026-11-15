# Audit command

`caphe audit` is the primary local workflow. The target defaults to the current directory, so these are equivalent:

```bash
caphe audit
caphe audit .
```

A directory at any depth is a valid target. ZIP archives are extracted into a private temporary workspace before scanners run; absolute paths, parent traversal, symlinks, excessive entry counts, and archives over the extraction limit are rejected.

```bash
caphe audit path/to/nested/repository
caphe audit repository.zip
```

The default outputs are `caphe-audit.json`, `caphe-audit.sarif`, `caphe-audit.md`, and `caphe-audit.html`. Pass an empty value to skip an output. The HTML report is self-contained and works offline. It supports text, severity, and scanner filters and displays scanner coverage so skipped tools are not mistaken for a clean audit. CVE identifiers link to the NIST National Vulnerability Database and CWE identifiers link to MITRE when the viewer chooses to follow them.

An existing bundle can be validated by its embedded digest and rendered again:

```bash
caphe report caphe-audit.json --format html --output posture.html
caphe report caphe-audit.json --format sarif --output posture.sarif
```

The bundle is the canonical artifact. HTML, Markdown, and SARIF are views derived from it.

## Offline boundary

Caphe itself does not require a remote service, and HTML rendering makes no background requests. Individual scanners and scanner configuration can still introduce network access. In particular, the current default Opengrep configuration names the upstream `p/security-audit` ruleset. A fully offline distribution must replace that reference with a reviewed, versioned, digest-pinned rules bundle embedded in the Caphe release; it must not silently substitute an unreviewed ruleset.
