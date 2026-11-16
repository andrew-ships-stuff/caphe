# Set up Caphe CI in another GitHub repository

This guide installs Caphe's pull-request review in a consumer repository. It uses two workflows:

1. An **untrusted analyzer** runs on `pull_request` with `contents: read`, compares the base and head revisions, and uploads a digest-bound review artifact.
2. A **trusted publisher** runs through `workflow_run`, downloads that artifact as untrusted data, verifies its repository, pull request, base SHA, head SHA, schema, bounds, and digest, and only then publishes comments and SARIF.

Do not combine these jobs or give the `pull_request` workflow a write token. The split is what makes the setup safe for pull requests from forks.

## Current coverage

The copy/paste setup below uses `caphe:git-security`, which scans GitHub Actions with Poutine and reports findings introduced by the pull request. It does not claim to be the full local `caphe audit .` scanner suite.

Caphe CPU inference is off in the base template. Scanner evidence and policy remain fully functional without it. An optional section below enables the pinned Qwen2.5 1.5B CPU model; all accepted model output remains an unverified hypothesis and cannot determine policy.

## Pinned versions

The examples intentionally pin both layers:

- Caphe Action revision: `7debe1e9c00db22f4566fd03819530f8d05ca830` (`v0.1.1` release commit)
- Caphe CLI release: `v0.1.1`

When upgrading, update the Action SHA in both workflows and the CLI release together. Never replace the full Action SHA with `main` or a floating major-version tag.

## 1. Add the read-only analyzer

Create `.github/workflows/caphe-pr.yml` in the consumer repository:

```yaml
name: Caphe PR analysis

on:
  pull_request:

permissions:
  contents: read

concurrency:
  group: caphe-pr-${{ github.event.pull_request.number }}
  cancel-in-progress: true

jobs:
  analyze:
    runs-on: ubuntu-latest
    timeout-minutes: 20
    steps:
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4
        with:
          fetch-depth: 0
          persist-credentials: false

      - id: caphe
        name: Analyze pull request
        continue-on-error: true
        uses: andrew-ships-stuff/caphe@7debe1e9c00db22f4566fd03819530f8d05ca830 # v0.1.1
        with:
          caphe-version: v0.1.1
          workflow: caphe:git-security
          base-sha: ${{ github.event.pull_request.base.sha }}
          head-sha: ${{ github.event.pull_request.head.sha }}
          repository: ${{ github.repository }}
          pull-request: ${{ github.event.pull_request.number }}
          severity-threshold: high
          fail-on-new: 'true'
          max-comments: '5'

      - name: Upload untrusted analysis artifact
        if: ${{ always() && steps.caphe.outputs.review-artifact != '' }}
        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.2
        with:
          name: caphe-pr-review-${{ github.event.pull_request.number }}
          path: ${{ steps.caphe.outputs.review-artifact }}
          if-no-files-found: error
          retention-days: 7

      - name: Enforce Caphe policy
        if: ${{ steps.caphe.outputs.policy-status == 'fail' }}
        shell: bash
        run: exit 1
```

`continue-on-error` is deliberate: Caphe must first upload the review artifact, then the final step converts the policy result into the job status used by branch protection.

## 2. Add the trusted publisher

Create `.github/workflows/caphe-publish.yml`:

```yaml
name: Caphe trusted PR publisher

on:
  workflow_run:
    workflows: [Caphe PR analysis]
    types: [completed]

permissions:
  actions: read
  contents: read
  pull-requests: write
  security-events: write

concurrency:
  group: caphe-publish-${{ github.event.workflow_run.id }}
  cancel-in-progress: false

jobs:
  publish:
    if: ${{ github.event.workflow_run.event == 'pull_request' && github.event.workflow_run.pull_requests[0].number != null }}
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - name: Checkout trusted Caphe installer
        uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4
        with:
          repository: andrew-ships-stuff/caphe
          ref: 7debe1e9c00db22f4566fd03819530f8d05ca830 # v0.1.1
          path: .caphe-action
          persist-credentials: false

      - name: Install checksum-verified Caphe release
        shell: bash
        env:
          CAPHE_VERSION: v0.1.1
          CAPHE_INSTALL_DIR: ${{ runner.temp }}/caphe-bin
        run: sh .caphe-action/scripts/install.sh

      - name: Download untrusted analysis as data
        uses: actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093 # v4.3.0
        with:
          name: caphe-pr-review-${{ github.event.workflow_run.pull_requests[0].number }}
          path: ${{ runner.temp }}/caphe-review
          github-token: ${{ github.token }}
          run-id: ${{ github.event.workflow_run.id }}

      - name: Validate artifact identity and schema
        shell: bash
        env:
          CAPHE_REPOSITORY: ${{ github.repository }}
          CAPHE_PR: ${{ github.event.workflow_run.pull_requests[0].number }}
          CAPHE_BASE_SHA: ${{ github.event.workflow_run.pull_requests[0].base.sha }}
          CAPHE_HEAD_SHA: ${{ github.event.workflow_run.head_sha }}
        run: |
          "${RUNNER_TEMP}/caphe-bin/caphe" github validate \
            "${RUNNER_TEMP}/caphe-review/caphe-pr-review.json" \
            --repository "$CAPHE_REPOSITORY" --pr "$CAPHE_PR" \
            --base-sha "$CAPHE_BASE_SHA" --head-sha "$CAPHE_HEAD_SHA" \
            --max-comments 5 --summary-output "${RUNNER_TEMP}/caphe-summary.md" \
            --sarif-output "${RUNNER_TEMP}/caphe-pr.sarif" --json
          cat "${RUNNER_TEMP}/caphe-summary.md" >> "$GITHUB_STEP_SUMMARY"
          "${RUNNER_TEMP}/caphe-bin/caphe" github annotations \
            "${RUNNER_TEMP}/caphe-review/caphe-pr-review.json" --max-comments 5

      - name: Publish deduplicated review
        shell: bash
        env:
          CAPHE_REPOSITORY: ${{ github.repository }}
          CAPHE_PR: ${{ github.event.workflow_run.pull_requests[0].number }}
          CAPHE_BASE_SHA: ${{ github.event.workflow_run.pull_requests[0].base.sha }}
          CAPHE_HEAD_SHA: ${{ github.event.workflow_run.head_sha }}
          GITHUB_TOKEN: ${{ github.token }}
        run: |
          "${RUNNER_TEMP}/caphe-bin/caphe" github publish \
            "${RUNNER_TEMP}/caphe-review/caphe-pr-review.json" \
            --repository "$CAPHE_REPOSITORY" --pr "$CAPHE_PR" \
            --base-sha "$CAPHE_BASE_SHA" --head-sha "$CAPHE_HEAD_SHA" \
            --max-comments 5 --json

      - name: Upload validated SARIF
        uses: github/codeql-action/upload-sarif@89a39a4e59826350b863aa6b6252a07ad50cf83e # v4
        with:
          sarif_file: ${{ runner.temp }}/caphe-pr.sarif
          category: caphe-pr
```

The publisher checks out Caphe—not pull-request code—at a trusted full commit SHA. It installs the matching checksum-verified release and treats the analyzer artifact strictly as untrusted input.

## 3. Merge the workflows before testing a feature PR

The trusted `workflow_run` workflow must exist on the consumer repository's default branch. Bootstrap the two files onto the default branch before expecting comments on another pull request. If they are introduced by the same pull request being analyzed, analysis can run, but trusted publication will not start until the publisher exists on the default branch.

No repository secret or personal access token is required. The publisher uses the repository-scoped `GITHUB_TOKEN` with the explicit permissions above. Organization or repository policy must allow those requested permissions.

If the repository cannot accept SARIF—for example, because code scanning is unavailable—remove the `security-events: write` permission and the `Upload validated SARIF` step. PR summary and inline publishing remain available.

## 4. Configure branch protection

After the first run, add the `analyze` job from **Caphe PR analysis** as a required pull-request check. A new finding at or above `severity-threshold` will then block the pull request after Caphe has emitted its artifact and job summary.

Recommended starting policy:

- `severity-threshold: high`
- `fail-on-new: 'true'`
- `max-comments: '5'`

Caphe compares base and head reports, so existing findings do not fail a pull request unless the change introduces them again under a new identity.

## Optional: bounded CPU inference

Add these inputs to the `with:` block of the analyzer's Caphe step:

```yaml
          ai: 'true'
          ai-serve: 'true'
          ai-threads: '4'
          max-model-calls: '3'
          max-inference-time: 5m
          ai-model: Qwen2.5-1.5B-Instruct-Q4_K_M.gguf
          ai-model-url: https://huggingface.co/bartowski/Qwen2.5-1.5B-Instruct-GGUF/resolve/main/Qwen2.5-1.5B-Instruct-Q4_K_M.gguf
          ai-model-digest: sha256:1adf0b11065d8ad2e8123ea110d1ec956dab4ab038eab665614adba04b6c3370
```

This installs the pinned `llama.cpp` runtime and downloads the digest-verified model on the GitHub-hosted runner. Expect roughly a 1 GB model download unless the runner cache is configured separately. AI failure never changes the deterministic scanner evidence or policy result.

## Upgrade checklist

1. Select a published Caphe release.
2. Resolve its tag to the immutable full commit SHA.
3. Update the `uses:` SHA in the analyzer.
4. Update the Caphe checkout `ref:` SHA in the publisher.
5. Update both `CAPHE_VERSION`/`caphe-version` values to the matching release tag.
6. If CPU inference is enabled, update the model only through Caphe's documented digest-pinned model change.
7. Open a pull request and review both workflow diffs carefully.

Keep GitHub Actions themselves pinned by full commit SHA. Dependabot can maintain those pins with the `github-actions` ecosystem enabled for `/`.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Analyzer says `workflow not found` | Use `caphe:git-security` exactly, or commit the custom workflow path before selecting it. |
| Analyzer passes but no comment appears | Confirm `caphe-publish.yml` already exists on the default branch and its `workflows:` name exactly matches `Caphe PR analysis`. |
| Publisher cannot download the artifact | Confirm the analyzer uploaded `caphe-pr-review-<PR number>` and retained `actions: read`. |
| Identity validation fails | Do not bypass it. Check that both workflows use the same PR, base SHA, head SHA, repository, and `max-comments` bound. |
| SARIF upload is rejected | Enable code scanning for the repository or remove only the SARIF permission/step. |
| Policy blocks an existing issue | Inspect the base/head summaries and finding identity; Caphe policy is intended to fail only introduced findings. |
