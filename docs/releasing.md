# Releasing Caphe

Every push to `main` creates a `vMAJOR.MINOR.PATCH` tag and starts the release workflow. The release cross-compiles macOS, Linux, and Windows archives for amd64 and arm64, publishes SHA-256 checksums and GitHub build-provenance attestations, and updates the Homebrew formula after the GitHub release succeeds.

## Version selection

The version workflow reads every commit message since the previous release. Use a `Semver: major`, `Semver: minor`, or `Semver: patch` trailer, or the equivalent `[major]`, `[minor]`, or `[patch]` marker. Major takes precedence over minor, and minor takes precedence over patch across a multi-commit merge.

Conventional commits are also recognized: `BREAKING CHANGE:` and a type ending in `!:` select major, while `feat:` and `feat(scope):` select minor. Commits without a recognized marker default to patch. The first unmarked release is `v0.1.0`.

## One-time Homebrew tap setup

1. Create the public repository `andrew-ships-stuff/homebrew-tap` with a `main` branch.
2. Add a fine-grained personal access token as the `HOMEBREW_TAP_TOKEN` Actions secret in the Caphe repository. Limit the token to `andrew-ships-stuff/homebrew-tap` with read/write access to repository contents.
3. Keep branch protection compatible with formula updates made by the release workflow, or grant the token permission to use the required update path.

The default `GITHUB_TOKEN` is intentionally used only for Caphe release assets. The separate token is needed because GitHub does not allow that repository-scoped token to write to the tap repository.

## Publish a release

Merge a green pull request to `main`. The version workflow tags the merge commit and explicitly dispatches the release workflow. The explicit dispatch is required because tags pushed with the repository's `GITHUB_TOKEN` do not themselves start another workflow.

For a manually managed release, run the required tests on the exact commit and push a semantic-version tag:

```bash
gofmt -l .
go vet ./...
go test ./...
git tag -a v0.1.0 -m "Release v0.1.0"
git push origin v0.1.0
```

The workflow validates the tag, creates or updates the GitHub release, and writes `Formula/caphe.rb` in the tap. Once it completes, verify the public install path:

```bash
brew update
brew install andrew-ships-stuff/tap/caphe
caphe version
brew test andrew-ships-stuff/tap/caphe
```

Re-running the workflow for the same tag replaces its release assets and updates the existing formula rather than creating a duplicate file.
