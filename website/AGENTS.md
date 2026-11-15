# AGENTS.md — Caphe website

Static Astro + Starlight site. Human setup lives in [README.md](README.md); these are agent rules.

## Concurrent work

- This folder is written by multiple agents at once (branding, homepage copy, OG images). Never `git add -A`/`git add .` — stage only paths you edited and commit with an explicit pathspec (`git commit -- website/src/...`).
- Verify `git diff --cached --stat` contains only your files before committing; leave other agents' staged/unstaged changes (logos, `public/*.png`, `src/pages/index.astro`) untouched and note collisions instead of overwriting them.
- `website/dist/` and `node_modules/` are build outputs — never commit them.

## Commands

From `website/`:

```bash
npm ci                   # never hand-edit package-lock.json
npm run dev              # local dev server
npm run build            # astro check + OG render + astro build; must pass before committing
npm run test:links
npx playwright install chromium && npm run test:a11y
```

## Content accuracy

- The site must only describe behavior that exists in the Go CLI at this revision. Before claiming a command, flag, or scanner integration, verify it against `internal/cli/` and `scripts/install-tools.sh` — or update the site in the same commit as the feature.
- Never present AI output as verified findings; site copy keeps the "hypothesis, unverified" labeling used by the CLI reports.
- Version numbers, model names, and scanner lists must match `internal/cli/root.go` (`Version`) and the pins in the root [AGENTS.md](../AGENTS.md).

## Deployment

`.github/workflows/pages.yml` builds and deploys on pushes to `main` only. Workflow file changes need `actionlint` (see root AGENTS.md) and must stay SHA-pinned.
