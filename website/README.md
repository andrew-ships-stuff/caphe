# Caphe website

The official Caphe site is a static Astro + Starlight project. Tailwind CSS supplies utility support; custom Astro components implement the marketing pages with minimal client JavaScript.

## Local development

```bash
cd website
npm ci
npm run dev
```

Build and verify the production output:

```bash
npm run build
npm run test:links
npx playwright install chromium
npm run test:a11y
```

The generated site is in `website/dist/`. No Caphe Go source is modified by the website build.

## GitHub Pages

The workflow at `.github/workflows/pages.yml` builds and deploys on pushes to `main`, and supports manual runs. For project Pages, the defaults produce canonical URLs under `https://andrew-ships-stuff.github.io/caphe/` and set Astro's base to `/caphe`.

In repository **Settings → Pages**, set **Source** to **GitHub Actions**. The first deployment creates the `github-pages` environment used by the official deployment action.

For a future custom domain:

1. Configure the domain in GitHub Pages and DNS.
2. Add repository Actions variable `SITE_URL`, for example `https://caphe.dev`.
3. Add repository Actions variable `BASE_PATH` with value `/`.
4. If GitHub requires it, add a `public/CNAME` file containing only the domain.

Do not claim a successful public deployment until the Pages workflow has completed in GitHub.

## Content accuracy

Current functionality is sourced from the Go command tree, typed workflow schema, adapters, tests, and repository documentation. Update status labels when implementation lands. Planned integrations and distributed workers must not be presented as available prematurely.
