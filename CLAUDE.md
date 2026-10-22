# trivyal

Web UI for trivy-operator reports. Go backend (`cmd/trivyal`, `internal/`)
serving a Svelte 5 / SvelteKit static SPA (`web/`) embedded with go:embed.
Helm chart in `charts/trivyal`.

## Never put cluster details in the repo

The project is developed against a real homelab cluster. Nothing from it may
be committed: namespaces, workload or image names, hostnames, registries,
node names, report dumps, screenshots. Fixtures (`internal/fixture`) and docs
use made-up names (`shop`, `demo`, `registry.example.com`). Dumps go to a
scratch directory outside the repo. Run `make leakcheck` before committing;
it greps tracked files against `~/.config/trivyal/leak-denylist`, which
lives outside the repo on purpose.

## Commands

- `make build` (web + Go), `make build-go` (Go only), `make test`
  (Go tests, svelte-check, vitest), `make lint`, `make race`,
  `make helm-lint`, `make leakcheck`.
- `make dev`: backend on :8080 with the current kubeconfig (read-only) and
  Vite on :5173.
- `make lab` / `make lab-down`: kind cluster with trivy-operator and this
  build; uses `dev/lab.kubeconfig`, never the current context.

## Conventions

- Web imports use `#lib/<file>.ts` (Kit 3 package imports, explicit
  extension) from routes, relative imports inside `src/lib`.
- New list pages: a query schema + facets in `internal/index`, a handler using
  `parseList`/`page` in `internal/api`, and `ListLayout` + `ListState` in the
  web app. Filters, grouping and paging stay in the URL.
- Severity colors come from the tokens in `web/src/app.css` and always sit
  next to a text label or number.

## Release notes (differs from the wiki "GitHub Release Process" skill)

- Changelog heading `## [X.Y.Z] - YYYY-MM-DD`.
- `release.yml` on `v*` tags: tests, multi-arch image, chart (version set
  from the tag), binaries and the GitHub release.
