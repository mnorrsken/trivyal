# Changelog

All notable changes to this project are documented here. Headings use
`## [X.Y.Z] - YYYY-MM-DD`; the release workflow takes the notes from them.

## [Unreleased]

### Changed

- Releases ship Linux binaries only (amd64, arm64). On macOS, build with
  `make build`.

## [0.4.2] - 2026-11-08

### Security

- Update github.com/go-jose/go-jose/v4 to 4.1.8. It is used to check OIDC
  tokens. Version 4.1.7 fixed five advisories: RSA key size limits in
  thumbprints and certificate checks, limits on JWE/JWS recipients and
  signatures, header detection, and a JSON embedded-field fix.

### Changed

- Only the Scans page updates live, and it no longer dims while it
  refreshes. Other pages blinked every 20 seconds or so because any cluster
  change (even a node status update) made them refetch; they now show the
  state when opened and still refresh after you flag or hide something.
- Dependency updates: k8s.io/api, apimachinery and client-go 0.37.2,
  modernc.org/sqlite 1.61.1. Web: @sveltejs/kit 3.1.1, adapter-static 4.0.1,
  @tailwindcss/vite 4.3.4, svelte-check 4.7.8, vitest 5.1.0.

## [0.4.1] - 2026-11-06

### Fixed

- Config audit, RBAC and infra reports showed trivy-operator's version as
  "Trivy X" (on the dashboard, the Scans page and report pages). They now
  say "Operator X", so it is not mixed up with the Trivy scanner version of
  image scans.

## [0.4.0] - 2026-11-06

### Added

- Scans page (`/scans`, `GET /api/v1/scans`): running and failed trivy-operator
  scan jobs (image scans and node collectors) plus the last scan of every
  report, with filters for state, type, age, namespace, kind, workload and
  image. Finished jobs are left out because their report is listed, and
  trivy-operator deletes jobs soon after they end, so failures show briefly.

## [0.3.3] - 2026-10-31

### Changed

- Web dependency update: svelte 5.57.3.

## [0.3.2] - 2026-10-25

### Fixed

- The config audit report page showed "500 Internal Error" when a check
  appeared once per container.
- Lines in multi-value cells (such as "Used by") and list rows that tie on
  the sort column no longer move around when the data refreshes. Secrets on
  image and workload pages are now sorted worst first.

## [0.3.1] - 2026-10-24

### Added

- Trivy scans in CI, before the release image is pushed, and daily on the
  published image (results under Security > Code scanning). Any
  vulnerability with a fix fails the build. `make scan` runs the same checks
  locally.

### Security

- golang.org/x/net 0.60.0 and golang.org/x/text 0.42.0 (2 high, 4 medium
  CVEs).
- github.com/go-jose/go-jose/v4 4.1.6, used to check OIDC tokens: fixes
  crashes and a denial of service in JWK, JSON and JWE parsing. JWK RSA keys
  are now limited to 4096 bits.
- Dependabot version updates and security alerts.

## [0.3.0] - 2026-10-24

### Added

- Flag items as well as hide them. A mark now has a state, `flagged` or
  `hidden`, on the same targets as before; one state per target. A flag
  covers everything in its target, now and later. A hide still covers only
  the findings present when hidden. If both cover a finding, the hide wins.
- Flagged items sort first by default in vulnerability groupings, checks,
  secrets, workloads, namespaces and most tables on detail pages. A "Flagged
  first" checkbox in the list sidebar turns it off (`flagfirst=0`). A group
  counts as flagged when it, or a finding in it, is flagged, and shows a
  flag marker.
- One pill per item (Mark, Flagged, Hidden) opens a menu with note, Flag,
  Hide ("Hide again" also hides new findings) and Clear. In wide tables the
  pill column sticks to the right edge.
- Dashboard line "N flagged, M hidden" linking to `/marks`.
- `?counts=1` on `GET /api/v1/marks` adds per-mark counts: findings when
  marked, now, and new.
- Database migration adds `marks.state` (default `hidden`), so marks saved by
  0.2.x stay hidden.

### Changed

- The Hidden page is now "Flagged & hidden" at `/marks`, with state, kind,
  target, note, finding counts and date.
- "Show hidden" and `hidden=1` are gone. Lists say "N hidden findings not
  shown"; detail pages add a Manage link to `/marks`.
- API: `/api/v1/hidden` is now `/api/v1/marks`. `POST` takes
  `{"target": {...}, "state": "flagged"|"hidden", "note": "..."}` (JSON
  content type required; an omitted note keeps the old one). A flag may go on
  a target with no findings, a hide may not. List responses have `hidden`,
  detail responses `hiddenFindings`, items `flagged`; the summary has
  `hidden` and `flagged` counts.

## [0.2.1] - 2026-10-23

0.2.0 was tagged but not published: its release failed in tests. This
release has everything listed under 0.2.0.

### Fixed

- Times of hidden items are saved at microsecond precision, the precision
  the database keeps.

## [0.2.0] - 2026-10-23

### Added

- Hide what you have handled: an image (all tags), a CVE in one image or
  everywhere, an exposed secret, a check everywhere or on one resource, a
  workload or a namespace. Hidden findings leave all counts, lists, facets,
  CSV exports and the dashboard. Search, SBOM and raw reports are not
  filtered.
- Hiding covers the findings the target has now. New findings (a new CVE, a
  new package version) show again; a rebuild with the same packages stays
  hidden.
- "Show hidden" toggle (`?hidden=1`), Unhide and "Hide new findings too" on
  hidden detail pages, a Hidden page (`/hidden`) and a hidden count on the
  dashboard.
- `GET/POST /api/v1/hidden` and `DELETE /api/v1/hidden/{id}`; list and detail
  endpoints accept `hidden=1`.
- `-database-url` / `DATABASE_URL` (`sqlite:<path>`) stores hidden items in
  SQLite (bun ORM, pure Go, no CGO). Empty keeps them in memory.
- Helm `persistence` values with a PVC for the database at `/data`, and
  `podSecurityContext.fsGroup: 65532`.

### Changed

- Hidden items are stored per user; for now there is one anonymous user, also
  with OIDC on.
- With persistence on, the Deployment uses the `Recreate` strategy. Keep
  `replicaCount` at 1 (SQLite has one writer).

### Fixed

- "Fixed in" versions stayed in place instead of scrolling with their table.

## [0.1.0] - 2026-10-23

### Added

- Dashboard with vulnerability, misconfiguration, secret and RBAC totals,
  compliance scores, most vulnerable images and namespaces.
- Pages for vulnerability, config audit, exposed secret, RBAC, infra,
  compliance and SBOM reports, with image, CVE, check, control and report
  detail pages.
- Workload, pod, namespace and node pages linked from all reports.
- Filter language with facets and autocomplete, global search, CSV export,
  CycloneDX download and live updates over Server-Sent Events.
- Optional OpenID Connect login.
- Helm chart with read-only RBAC, optional ingress, ServiceMonitor and OIDC
  settings.

### Fixed

- Pods reported on their own resolve to the custom resource that controls
  them, and such owners appear as workloads.
- When several reports cover one resource, only the newest report's checks
  count.
- Namespace totals count each image once, like the dashboard.
- Exposed secrets are counted once per image in totals and once per
  workload in lists.
