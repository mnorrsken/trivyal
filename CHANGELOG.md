# Changelog

All notable changes to this project are documented here. Headings use
`## [X.Y.Z] - YYYY-MM-DD`; the release workflow takes the notes from them.

## [Unreleased]

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
