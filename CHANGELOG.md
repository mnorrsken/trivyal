# Changelog

All notable changes to this project are documented here. Headings use
`## [X.Y.Z] - YYYY-MM-DD`; the release workflow takes the notes from them.

## [Unreleased]

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
