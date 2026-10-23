# Changelog

All notable changes to this project are documented here. Headings use
`## [X.Y.Z] - YYYY-MM-DD`; the release workflow takes the notes from them.

## [Unreleased]

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
