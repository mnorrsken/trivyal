# Changelog

All notable changes to this project are documented here. Headings use
`## [X.Y.Z] - YYYY-MM-DD`; the release workflow takes the notes from them.

## [Unreleased]

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
