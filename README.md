# trivyal

A web UI for [trivy-operator](https://github.com/aquasecurity/trivy-operator)
reports, made for small clusters such as a homelab. It runs inside the
cluster and reads the report CRDs through the Kubernetes API. Only the list
of flagged and hidden items is stored, in a small SQLite file.

- **Dashboard**: vulnerability, misconfiguration, secret and RBAC totals,
  compliance scores, the most vulnerable images and a per-namespace overview.
- **One page per report type**: vulnerabilities (by image, workload, CVE or
  finding, CSV export), config audit, exposed secrets, RBAC, infrastructure,
  compliance (CIS, NSA, Pod Security Standards) and SBOM.
- **Cluster pages**: workloads, pods, namespaces and nodes, each with what
  trivy found in them. Every report links to them.
- **Filtering everywhere**: one search box with a small query language, facet
  counts and autocomplete. Filters live in the URL, so every view can be
  bookmarked.
- **Global search** (`⌘K` / `Ctrl-K` or `/`) for namespaces, workloads, pods,
  nodes, images, CVEs, checks and packages.
- **Live**: pages update when trivy-operator writes new reports.
- Findings are counted once per image, even when several workloads run it.
  Old ReplicaSet revisions (scaled to zero) are hidden unless you ask for them.
- **Flag or hide**: images, CVEs, secrets, checks, workloads or namespaces.
  Flagged items sort first and cover new findings too. Hidden findings drop
  out of counts, lists, facets, CSV exports and the dashboard; findings that
  appear later show again. Review both on the "Flagged & hidden" page
  (`/marks`). Search, SBOM and raw reports are not filtered.
- Optional OpenID Connect login.

## Filter language

```
sev:critical,high fixable:yes ns:demo -kind:Job openssl
```

| Syntax | Meaning |
|---|---|
| `field:value` | field matches value (case does not matter) |
| `field:a,b` | either value |
| `-field:value` | exclude |
| `field:web*` | `*` is a wildcard |
| `field:=value` | exact match on fields that otherwise match substrings |
| `score:>=7`, `published:>2024-01-01`, `version:<3.0.13` | compare numbers, dates and versions |
| `word` or `"two words"` | free text anywhere in the row |

The `?` button next to each search box lists the fields of that page.

## Install

trivyal needs trivy-operator in the same cluster.

```sh
helm install trivyal oci://ghcr.io/mnorrsken/charts/trivyal -n trivy-system
kubectl -n trivy-system port-forward svc/trivyal 8080:80
```

Then open <http://localhost:8080/>.

### Helm chart

The chart creates a read-only ClusterRole: `get/list/watch` on the
`aquasecurity.github.io` reports, and `list/watch` on deployments,
statefulsets, daemonsets, replicasets, jobs, cronjobs, pods, nodes and
namespaces. Set `rbac.create=false` to manage it yourself.

| Value | Default | Description |
|---|---|---|
| `ingress.enabled` | `false` | Ingress for the UI (`ingress.hosts`, `ingress.tls`, `ingress.className`) |
| `auth.oidc.enabled` | `false` | Require login with OpenID Connect |
| `auth.oidc.issuerURL` | | Issuer, for example `https://auth.example.com` |
| `auth.oidc.clientID` | | Client ID |
| `auth.oidc.redirectURL` | | `https://<host>/auth/callback` |
| `auth.oidc.existingSecret` | | Secret with `client-secret` and `session-key` |
| `auth.oidc.allowedGroups` | `[]` | Only these groups may sign in (empty: everyone the provider accepts) |
| `auth.oidc.allowedEmails` | `[]` | Only these emails may sign in |
| `auth.oidc.groupsClaim` | `groups` | ID token claim with the user's groups |
| `metrics.enabled` | `false` | Prometheus metrics on port 9090 |
| `metrics.serviceMonitor.enabled` | `false` | ServiceMonitor for the Prometheus Operator |
| `persistence.enabled` | `true` | Keep flagged and hidden items in a PVC (SQLite at `/data/trivyal.db`); off uses an emptyDir |
| `persistence.existingClaim` | | Use this PVC instead of creating one |
| `persistence.storageClass` | | Storage class of the new PVC |
| `persistence.accessModes` | `[ReadWriteOnce]` | Access modes of the new PVC |
| `persistence.size` | `1Gi` | Size of the new PVC |
| `config.logLevel` | `info` | `debug`, `info`, `warn` or `error` |

With persistence on, the Deployment uses the `Recreate` strategy. The pod
runs with `fsGroup: 65532` so the volume is writable. SQLite has one writer:
keep `replicaCount` at 1.

### Access control

Security reports tell an attacker where to look. Without `auth.oidc` there
is no login, so either:

- enable OIDC:

  ```sh
  kubectl -n trivy-system create secret generic trivyal-oidc \
    --from-literal=client-secret=<client secret> \
    --from-literal=session-key="$(openssl rand -base64 48)"
  helm upgrade --install trivyal oci://ghcr.io/mnorrsken/charts/trivyal -n trivy-system \
    --set auth.oidc.enabled=true \
    --set auth.oidc.issuerURL=https://auth.example.com \
    --set auth.oidc.clientID=trivyal \
    --set auth.oidc.redirectURL=https://trivyal.example.com/auth/callback \
    --set auth.oidc.existingSecret=trivyal-oidc
  ```

  Register `https://trivyal.example.com/auth/callback` as redirect URI at the
  provider. Sessions last 12 hours. Without `session-key` they end when the
  pod restarts.

- or keep the service internal and put an authenticating proxy (for example
  oauth2-proxy or forward auth in your ingress controller) in front.

## Running outside the cluster

The binary uses your kubeconfig when it does not run in a pod:

```sh
trivyal -listen 127.0.0.1:8080
```

Flags (and environment variables): `-listen` (`LISTEN_ADDR`, `:8080`),
`-metrics-listen` (`METRICS_ADDR`, `:9090`, empty disables), `-kubeconfig`
(`KUBECONFIG`), `-database-url` (`DATABASE_URL`, `sqlite:<path>`; empty
keeps marks in memory and loses them on restart), `-log-level`
(`LOG_LEVEL`) and the `-oidc-*` flags
(`OIDC_ISSUER_URL`, `OIDC_CLIENT_ID`, `OIDC_REDIRECT_URL`, `OIDC_SCOPES`,
`OIDC_GROUPS_CLAIM`, `OIDC_ALLOWED_GROUPS`, `OIDC_ALLOWED_EMAILS`). Secrets
are read only from the environment: `OIDC_CLIENT_SECRET`, `SESSION_KEY`.

## Development

Go backend (`cmd/`, `internal/`) and a Svelte 5 / SvelteKit static app in
`web/`, embedded into the binary at build time.

```sh
make build     # web + Go into bin/trivyal
make dev       # backend on :8080 (db in bin/trivyal.db) + Vite on :5173
make test      # Go tests, svelte-check and vitest
make lint      # golangci-lint
make lab       # kind cluster with trivy-operator and this build
make lab-down
```

See [docs/architecture.md](docs/architecture.md) for how the pieces fit.

## License

MIT
