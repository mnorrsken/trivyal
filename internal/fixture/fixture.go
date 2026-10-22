// Package fixture builds a small fake cluster's reports for tests.
package fixture

import (
	"encoding/json"
	"testing"

	"github.com/mnorrsken/trivyal/internal/reports"
)

// All names are made up; never paste real cluster data here.

// Source implements index.Source over the fixture reports.
type Source struct {
	objs   map[string][]any
	owners map[string]reports.Owner // "Kind/ns/name"
}

func (f *Source) Reports(resource string) []any { return f.objs[resource] }
func (f *Source) Installed() bool               { return true }
func (f *Source) Owner(kind, ns, name string) (reports.Owner, bool) {
	o, ok := f.owners[kind+"/"+ns+"/"+name]
	return o, ok
}

func meta(kind, ns, name, resKind, resName, container string) map[string]any {
	labels := map[string]any{
		reports.LabelResourceKind: resKind,
		reports.LabelResourceName: resName,
	}
	if ns != "" {
		labels[reports.LabelResourceNamespace] = ns
	}
	if container != "" {
		labels[reports.LabelContainerName] = container
	}
	return map[string]any{
		"kind": kind,
		"metadata": map[string]any{
			"name": name, "namespace": ns, "uid": name + "-uid", "labels": labels,
			"creationTimestamp": "2026-01-01T00:00:00Z",
		},
	}
}

func vuln(id, sev, pkg, installed, fixed string) map[string]any {
	return map[string]any{
		"vulnerabilityID": id, "severity": sev, "resource": pkg,
		"installedVersion": installed, "fixedVersion": fixed, "title": id + " in " + pkg,
	}
}

func vulnReport(ns, name, resKind, resName, container, repo, tag, digest string, vulns ...map[string]any) map[string]any {
	o := meta("VulnerabilityReport", ns, name, resKind, resName, container)
	sum := reports.SeveritySummary{}
	list := make([]any, len(vulns))
	for i, v := range vulns {
		sum.Inc(v["severity"].(string))
		list[i] = v
	}
	o["report"] = map[string]any{
		"updateTimestamp": "2026-01-02T00:00:00Z",
		"scanner":         map[string]any{"name": "Trivy", "version": "0.0.1"},
		"registry":        map[string]any{"server": "registry.example.com"},
		"artifact":        map[string]any{"repository": repo, "tag": tag, "digest": digest},
		"os":              map[string]any{"family": "alpine", "name": "3.20.0"},
		"summary": map[string]any{
			"criticalCount": sum.Critical, "highCount": sum.High, "mediumCount": sum.Medium,
			"lowCount": sum.Low, "unknownCount": sum.Unknown,
		},
		"vulnerabilities": list,
	}
	return o
}

func check(id, sev string) map[string]any {
	return map[string]any{"checkID": id, "title": "title " + id, "severity": sev, "category": "Kubernetes Security Check", "success": false, "messages": []any{"fix " + id}}
}

func checkReport(kind, ns, name, resKind, resName string, checks ...map[string]any) map[string]any {
	o := meta(kind, ns, name, resKind, resName, "")
	list := make([]any, len(checks))
	for i, c := range checks {
		list[i] = c
	}
	o["report"] = map[string]any{"scanner": map[string]any{"name": "Trivy"}, "summary": map[string]any{}, "checks": list}
	return o
}

func parse(t testing.TB, resource string, obj map[string]any) any {
	t.Helper()
	data, err := json.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}
	r, err := reports.Parse(resource, data)
	if err != nil {
		t.Fatalf("parsing %s: %v", resource, err)
	}
	return r
}

// New builds a small cluster:
//
//	shop/Deployment web  -> ReplicaSet web-new (3 replicas), image web:1.0
//	shop/Deployment web  -> ReplicaSet web-old (0 replicas, stale), image web:0.9
//	shop/Deployment api  -> ReplicaSet api-1, also image web:1.0 (same digest)
//	demo/CronJob backup  -> Job backup-1, image tools:2
func New(t testing.TB) *Source {
	t.Helper()
	three, zero := int32(3), int32(0)
	src := &Source{
		objs: map[string][]any{},
		owners: map[string]reports.Owner{
			"ReplicaSet/shop/web-new": {Kind: "Deployment", Name: "web", Replicas: &three},
			"ReplicaSet/shop/web-old": {Kind: "Deployment", Name: "web", Replicas: &zero},
			"ReplicaSet/shop/api-1":   {Kind: "Deployment", Name: "api", Replicas: &three},
			"Job/demo/backup-1":       {Kind: "CronJob", Name: "backup"},
		},
	}
	add := func(res string, obj map[string]any) { src.objs[res] = append(src.objs[res], parse(t, res, obj)) }

	webVulns := []map[string]any{
		vuln("CVE-2024-0001", "CRITICAL", "openssl", "3.0.1", "3.0.13"),
		vuln("CVE-2024-0002", "HIGH", "zlib", "1.2.11", ""),
		vuln("CVE-2024-0003", "LOW", "busybox", "1.36.0", "1.36.1"),
	}
	add(reports.VulnerabilityReports, vulnReport("shop", "replicaset-web-new-web", "ReplicaSet", "web-new", "web", "shop/web", "1.0", "sha256:aaa", webVulns...))
	add(reports.VulnerabilityReports, vulnReport("shop", "replicaset-api-1-api", "ReplicaSet", "api-1", "api", "shop/web", "shop/web:1.0", "sha256:aaa", webVulns...))
	add(reports.VulnerabilityReports, vulnReport("shop", "replicaset-web-old-web", "ReplicaSet", "web-old", "web", "shop/web", "0.9", "sha256:old",
		vuln("CVE-2023-9999", "CRITICAL", "openssl", "1.1.1", "1.1.1w")))
	add(reports.VulnerabilityReports, vulnReport("demo", "job-backup-1-tools", "Job", "backup-1", "tools", "demo/tools", "2", "sha256:bbb",
		vuln("CVE-2024-0001", "CRITICAL", "openssl", "3.0.1", "3.0.13"),
		vuln("GHSA-xxxx", "MEDIUM", "lodash", "4.17.0", "")))

	add(reports.ConfigAuditReports, checkReport("ConfigAuditReport", "shop", "replicaset-web-new", "ReplicaSet", "web-new",
		check("AVD-KSV-0014", "HIGH"), check("AVD-KSV-0012", "MEDIUM")))
	add(reports.ConfigAuditReports, checkReport("ConfigAuditReport", "shop", "service-web", "Service", "web",
		check("AVD-KSV-0117", "LOW")))
	add(reports.ClusterRbacAssessmentReports, checkReport("ClusterRbacAssessmentReport", "", "clusterrole-admin", "ClusterRole", "admin",
		check("AVD-KSV-0041", "CRITICAL")))

	sec := meta("ExposedSecretReport", "shop", "replicaset-web-new-web", "ReplicaSet", "web-new", "web")
	sec["report"] = map[string]any{
		"registry": map[string]any{"server": "registry.example.com"},
		"artifact": map[string]any{"repository": "shop/web", "tag": "1.0", "digest": "sha256:aaa"},
		"summary":  map[string]any{"highCount": 1},
		"secrets":  []any{map[string]any{"ruleID": "private-key", "title": "Private key", "category": "AsymmetricPrivateKey", "severity": "HIGH", "target": "/etc/key.pem", "match": "****"}},
	}
	add(reports.ExposedSecretReports, sec)
	clean := meta("ExposedSecretReport", "demo", "job-backup-1-tools", "Job", "backup-1", "tools")
	clean["report"] = map[string]any{"artifact": map[string]any{"repository": "demo/tools", "digest": "sha256:bbb"}, "summary": map[string]any{}, "secrets": []any{}}
	add(reports.ExposedSecretReports, clean)

	sbom := meta("SbomReport", "shop", "replicaset-web-new-web", "ReplicaSet", "web-new", "web")
	sbom["report"] = map[string]any{
		"registry": map[string]any{"server": "registry.example.com"},
		"artifact": map[string]any{"repository": "shop/web", "tag": "1.0", "digest": "sha256:aaa"},
		"summary":  map[string]any{"componentsCount": 2, "dependenciesCount": 1},
		"components": map[string]any{
			"bomFormat": "CycloneDX",
			"components": []any{
				map[string]any{"name": "openssl", "version": "3.0.1", "type": "library",
					"licenses":   []any{map[string]any{"license": map[string]any{"id": "Apache-2.0"}}},
					"properties": []any{map[string]any{"name": "aquasecurity:trivy:PkgType", "value": "alpine"}, map[string]any{"name": "aquasecurity:trivy:LayerDigest", "value": "sha256:dropme"}}},
				map[string]any{"name": "zlib", "version": "1.2.11", "type": "library"},
			},
		},
	}
	add(reports.SbomReports, sbom)

	comp := map[string]any{
		"kind":     "ClusterComplianceReport",
		"metadata": map[string]any{"name": "demo-benchmark"},
		"spec": map[string]any{
			"cron": "0 */6 * * *", "reportType": "summary",
			"compliance": map[string]any{
				"id": "demo-benchmark", "title": "Demo benchmark",
				"controls": []any{
					map[string]any{"id": "1.1", "name": "Read-only root", "severity": "HIGH", "checks": []any{map[string]any{"id": "avd-ksv-0014"}}},
					map[string]any{"id": "1.2", "name": "Manual review", "severity": "LOW"},
				},
			},
		},
		"status": map[string]any{
			"updateTimestamp": "2026-01-03T00:00:00Z",
			"summary":         map[string]any{"passCount": 1, "failCount": 1},
			"summaryReport":   map[string]any{"controlCheck": []any{map[string]any{"id": "1.1", "totalFail": 1}}},
		},
	}
	add(reports.ClusterComplianceReports, comp)
	return src
}
