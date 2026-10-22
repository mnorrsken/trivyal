package index

import (
	"testing"

	"github.com/mnorrsken/trivyal/internal/fixture"
	"github.com/mnorrsken/trivyal/internal/query"
	"github.com/mnorrsken/trivyal/internal/reports"
)

func snapshot(t *testing.T) *Snapshot {
	t.Helper()
	return New(fixture.New(t)).Snapshot()
}

func mustQuery(t *testing.T, s string, schema query.Schema) query.Query {
	t.Helper()
	q, err := query.Parse(s, schema)
	if err != nil {
		t.Fatal(err)
	}
	return q
}

func TestOwnerResolution(t *testing.T) {
	s := snapshot(t)
	got := map[string]bool{}
	for _, r := range s.Vulns {
		got[r.Use.Workload.String()+map[bool]string{true: " stale", false: ""}[r.Use.Workload.Stale]] = true
	}
	for _, want := range []string{"shop/Deployment/web", "shop/Deployment/web stale", "shop/Deployment/api", "demo/CronJob/backup",
		"shop/Cluster/db", "kube-system/Pod/etcd-node-a"} {
		if !got[want] {
			t.Errorf("missing workload %q in %v", want, got)
		}
	}
}

func TestImageDedupe(t *testing.T) {
	s := snapshot(t)
	img := s.Images["sha256:aaa"]
	if img == nil {
		t.Fatal("image sha256:aaa missing")
	}
	if len(img.Uses) != 2 {
		t.Errorf("uses = %d, want 2 (web and api)", len(img.Uses))
	}
	if img.Ref != "registry.example.com/shop/web:1.0" {
		t.Errorf("ref = %q (tag holding the full reference must be cleaned)", img.Ref)
	}
	rows, _, _ := s.MatchVulns(query.Query{}, false)
	groups := GroupByImage(rows)
	if len(groups) != 4 {
		t.Fatalf("images = %d, want 4 (stale image hidden)", len(groups))
	}
	for _, g := range groups {
		if g.Key == "sha256:aaa" && g.Counts.Total() != 3 {
			t.Errorf("web image counts %+v, want 3 findings counted once", g.Counts)
		}
	}
}

func TestStaleToggle(t *testing.T) {
	s := snapshot(t)
	q := mustQuery(t, "cve:CVE-2023-9999", VulnSchema)
	if rows, _, _ := s.MatchVulns(q, false); len(rows) != 0 {
		t.Errorf("stale finding visible without stale=1")
	}
	if rows, _, _ := s.MatchVulns(q, true); len(rows) != 1 {
		t.Errorf("stale finding hidden with stale=1")
	}
}

func TestGroupings(t *testing.T) {
	s := snapshot(t)
	rows, all, m := s.MatchVulns(mustQuery(t, "sev:critical fixable:yes", VulnSchema), false)
	cves := GroupByCVE(rows)
	if len(cves) != 1 || cves[0].ID != "CVE-2024-0001" || cves[0].Images != 2 || cves[0].Workloads != 3 {
		t.Errorf("by cve = %+v", cves)
	}
	wl := GroupByWorkload(rows)
	if len(wl) != 3 {
		t.Errorf("by workload = %d groups, want 3", len(wl))
	}
	f := GroupByFinding(rows)
	if len(f) != 2 {
		t.Errorf("findings = %d, want 2 (one per image)", len(f))
	}
	facets := m.Facets(all, VulnFacets, 0)
	for _, v := range facets["sev"] {
		// Facets ignore the sev term and count unique findings.
		if v.Value == "HIGH" && v.Count != 0 {
			// HIGH has no fix, so fixable:yes removes it.
			t.Errorf("HIGH facet = %d, want 0", v.Count)
		}
	}
	if q := mustQuery(t, "ns:demo", VulnSchema); true {
		rows, _, _ := s.MatchVulns(q, false)
		if len(GroupByImage(rows)) != 1 {
			t.Errorf("ns:demo should match one image")
		}
	}
}

func TestSummary(t *testing.T) {
	sum := snapshot(t).Summary()
	want := reports.SeveritySummary{Critical: 2, High: 1, Medium: 1, Low: 1}
	want.Medium++ // db image
	want.Low++    // etcd image
	if sum.Vulns.Counts != want {
		t.Errorf("vuln counts = %+v, want %+v", sum.Vulns.Counts, want)
	}
	if sum.Vulns.Images != 4 || sum.Vulns.Workloads != 5 {
		t.Errorf("images %d workloads %d, want 4 and 5", sum.Vulns.Images, sum.Vulns.Workloads)
	}
	if sum.StaleWorkloads != 1 {
		t.Errorf("stale = %d, want 1", sum.StaleWorkloads)
	}
	if sum.Config.Failing != 3 || sum.Config.Counts.High != 1 || sum.Config.Counts.Medium != 3 {
		t.Errorf("config summary = %+v", sum.Config)
	}
	if sum.RBAC.Counts.Critical != 1 {
		t.Errorf("rbac summary = %+v", sum.RBAC)
	}
	wantSecrets := reports.SeveritySummary{High: 1, Medium: 1}
	if sum.Secrets.Scanned != 4 || sum.Secrets.Affected != 2 || sum.Secrets.Counts != wantSecrets {
		t.Errorf("secrets summary = %+v", sum.Secrets)
	}
	if len(sum.Compliance) != 1 || sum.Compliance[0].Pass != 1 {
		t.Errorf("compliance = %+v", sum.Compliance)
	}
}

func TestChecks(t *testing.T) {
	s := snapshot(t)
	rows, _, _ := s.MatchChecks(CheckConfig, mustQuery(t, "kind:Deployment", CheckSchema), false)
	if len(rows) != 3 {
		t.Fatalf("config rows for Deployment = %d, want 3", len(rows))
	}
	if g := GroupByCheck(rows); len(g) != 2 || g[0].Failed != 1 || g[1].Failed != 2 {
		t.Errorf("by check = %+v", g)
	}
	rows, _, _ = s.MatchChecks(CheckConfig, mustQuery(t, "kind:Cluster", CheckSchema), false)
	if g := GroupByResource(rows); len(g) != 1 || g[0].Counts.Medium != 1 {
		t.Errorf("custom resource config groups = %+v, want one group with the check once", g)
	}
	if f := Findings(rows); len(f) != 1 {
		t.Errorf("custom resource findings = %d, want 1", len(f))
	}
	if g := GroupByCheck(rows); len(g) != 1 || g[0].Failed != 1 {
		t.Errorf("by check = %+v, want the resource counted once", g)
	}
	if rows, _, _ := s.MatchChecks(CheckRBAC, mustQuery(t, "scope:cluster", CheckSchema), false); len(rows) != 1 {
		t.Errorf("rbac cluster rows = %d, want 1", len(rows))
	}
}

func TestSBOM(t *testing.T) {
	s := snapshot(t)
	rows, _, _ := s.MatchComponents(mustQuery(t, "pkgtype:alpine", ComponentSchema), false, "")
	if len(rows) != 1 || rows[0].C.Name != "openssl" {
		t.Fatalf("pkgtype rows = %d", len(rows))
	}
	if props := rows[0].C.Properties; len(props) != 1 {
		t.Errorf("properties not trimmed: %+v", props)
	}
	if rows, _, _ := s.MatchComponents(mustQuery(t, "version:<3.0.2 name:=openssl", ComponentSchema), false, ""); len(rows) != 1 {
		t.Errorf("version compare rows = %d, want 1", len(rows))
	}
	if rows, _, _ := s.MatchComponents(query.Query{}, false, "sha256:nope"); len(rows) != 0 {
		t.Errorf("key filter returned %d rows", len(rows))
	}
}

func TestForWorkload(t *testing.T) {
	s := snapshot(t)
	w := s.ForWorkload(reports.Resource{Kind: "Deployment", Namespace: "shop", Name: "web"})
	if len(w.Images) != 1 || w.Images[0].Key != "sha256:aaa" || !w.Images[0].HasSBOM {
		t.Errorf("images = %+v (stale image must not show)", w.Images)
	}
	if len(w.Config) != 3 || len(w.Secrets) != 1 {
		t.Errorf("config %d secrets %d, want 3 and 1", len(w.Config), len(w.Secrets))
	}
	db := s.ForWorkload(reports.Resource{Kind: "Cluster", Namespace: "shop", Name: "db"})
	if len(db.Images) != 1 || len(db.Reports) != 6 || len(db.Config) != 1 || len(db.Secrets) != 1 {
		t.Errorf("custom resource workload: %d images, %d reports, %d config, %d secrets, want 1, 6, 1, 1",
			len(db.Images), len(db.Reports), len(db.Config), len(db.Secrets))
	}
	if st := s.WorkloadStats()["shop/Cluster/db"]; st == nil || st.Secrets != 1 {
		t.Errorf("db stats = %+v, want 1 secret", st)
	}
	st := s.WorkloadStats()["shop/Deployment/web"]
	if st == nil || st.Vulns.Critical != 1 || st.Secrets != 1 {
		t.Errorf("stats = %+v", st)
	}
}

func TestCompliance(t *testing.T) {
	c := snapshot(t).Compliance[0]
	if c.Controls[0].TotalFail == nil || *c.Controls[0].TotalFail != 1 || !c.Controls[1].Manual {
		t.Errorf("controls = %+v", c.Controls)
	}
}

func TestSearch(t *testing.T) {
	hits := snapshot(t).Search("web", 8)
	kinds := map[string]int{}
	for _, h := range hits {
		kinds[h.Kind]++
	}
	if kinds["workload"] != 1 || kinds["image"] != 1 {
		t.Errorf("hits = %+v", hits)
	}
}
