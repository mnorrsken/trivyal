package index

import (
	"slices"
	"testing"

	"github.com/mnorrsken/trivyal/internal/query"
	"github.com/mnorrsken/trivyal/internal/reports"
)

// mark hides what t covers in s now, minus the findings in except (as if
// those had shown up after it was hidden).
func mark(t *testing.T, s *Snapshot, tg Target, except ...string) Mark {
	t.Helper()
	ids, err := s.Findings(tg)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) == 0 {
		t.Fatalf("%+v covers no findings", tg)
	}
	m := Mark{Target: tg, Findings: map[string]bool{}}
	for _, id := range ids {
		m.Findings[id] = true
	}
	for _, id := range except {
		delete(m.Findings, id)
	}
	return m
}

func TestTargetKeys(t *testing.T) {
	res := &reports.Resource{Kind: "Deployment", Namespace: "shop", Name: "web"}
	for _, tg := range []Target{
		{Kind: TargetImage, Image: "registry.example.com/shop/web"},
		{Kind: TargetImageCVE, Image: "registry.example.com/shop/web", ID: "CVE-2024-0001"},
		{Kind: TargetCVE, ID: "CVE-2024-0001"},
		{Kind: TargetSecret, Image: "registry.example.com/shop/web", Rule: "private-key", File: "/etc/a|b.pem"},
		{Kind: TargetCheck, Type: CheckConfig, ID: "AVD-KSV-0014"},
		{Kind: TargetResourceCheck, Type: CheckRBAC, ID: "AVD-KSV-0041", Resource: &reports.Resource{Kind: "ClusterRole", Name: "admin"}},
		{Kind: TargetWorkload, Resource: res},
		{Kind: TargetNamespace, Namespace: "shop"},
	} {
		key, err := tg.Key()
		if err != nil {
			t.Fatalf("%+v: %v", tg, err)
		}
		back, err := ParseTarget(tg.Kind, key)
		if err != nil {
			t.Fatalf("%s %q: %v", tg.Kind, key, err)
		}
		if k2, _ := back.Key(); k2 != key {
			t.Errorf("%s: %q parsed back to %q", tg.Kind, key, k2)
		}
	}
	for _, tg := range []Target{{Kind: "nope", ID: "x"}, {Kind: TargetImageCVE, Image: "x"}, {Kind: TargetWorkload, Resource: &reports.Resource{Kind: "Deployment"}}} {
		if _, err := tg.Key(); err == nil {
			t.Errorf("%+v: no error", tg)
		}
	}
}

func TestApplyHides(t *testing.T) {
	s := snapshot(t)
	web := "registry.example.com/shop/web"
	count := func(v *Snapshot, q string) int {
		rows, _, _ := v.MatchVulns(mustQuery(t, q, VulnSchema), false)
		return len(GroupByFinding(rows))
	}

	// The whole image, with one finding new since it was hidden.
	v := s.Apply([]Mark{mark(t, s, Target{Kind: TargetImage, Image: web}, "vuln|CVE-2024-0003|busybox|1.36.0")})
	if n := count(v, "image:shop/web"); n != 1 {
		t.Errorf("hidden image shows %d findings, want only the new one", n)
	}
	if n := count(v, ""); n != count(s, "")-2 {
		t.Errorf("findings %d, want %d", n, count(s, "")-2)
	}
	if rows, _, _ := v.MatchSecrets(query.Query{}, false); len(UniqueSecrets(rows)) != 1 {
		t.Errorf("image secret not hidden: %d secrets", len(UniqueSecrets(rows)))
	}
	if img := v.Images["sha256:aaa"]; img.Summary.Total() != 1 || len(img.Vulns()) != 1 || img.Fixable != 1 {
		t.Errorf("image counts not redone: %+v, %d vulns", img.Summary, len(img.Vulns()))
	}
	if s.Images["sha256:aaa"].Summary.Total() != 3 || count(s, "image:shop/web") != 3 {
		t.Error("Apply changed the original snapshot")
	}

	// A CVE in one image leaves the other image with it alone.
	v = s.Apply([]Mark{mark(t, s, Target{Kind: TargetImageCVE, Image: web, ID: "CVE-2024-0001"})})
	if n := count(v, "cve:CVE-2024-0001"); n != 1 {
		t.Errorf("CVE in image: %d findings left, want 1 (tools)", n)
	}
	v = s.Apply([]Mark{mark(t, s, Target{Kind: TargetCVE, ID: "CVE-2024-0001"})})
	if n := count(v, "cve:CVE-2024-0001"); n != 0 {
		t.Errorf("CVE everywhere: %d findings left", n)
	}

	// One workload: the other workload with the same image keeps its counts.
	res := reports.Resource{Kind: "Deployment", Namespace: "shop", Name: "web"}
	v = s.Apply([]Mark{mark(t, s, Target{Kind: TargetWorkload, Resource: &res})})
	if wr := v.ForWorkload(res); len(wr.Images) != 1 || wr.Images[0].Counts.Total() != 0 || len(wr.Config) != 0 || len(wr.Secrets) != 0 {
		t.Errorf("hidden workload: %+v", wr)
	}
	api := v.ForWorkload(reports.Resource{Kind: "Deployment", Namespace: "shop", Name: "api"})
	if len(api.Images) != 1 || api.Images[0].Counts.Total() != 3 {
		t.Errorf("other workload lost findings: %+v", api.Images)
	}

	// A namespace hides its checks and secrets; cluster checks stay.
	v = s.Apply([]Mark{mark(t, s, Target{Kind: TargetNamespace, Namespace: "shop"})})
	sum := v.Summary()
	if sum.Config.Counts.Total() != 0 || sum.RBAC.Counts.Total() != 1 || sum.Secrets.Counts.Total() != 0 || len(sum.TopImages) != 2 {
		t.Errorf("namespace hidden: config %+v rbac %+v secrets %+v images %d", sum.Config.Counts, sum.RBAC.Counts, sum.Secrets.Counts, len(sum.TopImages))
	}

	// A check everywhere, matched whatever the case of the ID.
	v = s.Apply([]Mark{mark(t, s, Target{Kind: TargetCheck, Type: CheckConfig, ID: "avd-ksv-0012"})})
	rows, _, _ := v.MatchChecks(CheckConfig, query.Query{}, false)
	for _, g := range GroupByCheck(rows) {
		if g.ID == "AVD-KSV-0012" {
			t.Errorf("hidden check listed: %+v", g)
		}
	}
	if len(GroupByCheck(rows)) != 3 {
		t.Errorf("checks = %d, want 3", len(GroupByCheck(rows)))
	}
}

func TestApplyFlags(t *testing.T) {
	s := snapshot(t)
	web := "registry.example.com/shop/web"
	flag := func(tg Target) Mark { return Mark{Target: tg, Flag: true} }

	// A flag covers the whole target, also findings it did not have yet.
	v := s.Apply([]Mark{flag(Target{Kind: TargetCVE, ID: "CVE-2024-0001"})})
	rows, _, _ := v.MatchVulns(query.Query{}, false)
	for _, g := range GroupByCVE(rows) {
		if g.Flagged != (g.ID == "CVE-2024-0001") {
			t.Errorf("cve %s flagged = %v", g.ID, g.Flagged)
		}
	}
	imgs := GroupByImage(rows)
	slices.SortStableFunc(imgs, FlaggedFirst)
	if !imgs[0].Flagged || !imgs[1].Flagged || imgs[2].Flagged {
		t.Errorf("images with the flagged CVE do not sort first: %+v", imgs)
	}
	if s.Vulns[0].flagged {
		t.Error("Apply changed the original rows")
	}

	// Namespace and workload flags reach the summaries.
	v = s.Apply([]Mark{flag(Target{Kind: TargetNamespace, Namespace: "demo"})})
	for _, n := range v.Summary().Namespaces {
		if n.Flagged != (n.Namespace == "demo") {
			t.Errorf("namespace %s flagged = %v", n.Namespace, n.Flagged)
		}
	}
	res := reports.Resource{Kind: "Deployment", Namespace: "shop", Name: "web"}
	v = s.Apply([]Mark{flag(Target{Kind: TargetWorkload, Resource: &res})})
	if st := v.WorkloadStats()[res.String()]; !st.Flagged {
		t.Errorf("workload stats not flagged: %+v", st)
	}
	if wr := v.ForWorkload(res); !wr.Images[0].Flagged || !wr.Config[0].Flagged || !wr.Secrets[0].Flagged {
		t.Errorf("workload reports not flagged: %+v", wr)
	}

	// A hide wins over a flag on the same findings.
	v = s.Apply([]Mark{flag(Target{Kind: TargetImage, Image: web}), mark(t, s, Target{Kind: TargetImageCVE, Image: web, ID: "CVE-2024-0001"})})
	rows, _, _ = v.MatchVulns(mustQuery(t, "image:shop/web", VulnSchema), false)
	if f := GroupByFinding(rows); len(f) != 2 || !f[0].Flagged || !f[1].Flagged {
		t.Errorf("flagged image with one hidden CVE: %+v", f)
	}
}
