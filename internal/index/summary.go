package index

import (
	"cmp"
	"slices"
	"time"

	"github.com/mnorrsken/trivyal/internal/reports"
)

// Summary is everything the dashboard shows.
type Summary struct {
	Installed  bool                `json:"installed"`
	Built      time.Time           `json:"built"`
	Reports    map[string]int      `json:"reports"`
	Scanners   []string            `json:"scanners"`
	Oldest     *time.Time          `json:"oldest,omitempty"`
	Newest     *time.Time          `json:"newest,omitempty"`
	Vulns      VulnSummary         `json:"vulns"`
	Config     CheckSummary        `json:"config"`
	RBAC       CheckSummary        `json:"rbac"`
	Infra      CheckSummary        `json:"infra"`
	Secrets    SecretSummary       `json:"secrets"`
	Compliance []ComplianceSummary `json:"compliance"`
	TopImages  []*ImageGroup       `json:"topImages"`
	Namespaces []*NamespaceSummary `json:"namespaces"`
	// StaleWorkloads counts old ReplicaSets hidden from all views.
	StaleWorkloads int `json:"staleWorkloads"`
}

type VulnSummary struct {
	Counts    reports.SeveritySummary `json:"counts"`
	Fixable   int                     `json:"fixable"`
	Images    int                     `json:"images"`
	Workloads int                     `json:"workloads"`
}

type CheckSummary struct {
	Counts    reports.SeveritySummary `json:"counts"`
	Resources int                     `json:"resources"`
	Failing   int                     `json:"failing"`
}

type SecretSummary struct {
	Counts   reports.SeveritySummary `json:"counts"`
	Scanned  int                     `json:"scanned"`
	Affected int                     `json:"affected"`
}

type ComplianceSummary struct {
	Name    string    `json:"name"`
	ID      string    `json:"id"`
	Title   string    `json:"title"`
	Pass    int       `json:"pass"`
	Fail    int       `json:"fail"`
	Updated time.Time `json:"updated"`
}

type NamespaceSummary struct {
	Namespace string                  `json:"namespace"`
	Vulns     reports.SeveritySummary `json:"vulns"`
	Config    reports.SeveritySummary `json:"config"`
	Secrets   int                     `json:"secrets"`
	Workloads int                     `json:"workloads"`
	Flagged   bool                    `json:"flagged,omitempty"`
}

// Summary computes the dashboard data. Stale workloads are left out.
func (s *Snapshot) Summary() *Summary {
	sum := &Summary{
		Installed: s.Installed,
		Built:     s.Built,
		Reports:   s.Counts,
		Scanners:  sortedKeys(s.Scanners),
	}
	if !s.Oldest.IsZero() {
		o, n := s.Oldest, s.Newest
		sum.Oldest, sum.Newest = &o, &n
	}

	nss := map[string]*NamespaceSummary{}
	ns := func(name string) *NamespaceSummary {
		if name == "" {
			return nil
		}
		n := nss[name]
		if n == nil {
			n = &NamespaceSummary{Namespace: name}
			nss[name] = n
		}
		return n
	}

	stale := map[string]bool{}
	workloads := map[string]bool{}
	var live []*VulnRow
	seenNS := map[string]bool{}
	for _, r := range s.Vulns {
		w := r.Use.Workload
		if w.Stale {
			stale[w.String()] = true
			continue
		}
		live = append(live, r)
		if !workloads[w.String()] {
			workloads[w.String()] = true
			if n := ns(w.Namespace); n != nil {
				n.Workloads++
			}
		}
		if n := ns(w.Namespace); n != nil && r.flagged {
			n.Flagged = true
		}
		k := w.Namespace + "|" + findingKey(r.Image.Key, r.V)
		if !seenNS[k] {
			seenNS[k] = true
			if n := ns(w.Namespace); n != nil {
				n.Vulns.Inc(r.V.Severity)
			}
		}
	}
	images := GroupByImage(live)
	for _, g := range images {
		sum.Vulns.Counts.Add(g.Counts)
		sum.Vulns.Fixable += g.Fixable
	}
	sum.Vulns.Images = len(images)
	sum.Vulns.Workloads = len(workloads)
	slices.SortStableFunc(images, ImageSorts["severity"])
	sum.TopImages = images[:min(10, len(images))]

	failRes := map[string]map[string]bool{CheckConfig: {}, CheckRBAC: {}, CheckInfra: {}}
	for _, r := range s.Checks {
		if r.Resource.Stale {
			stale[r.Resource.String()] = true
		}
	}
	for _, r := range uniqueChecks(s.Checks) {
		if r.Resource.Stale {
			continue
		}
		var cs *CheckSummary
		switch r.Type {
		case CheckConfig:
			cs = &sum.Config
		case CheckRBAC:
			cs = &sum.RBAC
		case CheckInfra:
			cs = &sum.Infra
		default:
			continue
		}
		if r.C.Success {
			continue
		}
		failRes[r.Type][r.Resource.String()] = true
		cs.Counts.Inc(r.C.Severity)
		if r.Type == CheckConfig {
			if n := ns(r.Resource.Namespace); n != nil {
				n.Config.Inc(r.C.Severity)
				n.Flagged = n.Flagged || r.flagged
			}
		}
	}
	sum.Config.Failing, sum.RBAC.Failing, sum.Infra.Failing = len(failRes[CheckConfig]), len(failRes[CheckRBAC]), len(failRes[CheckInfra])
	sum.Config.Resources = s.Counts[reports.ConfigAuditReports] + s.Counts[reports.ClusterConfigAuditReports]
	sum.RBAC.Resources = s.Counts[reports.RbacAssessmentReports] + s.Counts[reports.ClusterRbacAssessmentReports]
	sum.Infra.Resources = s.Counts[reports.InfraAssessmentReports] + s.Counts[reports.ClusterInfraAssessmentReports]

	affected := map[string]bool{}
	for _, sc := range s.SecretScans {
		if sc.Workload.Stale {
			continue
		}
		sum.Secrets.Scanned++
		if sc.Summary.Total() > 0 {
			affected[sc.Workload.String()] = true
		}
	}
	seenSecret := map[string]bool{}
	for _, r := range s.Secrets {
		if r.Scan.Workload.Stale {
			continue
		}
		if k := r.Key(); !seenSecret[k] {
			seenSecret[k] = true
			sum.Secrets.Counts.Inc(r.S.Severity)
		}
		if k := r.Scan.Workload.Namespace + "|" + r.Key(); !seenSecret[k] {
			seenSecret[k] = true
			if n := ns(r.Scan.Workload.Namespace); n != nil {
				n.Secrets++
				n.Flagged = n.Flagged || r.flagged
			}
		}
	}
	sum.Secrets.Affected = len(affected)

	for _, c := range s.Compliance {
		sum.Compliance = append(sum.Compliance, ComplianceSummary{
			Name: c.Name, ID: c.ID, Title: c.Title, Pass: c.Pass, Fail: c.Fail, Updated: c.Updated,
		})
	}
	slices.SortFunc(sum.Compliance, func(a, b ComplianceSummary) int { return cmp.Compare(a.Name, b.Name) })

	for _, n := range nss {
		sum.Namespaces = append(sum.Namespaces, n)
	}
	slices.SortFunc(sum.Namespaces, func(a, b *NamespaceSummary) int {
		return cmp.Or(severityCmp(a.Vulns, b.Vulns), severityCmp(a.Config, b.Config), cmp.Compare(a.Namespace, b.Namespace))
	})
	sum.StaleWorkloads = len(stale)
	return sum
}

func sortedKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}
