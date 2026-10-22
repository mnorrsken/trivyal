package index

import (
	"cmp"

	"github.com/mnorrsken/trivyal/internal/query"
	"github.com/mnorrsken/trivyal/internal/reports"
)

// Check report families.
const (
	CheckConfig = "config"
	CheckRBAC   = "rbac"
	CheckInfra  = "infra"
)

// CheckType maps a report resource to its check family.
func CheckType(resource string) string {
	switch resource {
	case reports.ConfigAuditReports, reports.ClusterConfigAuditReports:
		return CheckConfig
	case reports.RbacAssessmentReports, reports.ClusterRbacAssessmentReports:
		return CheckRBAC
	case reports.InfraAssessmentReports, reports.ClusterInfraAssessmentReports:
		return CheckInfra
	}
	return ""
}

// CheckRow is one check result on one resource.
type CheckRow struct {
	Type     string
	Cluster  bool
	Resource Workload
	Report   ReportRef
	C        *reports.Check
	text     string
}

// CheckSchema lists the filters for config audit, RBAC and infra checks.
var CheckSchema = query.Schema{
	{Name: "sev", Aliases: []string{"severity"}, Help: "severity: critical, high, medium, low"},
	{Name: "check", Aliases: []string{"id"}, Mode: query.Contains, Help: "check ID, e.g. KSV-0014"},
	{Name: "category", Mode: query.Contains, Help: "check category"},
	{Name: "title", Mode: query.Contains, Help: "words in the check title"},
	{Name: "kind", Help: "resource kind"},
	{Name: "ns", Aliases: []string{"namespace"}, Help: "resource namespace"},
	{Name: "resource", Aliases: []string{"name"}, Mode: query.Contains, Help: "resource name"},
	{Name: "status", Help: "fail or pass"},
	{Name: "scope", Help: "namespace or cluster"},
}

// CheckFacets are the fields shown as facets in the UI.
var CheckFacets = []string{"sev", "kind", "ns", "category", "status", "scope"}

func (r *CheckRow) Field(name string) []string {
	switch name {
	case "sev":
		return []string{r.C.Severity}
	case "check":
		return []string{r.C.ID}
	case "category":
		return []string{r.C.Category}
	case "title":
		return []string{r.C.Title}
	case "kind":
		return []string{r.Resource.Kind}
	case "ns":
		return []string{r.Resource.Namespace}
	case "resource":
		return []string{r.Resource.Name}
	case "status":
		if r.C.Success {
			return []string{"pass"}
		}
		return []string{"fail"}
	case "scope":
		if r.Cluster {
			return []string{"cluster"}
		}
		return []string{"namespace"}
	}
	return nil
}

func (r *CheckRow) Text() string { return r.text }

func (s *Snapshot) addChecks(kind string, r *reports.CheckReport, w Workload) {
	typ := CheckType(kind)
	ref := ReportRef{kind, r.Namespace, r.Name}
	for i := range r.Checks {
		c := &r.Checks[i]
		s.Checks = append(s.Checks, &CheckRow{
			Type: typ, Cluster: !reports.Namespaced(kind), Resource: w, Report: ref, C: c,
			text: lower(c.ID, c.Title, c.Category, w.Kind, w.Namespace, w.Name),
		})
	}
}

// MatchChecks returns the rows of one check family matching q.
func (s *Snapshot) MatchChecks(typ string, q query.Query, withStale bool) ([]*CheckRow, []query.Row, *query.Matcher) {
	m := query.NewMatcher(q, CheckSchema)
	var out []*CheckRow
	var all []query.Row
	for _, r := range s.Checks {
		if r.Type != typ || (r.Resource.Stale && !withStale) {
			continue
		}
		all = append(all, r)
		if m.Match(r) {
			out = append(out, r)
		}
	}
	return out, all, m
}

// ResourceGroup aggregates check results per resource.
type ResourceGroup struct {
	Resource Workload                `json:"resource"`
	Report   ReportRef               `json:"report"`
	Counts   reports.SeveritySummary `json:"counts"`
	Passed   int                     `json:"passed"`
}

// GroupByResource counts failed checks per resource.
func GroupByResource(rows []*CheckRow) []*ResourceGroup {
	groups := map[string]*ResourceGroup{}
	var order []*ResourceGroup
	for _, r := range rows {
		k := r.Resource.String() + "|" + r.Report.Name
		g := groups[k]
		if g == nil {
			g = &ResourceGroup{Resource: r.Resource, Report: r.Report}
			groups[k] = g
			order = append(order, g)
		}
		if r.C.Success {
			g.Passed++
		} else {
			g.Counts.Inc(r.C.Severity)
		}
	}
	return order
}

// CheckGroup aggregates results per check ID.
type CheckGroup struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Severity    string `json:"severity"`
	Category    string `json:"category,omitempty"`
	Description string `json:"description,omitempty"`
	Remediation string `json:"remediation,omitempty"`
	Failed      int    `json:"failed"`
	Passed      int    `json:"passed"`
}

// GroupByCheck counts resources per check.
func GroupByCheck(rows []*CheckRow) []*CheckGroup {
	groups := map[string]*CheckGroup{}
	var order []*CheckGroup
	for _, r := range rows {
		g := groups[r.C.ID]
		if g == nil {
			c := r.C
			g = &CheckGroup{ID: c.ID, Title: c.Title, Severity: c.Severity, Category: c.Category, Description: c.Description, Remediation: c.Remediation}
			groups[c.ID] = g
			order = append(order, g)
		}
		if r.C.Success {
			g.Passed++
		} else {
			g.Failed++
		}
	}
	return order
}

// CheckFinding is one check result, flattened for the API.
type CheckFinding struct {
	Resource Workload       `json:"resource"`
	Report   ReportRef      `json:"report"`
	Check    *reports.Check `json:"check"`
}

// Findings flattens check rows.
func Findings(rows []*CheckRow) []*CheckFinding {
	out := make([]*CheckFinding, len(rows))
	for i, r := range rows {
		out[i] = &CheckFinding{Resource: r.Resource, Report: r.Report, Check: r.C}
	}
	return out
}

var (
	ResourceSorts = map[string]func(a, b *ResourceGroup) int{
		"severity": func(a, b *ResourceGroup) int {
			return cmp.Or(severityCmp(a.Counts, b.Counts), cmp.Compare(a.Resource.String(), b.Resource.String()))
		},
		"resource":  func(a, b *ResourceGroup) int { return cmp.Compare(a.Resource.Name, b.Resource.Name) },
		"namespace": func(a, b *ResourceGroup) int { return cmp.Compare(a.Resource.String(), b.Resource.String()) },
		"kind":      func(a, b *ResourceGroup) int { return cmp.Compare(a.Resource.Kind, b.Resource.Kind) },
		"total":     func(a, b *ResourceGroup) int { return cmp.Compare(b.Counts.Total(), a.Counts.Total()) },
	}
	CheckSorts = map[string]func(a, b *CheckGroup) int{
		"severity": func(a, b *CheckGroup) int {
			return cmp.Or(cmp.Compare(reports.SeverityRank(a.Severity), reports.SeverityRank(b.Severity)),
				cmp.Compare(b.Failed, a.Failed), cmp.Compare(a.ID, b.ID))
		},
		"id":     func(a, b *CheckGroup) int { return cmp.Compare(a.ID, b.ID) },
		"failed": func(a, b *CheckGroup) int { return cmp.Compare(b.Failed, a.Failed) },
		"title":  func(a, b *CheckGroup) int { return cmp.Compare(a.Title, b.Title) },
	}
	CheckFindingSorts = map[string]func(a, b *CheckFinding) int{
		"severity": func(a, b *CheckFinding) int {
			return cmp.Or(cmp.Compare(reports.SeverityRank(a.Check.Severity), reports.SeverityRank(b.Check.Severity)),
				cmp.Compare(a.Resource.String(), b.Resource.String()), cmp.Compare(a.Check.ID, b.Check.ID))
		},
		"id":       func(a, b *CheckFinding) int { return cmp.Compare(a.Check.ID, b.Check.ID) },
		"resource": func(a, b *CheckFinding) int { return cmp.Compare(a.Resource.String(), b.Resource.String()) },
	}
)
