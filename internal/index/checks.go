package index

import (
	"cmp"
	"strings"
	"time"

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
	// Dup is set when a newer report covers the same resource: one report
	// per pod of a custom resource, or two ReplicaSets during a rollout.
	// Only the newest report counts.
	Dup     bool
	updated time.Time
	text    string
	// flagged is set on copies made by Apply.
	flagged bool
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

// uniqueChecks drops rows of reports that a newer report of the same
// resource replaces.
func uniqueChecks(rows []*CheckRow) []*CheckRow {
	out := rows[:0:0]
	for _, r := range rows {
		if !r.Dup {
			out = append(out, r)
		}
	}
	return out
}

// markDuplicateChecks sets Dup on rows from all but the newest report of
// each resource.
func (s *Snapshot) markDuplicateChecks() {
	type best struct {
		report  ReportRef
		updated time.Time
	}
	newest := map[string]best{}
	key := func(r *CheckRow) string { return r.Type + "|" + r.Resource.String() + "|" + yesNo(r.Resource.Stale) }
	for _, r := range s.Checks {
		k := key(r)
		b, ok := newest[k]
		if !ok || r.updated.After(b.updated) || (r.updated.Equal(b.updated) && r.Report.Name < b.report.Name) {
			newest[k] = best{r.Report, r.updated}
		}
	}
	for _, r := range s.Checks {
		r.Dup = newest[key(r)].report != r.Report
	}
}

func (s *Snapshot) addChecks(kind string, r *reports.CheckReport, w Workload) {
	typ := CheckType(kind)
	ref := ReportRef{kind, r.Namespace, r.Name}
	for i := range r.Checks {
		c := &r.Checks[i]
		s.Checks = append(s.Checks, &CheckRow{
			Type: typ, Cluster: !reports.Namespaced(kind), Resource: w, Report: ref, C: c, updated: r.Updated,
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
		if r.Type != typ || r.Dup || (r.Resource.Stale && !withStale) {
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
	Flagged  bool                    `json:"flagged,omitempty"`
}

// GroupByResource counts failed checks per resource.
func GroupByResource(rows []*CheckRow) []*ResourceGroup {
	groups := map[string]*ResourceGroup{}
	var order []*ResourceGroup
	for _, r := range uniqueChecks(rows) {
		k := r.Resource.String()
		g := groups[k]
		if g == nil {
			g = &ResourceGroup{Resource: r.Resource, Report: r.Report}
			groups[k] = g
			order = append(order, g)
		}
		g.Flagged = g.Flagged || r.flagged
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
	Flagged     bool   `json:"flagged,omitempty"`
}

// GroupByCheck counts resources per check.
func GroupByCheck(rows []*CheckRow) []*CheckGroup {
	groups := map[string]*CheckGroup{}
	var order []*CheckGroup
	for _, r := range uniqueChecks(rows) {
		g := groups[r.C.ID]
		if g == nil {
			c := r.C
			g = &CheckGroup{ID: c.ID, Title: c.Title, Severity: c.Severity, Category: c.Category, Description: c.Description, Remediation: c.Remediation}
			groups[c.ID] = g
			order = append(order, g)
		}
		g.Flagged = g.Flagged || r.flagged
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
	Flagged  bool           `json:"flagged,omitempty"`
}

func (g *ResourceGroup) IsFlagged() bool { return g.Flagged }
func (g *CheckGroup) IsFlagged() bool    { return g.Flagged }
func (f *CheckFinding) IsFlagged() bool  { return f.Flagged }

func (g *ResourceGroup) SortKey() string { return g.Report.String() }
func (g *CheckGroup) SortKey() string    { return g.ID }
func (f *CheckFinding) SortKey() string {
	return f.Report.String() + "|" + f.Check.ID + "|" + strings.Join(f.Check.Messages, " ")
}

// AsFinding returns the row as a CheckFinding.
func (r *CheckRow) AsFinding() *CheckFinding {
	return &CheckFinding{Resource: r.Resource, Report: r.Report, Check: r.C, Flagged: r.flagged}
}

// Findings flattens check rows, one per check and resource.
func Findings(rows []*CheckRow) []*CheckFinding {
	rows = uniqueChecks(rows)
	out := make([]*CheckFinding, len(rows))
	for i, r := range rows {
		out[i] = r.AsFinding()
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
