package index

import (
	"cmp"
	"time"

	"github.com/mnorrsken/trivyal/internal/query"
	"github.com/mnorrsken/trivyal/internal/reports"
)

// SecretScan is one exposed secret report, kept so clean scans can be shown.
type SecretScan struct {
	Workload  Workload                `json:"workload"`
	Container string                  `json:"container,omitempty"`
	Image     string                  `json:"image"`
	ImageKey  string                  `json:"imageKey"`
	ImageName string                  `json:"imageName"`
	Report    ReportRef               `json:"report"`
	Summary   reports.SeveritySummary `json:"summary"`
	Updated   time.Time               `json:"updated"`
}

// SecretRow is one secret found in one workload container image.
type SecretRow struct {
	Scan *SecretScan
	S    *reports.Secret
	text string
}

// SecretSchema lists the filters for exposed secrets.
var SecretSchema = query.Schema{
	{Name: "sev", Aliases: []string{"severity"}, Help: "severity: critical, high, medium, low"},
	{Name: "rule", Aliases: []string{"id"}, Mode: query.Contains, Help: "rule ID, e.g. aws-access-key-id"},
	{Name: "category", Mode: query.Contains, Help: "secret category"},
	{Name: "target", Aliases: []string{"file"}, Mode: query.Contains, Help: "file path in the image"},
	{Name: "image", Mode: query.Contains, Help: "image reference"},
	{Name: "ns", Aliases: []string{"namespace"}, Help: "workload namespace"},
	{Name: "kind", Help: "workload kind"},
	{Name: "workload", Aliases: []string{"name"}, Mode: query.Contains, Help: "workload name"},
}

// SecretFacets are the fields shown as facets in the UI.
var SecretFacets = []string{"sev", "category", "rule", "ns", "kind"}

func (r *SecretRow) Field(name string) []string {
	switch name {
	case "sev":
		return []string{r.S.Severity}
	case "rule":
		return []string{r.S.RuleID}
	case "category":
		return []string{r.S.Category}
	case "target":
		return []string{r.S.Target}
	case "image":
		return []string{r.Scan.Image}
	case "ns":
		return []string{r.Scan.Workload.Namespace}
	case "kind":
		return []string{r.Scan.Workload.Kind}
	case "workload":
		return []string{r.Scan.Workload.Name}
	}
	return nil
}

func (r *SecretRow) Text() string { return r.text }

// Key identifies a secret in an image, so a secret is counted once per
// image like a vulnerability, however many pods run the image.
func (r *SecretRow) Key() string {
	return r.Scan.ImageKey + "|" + r.S.RuleID + "|" + r.S.Target + "|" + r.S.Match
}

// UniqueSecrets keeps one row per workload and secret (pods of one
// workload run the same image and report the same secret).
func UniqueSecrets(rows []*SecretRow) []*SecretRow {
	seen := make(map[string]bool, len(rows))
	out := rows[:0:0]
	for _, r := range rows {
		if k := r.Scan.Workload.String() + "|" + r.Key(); !seen[k] {
			seen[k] = true
			out = append(out, r)
		}
	}
	return out
}

func (s *Snapshot) addSecrets(kind string, r *reports.ExposedSecretReport, w Workload) {
	scan := &SecretScan{
		Workload: w, Container: r.Container,
		Image: ImageRef(r.Registry, r.Artifact), ImageKey: imageKey(r.Registry, r.Artifact),
		ImageName: ImageRef(r.Registry, reports.Artifact{Repository: r.Artifact.Repository}),
		Report: ReportRef{kind, r.Namespace, r.Name}, Summary: r.Summary, Updated: r.Updated,
	}
	s.SecretScans = append(s.SecretScans, scan)
	for i := range r.Secrets {
		sec := &r.Secrets[i]
		s.Secrets = append(s.Secrets, &SecretRow{
			Scan: scan, S: sec,
			text: lower(sec.RuleID, sec.Title, sec.Category, sec.Target, scan.Image, w.Namespace, w.Name),
		})
	}
}

// MatchSecrets returns the rows matching q.
func (s *Snapshot) MatchSecrets(q query.Query, withStale bool) ([]*SecretRow, []query.Row, *query.Matcher) {
	m := query.NewMatcher(q, SecretSchema)
	var out []*SecretRow
	var all []query.Row
	for _, r := range s.Secrets {
		if r.Scan.Workload.Stale && !withStale {
			continue
		}
		all = append(all, r)
		if m.Match(r) {
			out = append(out, r)
		}
	}
	return out, all, m
}

// SecretFinding is one secret, flattened for the API.
type SecretFinding struct {
	Workload  Workload        `json:"workload"`
	Container string          `json:"container,omitempty"`
	Image     string          `json:"image"`
	ImageKey  string          `json:"imageKey"`
	ImageName string          `json:"imageName"`
	Report    ReportRef       `json:"report"`
	Secret    *reports.Secret `json:"secret"`
}

// SecretFindings flattens secret rows.
func SecretFindings(rows []*SecretRow) []*SecretFinding {
	out := make([]*SecretFinding, len(rows))
	for i, r := range rows {
		out[i] = &SecretFinding{
			Workload: r.Scan.Workload, Container: r.Scan.Container, Image: r.Scan.Image,
			ImageKey: r.Scan.ImageKey, ImageName: r.Scan.ImageName, Report: r.Scan.Report, Secret: r.S,
		}
	}
	return out
}

var SecretSorts = map[string]func(a, b *SecretFinding) int{
	"severity": func(a, b *SecretFinding) int {
		return cmp.Or(cmp.Compare(reports.SeverityRank(a.Secret.Severity), reports.SeverityRank(b.Secret.Severity)),
			cmp.Compare(a.Workload.String(), b.Workload.String()), cmp.Compare(a.Secret.Target, b.Secret.Target))
	},
	"rule":     func(a, b *SecretFinding) int { return cmp.Compare(a.Secret.RuleID, b.Secret.RuleID) },
	"workload": func(a, b *SecretFinding) int { return cmp.Compare(a.Workload.String(), b.Workload.String()) },
	"target":   func(a, b *SecretFinding) int { return cmp.Compare(a.Secret.Target, b.Secret.Target) },
}
