package index

import (
	"cmp"
	"slices"
	"time"

	"github.com/mnorrsken/trivyal/internal/query"
	"github.com/mnorrsken/trivyal/internal/reports"
)

// Scan is one entry of the scans list: a scan job that is running or
// failed, or the last scan of a resource as its report records it. A new
// scan replaces the report, so each resource has one finished entry.
type Scan struct {
	State    string           `json:"state"`
	Type     string           `json:"type"`
	Time     time.Time        `json:"time"`
	Finished *time.Time       `json:"finished,omitempty"`
	Resource reports.Resource `json:"resource"`
	Workload Workload         `json:"workload"`
	Images   []ScanImage      `json:"images,omitempty"`
	Report   *ReportRef       `json:"report,omitempty"`
	Job      *JobRef          `json:"job,omitempty"`
	Scanner  string           `json:"scanner,omitempty"`
	Message  string           `json:"message,omitempty"`
	// Summary counts findings by severity (vulnerability, secret and check
	// reports), as the report has them: hidden findings are included.
	Summary    *reports.SeveritySummary `json:"summary,omitempty"`
	Components *int                     `json:"components,omitempty"`
	Pass       *int                     `json:"pass,omitempty"`
	Fail       *int                     `json:"fail,omitempty"`
	text       string
}

// ScanImage is a container image a scan covers. Key is set when the
// image has a page.
type ScanImage struct {
	Container string `json:"container,omitempty"`
	Image     string `json:"image"`
	Key       string `json:"key,omitempty"`
}

// JobRef identifies a scan job.
type JobRef struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

// scanTypes maps report resources to scan types.
var scanTypes = map[string]string{
	reports.VulnerabilityReports:          "vulnerability",
	reports.ClusterVulnerabilityReports:   "vulnerability",
	reports.ConfigAuditReports:            CheckConfig,
	reports.ClusterConfigAuditReports:     CheckConfig,
	reports.ExposedSecretReports:          "secret",
	reports.RbacAssessmentReports:         CheckRBAC,
	reports.ClusterRbacAssessmentReports:  CheckRBAC,
	reports.InfraAssessmentReports:        CheckInfra,
	reports.ClusterInfraAssessmentReports: CheckInfra,
	reports.SbomReports:                   "sbom",
	reports.ClusterSbomReports:            "sbom",
	reports.ClusterComplianceReports:      "compliance",
}

// ScanSchema lists the filters for the scans list.
var ScanSchema = query.Schema{
	{Name: "state", Help: "running, failed or done"},
	{Name: "type", Help: "vulnerability, secret, sbom, config, rbac, infra, compliance"},
	{Name: "age", Help: "scanned within 1h, 24h or 7d"},
	{Name: "ns", Aliases: []string{"namespace"}, Help: "workload namespace"},
	{Name: "kind", Help: "workload kind"},
	{Name: "workload", Aliases: []string{"name"}, Mode: query.Contains, Help: "workload name"},
	{Name: "image", Mode: query.Contains, Help: "image reference"},
	{Name: "time", Help: "scan time, e.g. time:>=2026-01-02"},
}

// ScanFacets are the fields shown as facets in the UI.
var ScanFacets = []string{"state", "type", "age", "ns", "kind"}

// scanAges are the age buckets; a scan is in every bucket it fits in.
var scanAges = []struct {
	name string
	d    time.Duration
}{{"1h", time.Hour}, {"24h", 24 * time.Hour}, {"7d", 7 * 24 * time.Hour}}

func (r *Scan) Field(name string) []string {
	switch name {
	case "state":
		return []string{r.State}
	case "type":
		return []string{r.Type}
	case "age":
		var out []string
		age := time.Since(r.Time)
		for _, a := range scanAges {
			if age <= a.d {
				out = append(out, a.name)
			}
		}
		return out
	case "ns":
		return []string{r.Workload.Namespace}
	case "kind":
		return []string{r.Workload.Kind}
	case "workload":
		return []string{r.Workload.Name}
	case "image":
		out := make([]string, len(r.Images))
		for i, img := range r.Images {
			out[i] = img.Image
		}
		return out
	case "time":
		return []string{r.Time.UTC().Format(time.RFC3339)}
	}
	return nil
}

func (r *Scan) Text() string { return r.text }

func (r *Scan) SortKey() string {
	if r.Job != nil {
		return "job/" + r.Job.Namespace + "/" + r.Job.Name
	}
	return r.Report.String()
}

func (r *Scan) setText() {
	parts := []string{r.State, r.Type, r.Resource.String(), r.Workload.String(), r.Message, r.Scanner}
	for _, img := range r.Images {
		parts = append(parts, img.Container, img.Image)
	}
	r.text = lower(parts...)
}

// addScan adds the scan recorded by a namespaced or cluster report.
func (s *Snapshot) addScan(kind string, c *reports.Common, w Workload, img *ScanImage, sum *reports.SeveritySummary) *Scan {
	sc := &Scan{
		State: reports.JobDone, Type: scanTypes[kind], Time: c.Updated, Resource: c.Resource, Workload: w,
		Report: &ReportRef{kind, c.Namespace, c.Name}, Summary: sum,
	}
	if c.Scanner.Name != "" {
		sc.Scanner = c.Scanner.Name + " " + c.Scanner.Version
	}
	if img != nil {
		sc.Images = []ScanImage{*img}
	}
	sc.setText()
	s.Scans = append(s.Scans, sc)
	return sc
}

func (s *Snapshot) addComplianceScan(kind string, r *reports.ComplianceReport) {
	t := r.Updated
	if t.IsZero() {
		t = r.Created
	}
	res := reports.Resource{Kind: r.Kind, Name: r.Name}
	sc := &Scan{
		State: reports.JobDone, Type: scanTypes[kind], Time: t, Resource: res, Workload: Workload{Resource: res},
		Report: &ReportRef{kind, "", r.Name}, Pass: &r.Pass, Fail: &r.Fail,
	}
	sc.setText()
	s.Scans = append(s.Scans, sc)
}

// addScanJob adds a running or failed scan job. Finished jobs are left
// out: their report is in the list.
func (s *Snapshot) addScanJob(j reports.ScanJob, res *resolver) {
	if j.State == reports.JobDone {
		return
	}
	sc := &Scan{
		State: j.State, Type: j.Type, Time: j.Started, Resource: j.Resource, Workload: res.workload(j.Resource),
		Job: &JobRef{j.Namespace, j.Name}, Message: j.Message,
	}
	if !j.Finished.IsZero() {
		t := j.Finished
		sc.Finished = &t
	}
	for c, img := range j.Images {
		sc.Images = append(sc.Images, ScanImage{Container: c, Image: img})
	}
	slices.SortFunc(sc.Images, func(a, b ScanImage) int { return cmp.Compare(a.Container, b.Container) })
	sc.setText()
	s.Scans = append(s.Scans, sc)
}

// MatchScans returns the scans matching q.
func (s *Snapshot) MatchScans(q query.Query, withStale bool) ([]*Scan, []query.Row, *query.Matcher) {
	m := query.NewMatcher(q, ScanSchema)
	var out []*Scan
	var all []query.Row
	for _, r := range s.Scans {
		if r.Workload.Stale && !withStale {
			continue
		}
		all = append(all, r)
		if m.Match(r) {
			out = append(out, r)
		}
	}
	return out, all, m
}

var scanStateRank = map[string]int{reports.JobRunning: 0, reports.JobFailed: 1, reports.JobDone: 2}

func newestFirst(a, b *Scan) int { return b.Time.Compare(a.Time) }

// ScanSorts order the scans list. "recent" puts running and failed jobs
// first, then the newest scans; "time" is newest first.
var ScanSorts = map[string]func(a, b *Scan) int{
	"recent": func(a, b *Scan) int {
		return cmp.Or(cmp.Compare(scanStateRank[a.State], scanStateRank[b.State]), newestFirst(a, b))
	},
	"time": newestFirst,
	"type": func(a, b *Scan) int { return cmp.Or(cmp.Compare(a.Type, b.Type), newestFirst(a, b)) },
	"workload": func(a, b *Scan) int {
		return cmp.Or(cmp.Compare(a.Workload.String(), b.Workload.String()), newestFirst(a, b))
	},
}

func scanImage(container string, reg reports.Registry, a reports.Artifact) *ScanImage {
	return &ScanImage{Container: container, Image: ImageRef(reg, a), Key: imageKey(reg, a)}
}
