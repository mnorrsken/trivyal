package index

import (
	"cmp"
	"strconv"
	"strings"
	"time"

	"github.com/mnorrsken/trivyal/internal/query"
	"github.com/mnorrsken/trivyal/internal/reports"
)

// Image is one container image, deduplicated by digest across workloads.
type Image struct {
	Key string `json:"key"`
	Ref string `json:"ref"`
	// Name is the reference without tag, the same for every build.
	Name       string                  `json:"name"`
	Registry   string                  `json:"registry"`
	Repository string                  `json:"repository"`
	Tag        string                  `json:"tag,omitempty"`
	Digest     string                  `json:"digest,omitempty"`
	OS         reports.OS              `json:"os"`
	Summary    reports.SeveritySummary `json:"summary"`
	Fixable    int                     `json:"fixable"`
	Updated    time.Time               `json:"updated"`
	Uses       []ImageUse              `json:"uses"`

	vulns []reports.Vulnerability
}

// ImageUse is one workload container running an image.
type ImageUse struct {
	Workload  Workload  `json:"workload"`
	Container string    `json:"container,omitempty"`
	Report    ReportRef `json:"report"`
}

// Vulns returns the image's vulnerabilities.
func (i *Image) Vulns() []reports.Vulnerability { return i.vulns }

// VulnRow is one vulnerability in one workload container.
type VulnRow struct {
	Image *Image
	Use   ImageUse
	V     *reports.Vulnerability
	text  string
}

// VulnSchema lists the filters for vulnerabilities.
var VulnSchema = query.Schema{
	{Name: "sev", Aliases: []string{"severity"}, Help: "severity: critical, high, medium, low, unknown"},
	{Name: "cve", Aliases: []string{"id", "vuln"}, Help: "vulnerability ID, e.g. CVE-2024-*"},
	{Name: "pkg", Aliases: []string{"package"}, Mode: query.Contains, Help: "package name"},
	{Name: "fixable", Aliases: []string{"fix"}, Help: "yes when a fixed version exists"},
	{Name: "score", Mode: query.Number, Help: "CVSS score, e.g. >=7"},
	{Name: "published", Help: "publish date, e.g. >2024-01-01"},
	{Name: "image", Mode: query.Contains, Help: "image reference"},
	{Name: "registry", Mode: query.Contains, Help: "registry host"},
	{Name: "ns", Aliases: []string{"namespace"}, Help: "workload namespace"},
	{Name: "kind", Help: "workload kind"},
	{Name: "workload", Aliases: []string{"name"}, Mode: query.Contains, Help: "workload name"},
	{Name: "container", Mode: query.Contains, Help: "container name"},
	{Name: "os", Mode: query.Contains, Help: "image OS family/version"},
	{Name: "class", Help: "os-pkgs or lang-pkgs"},
	{Name: "title", Mode: query.Contains, Help: "words in the title"},
}

// VulnFacets are the fields shown as facets in the UI.
var VulnFacets = []string{"sev", "fixable", "ns", "kind", "registry", "class"}

func (r *VulnRow) Field(name string) []string {
	v := r.V
	switch name {
	case "sev":
		return []string{v.Severity}
	case "cve":
		return []string{v.ID}
	case "pkg":
		return []string{v.Resource}
	case "fixable":
		return []string{yesNo(v.FixedVersion != "")}
	case "score":
		if v.Score == nil {
			return nil
		}
		return []string{strconv.FormatFloat(*v.Score, 'f', 1, 64)}
	case "published":
		return []string{v.PublishedDate}
	case "image":
		return []string{r.Image.Ref}
	case "registry":
		return []string{r.Image.Registry}
	case "ns":
		return []string{r.Use.Workload.Namespace}
	case "kind":
		return []string{r.Use.Workload.Kind}
	case "workload":
		return []string{r.Use.Workload.Name}
	case "container":
		return []string{r.Use.Container}
	case "os":
		return []string{strings.TrimSpace(r.Image.OS.Family + " " + r.Image.OS.Name)}
	case "class":
		return []string{v.Class}
	case "title":
		return []string{v.Title}
	}
	return nil
}

func (r *VulnRow) Text() string { return r.text }

// Key makes facets count each image's finding once.
func (r *VulnRow) Key() string { return findingKey(r.Image, r.V) }

func (s *Snapshot) addVulns(kind string, r *reports.VulnerabilityReport, w Workload) {
	key := imageKey(r.Registry, r.Artifact)
	img := s.Images[key]
	if img == nil {
		img = &Image{
			Key:        key,
			Ref:        ImageRef(r.Registry, r.Artifact),
			Name:       ImageRef(r.Registry, reports.Artifact{Repository: r.Artifact.Repository}),
			Registry:   ImageRef(r.Registry, reports.Artifact{}),
			Repository: r.Artifact.Repository,
			Tag:        cleanTag(r.Artifact.Tag),
			Digest:     r.Artifact.Digest,
			OS:         r.OS,
			Summary:    r.Summary,
			Updated:    r.Updated,
			vulns:      r.Vulnerabilities,
		}
		for _, v := range r.Vulnerabilities {
			if v.FixedVersion != "" {
				img.Fixable++
			}
		}
		s.Images[key] = img
	} else if r.Updated.After(img.Updated) {
		// Prefer the newest scan of the same image.
		img.Summary, img.Updated, img.vulns, img.OS = r.Summary, r.Updated, r.Vulnerabilities, r.OS
		img.Fixable = 0
		for _, v := range r.Vulnerabilities {
			if v.FixedVersion != "" {
				img.Fixable++
			}
		}
	}
	use := ImageUse{Workload: w, Container: r.Container, Report: ReportRef{kind, r.Namespace, r.Name}}
	img.Uses = append(img.Uses, use)
	for i := range r.Vulnerabilities {
		v := &r.Vulnerabilities[i]
		s.Vulns = append(s.Vulns, &VulnRow{
			Image: img, Use: use, V: v,
			text: lower(v.ID, v.Resource, v.Title, img.Ref, w.Namespace, w.Name, r.Container),
		})
	}
}

// MatchVulns returns the rows matching q and the matcher (for facets).
func (s *Snapshot) MatchVulns(q query.Query, withStale bool) ([]*VulnRow, []query.Row, *query.Matcher) {
	m := query.NewMatcher(q, VulnSchema)
	var out []*VulnRow
	all := make([]query.Row, 0, len(s.Vulns))
	for _, r := range s.Vulns {
		if r.Use.Workload.Stale && !withStale {
			continue
		}
		all = append(all, r)
		if m.Match(r) {
			out = append(out, r)
		}
	}
	return out, all, m
}

func findingKey(img *Image, v *reports.Vulnerability) string {
	return img.Key + "|" + v.ID + "|" + v.Resource + "|" + v.InstalledVersion + "|" + v.Target
}

// ImageGroup aggregates matched vulnerabilities per image.
type ImageGroup struct {
	Key       string                  `json:"key"`
	Ref       string                  `json:"ref"`
	Digest    string                  `json:"digest,omitempty"`
	OS        reports.OS              `json:"os"`
	Counts    reports.SeveritySummary `json:"counts"`
	Fixable   int                     `json:"fixable"`
	Workloads []Workload              `json:"workloads"`
	Updated   time.Time               `json:"updated"`
}

// GroupByImage dedupes findings per image.
func GroupByImage(rows []*VulnRow) []*ImageGroup {
	groups := map[string]*ImageGroup{}
	seen := map[string]bool{}
	seenW := map[string]bool{}
	var order []*ImageGroup
	for _, r := range rows {
		g := groups[r.Image.Key]
		if g == nil {
			g = &ImageGroup{Key: r.Image.Key, Ref: r.Image.Ref, Digest: r.Image.Digest, OS: r.Image.OS, Updated: r.Image.Updated}
			groups[r.Image.Key] = g
			order = append(order, g)
		}
		wk := r.Image.Key + "|" + r.Use.Workload.String()
		if !seenW[wk] {
			seenW[wk] = true
			g.Workloads = append(g.Workloads, r.Use.Workload)
		}
		fk := findingKey(r.Image, r.V)
		if seen[fk] {
			continue
		}
		seen[fk] = true
		g.Counts.Inc(r.V.Severity)
		if r.V.FixedVersion != "" {
			g.Fixable++
		}
	}
	return order
}

// WorkloadGroup aggregates matched vulnerabilities per workload.
type WorkloadGroup struct {
	Workload Workload                `json:"workload"`
	Images   []string                `json:"images"`
	Counts   reports.SeveritySummary `json:"counts"`
	Fixable  int                     `json:"fixable"`
}

// GroupByWorkload counts findings per workload, deduped across its pods'
// containers that run the same image.
func GroupByWorkload(rows []*VulnRow) []*WorkloadGroup {
	groups := map[string]*WorkloadGroup{}
	seen := map[string]bool{}
	seenImg := map[string]bool{}
	var order []*WorkloadGroup
	for _, r := range rows {
		k := r.Use.Workload.String()
		g := groups[k]
		if g == nil {
			g = &WorkloadGroup{Workload: r.Use.Workload}
			groups[k] = g
			order = append(order, g)
		}
		ik := k + "|" + r.Image.Key
		if !seenImg[ik] {
			seenImg[ik] = true
			g.Images = append(g.Images, r.Image.Ref)
		}
		fk := k + "|" + findingKey(r.Image, r.V)
		if seen[fk] {
			continue
		}
		seen[fk] = true
		g.Counts.Inc(r.V.Severity)
		if r.V.FixedVersion != "" {
			g.Fixable++
		}
	}
	return order
}

// CVEGroup aggregates matched rows per vulnerability ID.
type CVEGroup struct {
	ID        string   `json:"id"`
	Severity  string   `json:"severity"`
	Title     string   `json:"title,omitempty"`
	Score     *float64 `json:"score,omitempty"`
	Published string   `json:"published,omitempty"`
	Link      string   `json:"link,omitempty"`
	Packages  []string `json:"packages"`
	Images    int      `json:"images"`
	Workloads int      `json:"workloads"`
	Fixable   bool     `json:"fixable"`
}

// GroupByCVE lists each vulnerability ID once with its reach.
func GroupByCVE(rows []*VulnRow) []*CVEGroup {
	groups := map[string]*CVEGroup{}
	imgs := map[string]bool{}
	wls := map[string]bool{}
	pkgs := map[string]bool{}
	var order []*CVEGroup
	for _, r := range rows {
		v := r.V
		g := groups[v.ID]
		if g == nil {
			g = &CVEGroup{ID: v.ID, Severity: v.Severity, Title: v.Title, Score: v.Score, Published: v.PublishedDate, Link: v.PrimaryLink}
			groups[v.ID] = g
			order = append(order, g)
		}
		if v.FixedVersion != "" {
			g.Fixable = true
		}
		if k := v.ID + "|" + r.Image.Key; !imgs[k] {
			imgs[k] = true
			g.Images++
		}
		if k := v.ID + "|" + r.Use.Workload.String(); !wls[k] {
			wls[k] = true
			g.Workloads++
		}
		if k := v.ID + "|" + v.Resource; !pkgs[k] {
			pkgs[k] = true
			g.Packages = append(g.Packages, v.Resource)
		}
	}
	return order
}

// Finding is one vulnerability in one image, with the workloads affected.
type Finding struct {
	ImageKey  string                 `json:"imageKey"`
	Image     string                 `json:"image"`
	ImageName string                 `json:"imageName"`
	Vuln      *reports.Vulnerability `json:"vuln"`
	Workloads []Workload             `json:"workloads"`
}

// GroupByFinding dedupes rows to one per image and vulnerability.
func GroupByFinding(rows []*VulnRow) []*Finding {
	groups := map[string]*Finding{}
	seenW := map[string]bool{}
	var order []*Finding
	for _, r := range rows {
		k := findingKey(r.Image, r.V)
		f := groups[k]
		if f == nil {
			f = &Finding{ImageKey: r.Image.Key, Image: r.Image.Ref, ImageName: r.Image.Name, Vuln: r.V}
			groups[k] = f
			order = append(order, f)
		}
		if wk := k + "|" + r.Use.Workload.String(); !seenW[wk] {
			seenW[wk] = true
			f.Workloads = append(f.Workloads, r.Use.Workload)
		}
	}
	return order
}

// severityCmp orders severity summaries, worst first.
func severityCmp(a, b reports.SeveritySummary) int {
	return cmp.Or(
		cmp.Compare(b.Critical, a.Critical),
		cmp.Compare(b.High, a.High),
		cmp.Compare(b.Medium, a.Medium),
		cmp.Compare(b.Low, a.Low),
		cmp.Compare(b.Unknown, a.Unknown),
	)
}

func scoreOf(p *float64) float64 {
	if p == nil {
		return -1
	}
	return *p
}

// Sort orders for each grouping. A leading "-" in the API reverses them.
var (
	ImageSorts = map[string]func(a, b *ImageGroup) int{
		"severity": func(a, b *ImageGroup) int { return cmp.Or(severityCmp(a.Counts, b.Counts), cmp.Compare(a.Ref, b.Ref)) },
		"image":    func(a, b *ImageGroup) int { return cmp.Compare(a.Ref, b.Ref) },
		"fixable": func(a, b *ImageGroup) int {
			return cmp.Or(cmp.Compare(b.Fixable, a.Fixable), cmp.Compare(a.Ref, b.Ref))
		},
		"workloads": func(a, b *ImageGroup) int {
			return cmp.Or(cmp.Compare(len(b.Workloads), len(a.Workloads)), cmp.Compare(a.Ref, b.Ref))
		},
		"total": func(a, b *ImageGroup) int {
			return cmp.Or(cmp.Compare(b.Counts.Total(), a.Counts.Total()), cmp.Compare(a.Ref, b.Ref))
		},
	}
	WorkloadSorts = map[string]func(a, b *WorkloadGroup) int{
		"severity": func(a, b *WorkloadGroup) int {
			return cmp.Or(severityCmp(a.Counts, b.Counts), cmp.Compare(a.Workload.String(), b.Workload.String()))
		},
		"workload":  func(a, b *WorkloadGroup) int { return cmp.Compare(a.Workload.Name, b.Workload.Name) },
		"namespace": func(a, b *WorkloadGroup) int { return cmp.Compare(a.Workload.String(), b.Workload.String()) },
		"fixable":   func(a, b *WorkloadGroup) int { return cmp.Compare(b.Fixable, a.Fixable) },
		"total":     func(a, b *WorkloadGroup) int { return cmp.Compare(b.Counts.Total(), a.Counts.Total()) },
	}
	CVESorts = map[string]func(a, b *CVEGroup) int{
		"severity": func(a, b *CVEGroup) int {
			return cmp.Or(cmp.Compare(reports.SeverityRank(a.Severity), reports.SeverityRank(b.Severity)),
				cmp.Compare(scoreOf(b.Score), scoreOf(a.Score)), cmp.Compare(b.Images, a.Images), cmp.Compare(b.ID, a.ID))
		},
		"score":     func(a, b *CVEGroup) int { return cmp.Compare(scoreOf(b.Score), scoreOf(a.Score)) },
		"id":        func(a, b *CVEGroup) int { return cmp.Compare(b.ID, a.ID) },
		"images":    func(a, b *CVEGroup) int { return cmp.Compare(b.Images, a.Images) },
		"workloads": func(a, b *CVEGroup) int { return cmp.Compare(b.Workloads, a.Workloads) },
		"published": func(a, b *CVEGroup) int { return cmp.Compare(b.Published, a.Published) },
	}
	FindingSorts = map[string]func(a, b *Finding) int{
		"severity": func(a, b *Finding) int {
			return cmp.Or(cmp.Compare(reports.SeverityRank(a.Vuln.Severity), reports.SeverityRank(b.Vuln.Severity)),
				cmp.Compare(scoreOf(b.Vuln.Score), scoreOf(a.Vuln.Score)), cmp.Compare(a.Image, b.Image))
		},
		"score":     func(a, b *Finding) int { return cmp.Compare(scoreOf(b.Vuln.Score), scoreOf(a.Vuln.Score)) },
		"id":        func(a, b *Finding) int { return cmp.Compare(b.Vuln.ID, a.Vuln.ID) },
		"package":   func(a, b *Finding) int { return cmp.Compare(a.Vuln.Resource, b.Vuln.Resource) },
		"image":     func(a, b *Finding) int { return cmp.Compare(a.Image, b.Image) },
		"published": func(a, b *Finding) int { return cmp.Compare(b.Vuln.PublishedDate, a.Vuln.PublishedDate) },
	}
)
