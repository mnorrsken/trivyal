package api

import (
	"cmp"
	"encoding/csv"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/mnorrsken/trivyal/internal/index"
	"github.com/mnorrsken/trivyal/internal/reports"
)

func (s *Server) vulnerabilities(w http.ResponseWriter, r *http.Request) {
	p, err := parseList(r, index.VulnSchema)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	snap, uv, ok := s.visible(w, r)
	if !ok {
		return
	}
	rows, all, m := snap.MatchVulns(p.q, p.stale)
	res := List{Page: p.page, Size: p.size, Group: p.group, Rows: len(rows), Facets: m.Facets(all, index.VulnFacets, 50)}
	if uv.hidden {
		every, _, _ := uv.base.MatchVulns(p.q, p.stale)
		res.Hidden = hiddenRows(uv, every, rows, index.GroupByFinding)
	}
	switch p.group {
	case "workload":
		g := index.GroupByWorkload(rows)
		res.Total = len(g)
		res.Items, res.Sort = page(g, p.sort, "severity", index.WorkloadSorts, p)
	case "cve":
		g := index.GroupByCVE(rows)
		res.Total = len(g)
		res.Items, res.Sort = page(g, p.sort, "severity", index.CVESorts, p)
	case "finding":
		g := index.GroupByFinding(rows)
		res.Total = len(g)
		res.Items, res.Sort = page(g, p.sort, "severity", index.FindingSorts, p)
	default:
		res.Group = "image"
		g := index.GroupByImage(rows)
		res.Total = len(g)
		res.Items, res.Sort = page(g, p.sort, "severity", index.ImageSorts, p)
	}
	writeJSON(w, res)
}

// ImageDetail is everything known about one image.
type ImageDetail struct {
	*index.Image
	Vulnerabilities []reports.Vulnerability `json:"vulnerabilities"`
	Secrets         []*index.SecretFinding  `json:"secrets"`
	SecretScanned   bool                    `json:"secretScanned"`
	SBOM            *index.SBOMInfo         `json:"sbom,omitempty"`
	// HiddenFindings counts the findings of the image's name (all tags)
	// the user hid.
	HiddenFindings int `json:"hiddenFindings"`
}

func (s *Server) image(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("key")
	snap, uv, ok := s.visible(w, r)
	if !ok {
		return
	}
	img := snap.Images[key]
	sb := snap.SBOMs[key]
	if img == nil && sb == nil {
		writeError(w, http.StatusNotFound, "image not found")
		return
	}
	d := ImageDetail{Image: img, SBOM: sb}
	if img != nil {
		d.HiddenFindings = uv.hiddenIn(index.Target{Kind: index.TargetImage, Image: img.Name})
		// Not nil when all are hidden: the UI tells "none" from "no report".
		d.Vulnerabilities = append([]reports.Vulnerability{}, img.Vulns()...)
		slices.SortStableFunc(d.Vulnerabilities, func(a, b reports.Vulnerability) int {
			return cmp.Or(cmp.Compare(reports.SeverityRank(a.Severity), reports.SeverityRank(b.Severity)),
				cmp.Compare(scoreOf(b.Score), scoreOf(a.Score)), cmp.Compare(a.Resource, b.Resource), cmp.Compare(a.ID, b.ID))
		})
	} else {
		d.Image = &index.Image{Key: sb.Key, Ref: sb.Ref, Digest: sb.Digest, Uses: sb.Uses, Updated: sb.Updated}
	}
	seen := map[string]bool{}
	for _, sc := range snap.SecretScans {
		if sc.ImageKey == key {
			d.SecretScanned = true
		}
	}
	for _, sr := range snap.Secrets {
		if sr.Scan.ImageKey != key {
			continue
		}
		k := sr.S.RuleID + "|" + sr.S.Target + "|" + sr.S.Match
		if seen[k] {
			continue
		}
		seen[k] = true
		d.Secrets = append(d.Secrets, index.SecretFindings([]*index.SecretRow{sr})...)
	}
	writeJSON(w, d)
}

func scoreOf(p *float64) float64 {
	if p == nil {
		return -1
	}
	return *p
}

// CVEDetail lists every place one vulnerability was found.
type CVEDetail struct {
	ID       string                 `json:"id"`
	Vuln     *reports.Vulnerability `json:"vuln"`
	Affected []*index.Finding       `json:"affected"`
	// HiddenFindings counts the findings of the CVE the user hid.
	HiddenFindings int `json:"hiddenFindings"`
}

func (s *Server) cve(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	snap, uv, ok := s.visible(w, r)
	if !ok {
		return
	}
	// Found even when every finding of it is hidden.
	var best *reports.Vulnerability
	for _, v := range uv.base.Vulns {
		// The most complete record (longest description) represents the CVE.
		if v.V.ID == id && (best == nil || len(v.V.Description)+len(v.V.Links) > len(best.Description)+len(best.Links)) {
			best = v.V
		}
	}
	if best == nil {
		writeError(w, http.StatusNotFound, "vulnerability not found")
		return
	}
	var rows []*index.VulnRow
	for _, v := range snap.Vulns {
		if v.V.ID == id {
			rows = append(rows, v)
		}
	}
	f := index.GroupByFinding(rows)
	slices.SortStableFunc(f, func(a, b *index.Finding) int {
		return cmp.Or(cmp.Compare(a.Image, b.Image), cmp.Compare(a.Vuln.Resource, b.Vuln.Resource))
	})
	if f == nil {
		f = []*index.Finding{}
	}
	slices.SortStableFunc(f, index.FlaggedFirst)
	writeJSON(w, CVEDetail{ID: id, Vuln: best, Affected: f, HiddenFindings: uv.hiddenIn(index.Target{Kind: index.TargetCVE, ID: id})})
}

// vulnerabilitiesCSV exports every matching finding (one row per image and
// vulnerability) for spreadsheets.
func (s *Server) vulnerabilitiesCSV(w http.ResponseWriter, r *http.Request) {
	p, err := parseList(r, index.VulnSchema)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	snap, _, ok := s.visible(w, r)
	if !ok {
		return
	}
	matched, _, _ := snap.MatchVulns(p.q, p.stale)
	f := index.GroupByFinding(matched)
	slices.SortStableFunc(f, index.FindingSorts["severity"])
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="vulnerabilities.csv"`)
	cw := csv.NewWriter(w)
	rows := [][]string{{"severity", "id", "score", "package", "installed", "fixed", "image", "workloads", "title", "published", "link"}}
	for _, x := range f {
		v := x.Vuln
		score := ""
		if v.Score != nil {
			score = strconv.FormatFloat(*v.Score, 'f', 1, 64)
		}
		wl := make([]string, len(x.Workloads))
		for i, w := range x.Workloads {
			wl[i] = w.String()
		}
		rows = append(rows, []string{v.Severity, v.ID, score, v.Resource, v.InstalledVersion, v.FixedVersion, x.Image,
			strings.Join(wl, " "), v.Title, v.PublishedDate, v.PrimaryLink})
	}
	// An error here means the client went away; nothing to report to.
	_ = cw.WriteAll(rows)
}
