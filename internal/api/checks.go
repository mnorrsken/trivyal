package api

import (
	"cmp"
	"net/http"
	"slices"
	"strings"

	"github.com/mnorrsken/trivyal/internal/index"
	"github.com/mnorrsken/trivyal/internal/reports"
)

func checkType(w http.ResponseWriter, r *http.Request) (string, bool) {
	t := r.PathValue("type")
	switch t {
	case index.CheckConfig, index.CheckRBAC, index.CheckInfra:
		return t, true
	}
	writeError(w, http.StatusNotFound, "unknown check type "+t)
	return "", false
}

func (s *Server) checks(w http.ResponseWriter, r *http.Request) {
	typ, ok := checkType(w, r)
	if !ok {
		return
	}
	p, err := parseList(r, index.CheckSchema)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	snap := s.snapshot()
	rows, all, m := snap.MatchChecks(typ, p.q, p.stale)
	res := List{Page: p.page, Size: p.size, Group: p.group, Rows: len(rows), Facets: m.Facets(all, index.CheckFacets, 50)}
	switch p.group {
	case "check":
		g := index.GroupByCheck(rows)
		res.Total = len(g)
		res.Items, res.Sort = page(g, p.sort, "severity", index.CheckSorts, p)
	case "finding":
		g := index.Findings(rows)
		res.Total = len(g)
		res.Items, res.Sort = page(g, p.sort, "severity", index.CheckFindingSorts, p)
	default:
		res.Group = "resource"
		g := index.GroupByResource(rows)
		res.Total = len(g)
		res.Items, res.Sort = page(g, p.sort, "severity", index.ResourceSorts, p)
	}
	writeJSON(w, res)
}

// CheckDetail is one check and every resource it ran on.
type CheckDetail struct {
	Check     *reports.Check        `json:"check"`
	Resources []*index.CheckFinding `json:"resources"`
}

func (s *Server) check(w http.ResponseWriter, r *http.Request) {
	typ, ok := checkType(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	snap := s.snapshot()
	var d CheckDetail
	for _, row := range snap.Checks {
		if row.Type != typ || !strings.EqualFold(row.C.ID, id) || row.Resource.Stale || row.Dup {
			continue
		}
		if d.Check == nil {
			d.Check = row.C
		}
		d.Resources = append(d.Resources, &index.CheckFinding{Resource: row.Resource, Report: row.Report, Check: row.C})
	}
	if d.Check == nil {
		writeError(w, http.StatusNotFound, "check not found")
		return
	}
	slices.SortStableFunc(d.Resources, func(a, b *index.CheckFinding) int {
		return cmp.Or(cmp.Compare(boolInt(a.Check.Success), boolInt(b.Check.Success)), cmp.Compare(a.Resource.String(), b.Resource.String()))
	})
	writeJSON(w, d)
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
