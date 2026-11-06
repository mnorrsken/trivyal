package api

import (
	"net/http"

	"github.com/mnorrsken/trivyal/internal/index"
	"github.com/mnorrsken/trivyal/internal/reports"
)

// ScanList adds the number of running scan jobs to the scans list.
type ScanList struct {
	List
	Running int `json:"running"`
}

// scans lists running and failed scan jobs and the last scan of every
// report. Marks do not apply: a scan is not a finding.
func (s *Server) scans(w http.ResponseWriter, r *http.Request) {
	p, err := parseList(r, index.ScanSchema)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	snap := s.snapshot()
	rows, all, m := snap.MatchScans(p.q, p.stale)
	res := ScanList{List: List{Page: p.page, Size: p.size, Group: "scan", Rows: len(rows), Total: len(rows), Facets: m.Facets(all, index.ScanFacets, 50)}}
	for _, sc := range all {
		if sc.(*index.Scan).State == reports.JobRunning {
			res.Running++
		}
	}
	res.Items, res.Sort = page(rows, p.sort, "recent", index.ScanSorts, p)
	writeJSON(w, res)
}
