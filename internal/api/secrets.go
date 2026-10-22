package api

import (
	"net/http"

	"github.com/mnorrsken/trivyal/internal/index"
)

// SecretList adds scan coverage to the secrets list, so an empty result can
// say how many images were scanned clean.
type SecretList struct {
	List
	Scanned int `json:"scanned"`
	Clean   int `json:"clean"`
}

func (s *Server) secrets(w http.ResponseWriter, r *http.Request) {
	p, err := parseList(r, index.SecretSchema)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	snap := s.snapshot()
	rows, all, m := snap.MatchSecrets(p.q, p.stale)
	f := index.SecretFindings(index.UniqueSecrets(rows))
	res := SecretList{List: List{Page: p.page, Size: p.size, Group: "finding", Rows: len(rows), Total: len(f), Facets: m.Facets(all, index.SecretFacets, 50)}}
	res.Items, res.Sort = page(f, p.sort, "severity", index.SecretSorts, p)
	for _, sc := range snap.SecretScans {
		if sc.Workload.Stale && !p.stale {
			continue
		}
		res.Scanned++
		if sc.Summary.Total() == 0 {
			res.Clean++
		}
	}
	writeJSON(w, res)
}
