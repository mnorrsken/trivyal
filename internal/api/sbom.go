package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/mnorrsken/trivyal/internal/index"
)

func (s *Server) sbom(w http.ResponseWriter, r *http.Request) {
	p, err := parseList(r, index.ComponentSchema)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	snap := s.snapshot()
	rows, all, m := snap.MatchComponents(p.q, p.stale, r.URL.Query().Get("key"))
	res := List{Page: p.page, Size: p.size, Group: p.group, Rows: len(rows), Facets: m.Facets(all, index.ComponentFacets, 50)}
	switch p.group {
	case "image":
		g := index.GroupBySBOM(rows)
		res.Total = len(g)
		res.Items, res.Sort = page(g, p.sort, "image", index.SBOMSorts, p)
	default:
		res.Group = "component"
		g := index.GroupByComponent(rows)
		res.Total = len(g)
		res.Items, res.Sort = page(g, p.sort, "name", index.ComponentSorts, p)
	}
	writeJSON(w, res)
}

// sbomDownload fetches the full CycloneDX document from the API server;
// the cache keeps only the parsed components.
func (s *Server) sbomDownload(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("key")
	info := s.snapshot().SBOMs[key]
	if info == nil {
		writeError(w, http.StatusNotFound, "sbom not found")
		return
	}
	obj, err := s.backend.Get(r.Context(), info.Report.Type, info.Report.Namespace, info.Report.Name)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	rep, _ := obj["report"].(map[string]any)
	bom, ok := rep["components"]
	if !ok {
		writeError(w, http.StatusNotFound, "report has no components")
		return
	}
	name := strings.NewReplacer("/", "_", ":", "_", "@", "_").Replace(info.Ref)
	w.Header().Set("Content-Type", "application/vnd.cyclonedx+json")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`.cdx.json"`)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(bom)
}
