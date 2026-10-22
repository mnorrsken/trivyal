package api

import (
	"net/http"

	"github.com/mnorrsken/trivyal/internal/index"
)

// report returns one parsed report.
func (s *Server) report(w http.ResponseWriter, r *http.Request) {
	ref := index.ReportRef{Type: r.PathValue("type"), Namespace: r.PathValue("ns"), Name: r.PathValue("name")}
	rep, ok := s.snapshot().ReportsByRef[ref]
	if !ok || rep == nil {
		writeError(w, http.StatusNotFound, "report not found")
		return
	}
	writeJSON(w, map[string]any{"ref": ref, "report": rep})
}
