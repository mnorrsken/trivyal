package api

import (
	"cmp"
	"net/http"
	"slices"
	"strings"

	"github.com/mnorrsken/trivyal/internal/index"
	"github.com/mnorrsken/trivyal/internal/reports"
)

func (s *Server) complianceList(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, s.snapshot().Summary().Compliance)
}

func (s *Server) findCompliance(w http.ResponseWriter, r *http.Request) (*index.Snapshot, *reports.ComplianceReport) {
	snap := s.snapshot()
	name := r.PathValue("name")
	for _, c := range snap.Compliance {
		if c.Name == name {
			return snap, c
		}
	}
	writeError(w, http.StatusNotFound, "compliance report not found")
	return nil, nil
}

func (s *Server) compliance(w http.ResponseWriter, r *http.Request) {
	_, c := s.findCompliance(w, r)
	if c == nil {
		return
	}
	writeJSON(w, c)
}

// ControlDetail is one control with the failing resources found by joining
// its check IDs with the config audit, RBAC and infra reports.
type ControlDetail struct {
	Report  string                `json:"report"`
	Title   string                `json:"title"`
	Control reports.Control       `json:"control"`
	Failing []*ControlFinding     `json:"failing"`
	Checks  map[string]*CheckInfo `json:"checks"`
}

// ControlFinding is a failing check on a resource.
type ControlFinding struct {
	Type string `json:"type"`
	*index.CheckFinding
}

// CheckInfo describes a check referenced by a control.
type CheckInfo struct {
	Title    string `json:"title"`
	Severity string `json:"severity"`
	Type     string `json:"type"`
}

func (s *Server) complianceControl(w http.ResponseWriter, r *http.Request) {
	_, c := s.findCompliance(w, r)
	if c == nil {
		return
	}
	snap, _, ok := s.visible(w, r)
	if !ok {
		return
	}
	id := r.PathValue("control")
	i := slices.IndexFunc(c.Controls, func(ct reports.Control) bool { return ct.ID == id })
	if i < 0 {
		writeError(w, http.StatusNotFound, "control not found")
		return
	}
	ctl := c.Controls[i]
	d := ControlDetail{Report: c.Name, Title: c.Title, Control: ctl, Failing: []*ControlFinding{}, Checks: map[string]*CheckInfo{}}
	want := map[string]bool{}
	for _, ch := range ctl.Checks {
		want[strings.ToUpper(ch)] = true
	}
	for _, row := range snap.Checks {
		id := strings.ToUpper(row.C.ID)
		if !want[id] || row.Resource.Stale || row.Dup {
			continue
		}
		if d.Checks[id] == nil {
			d.Checks[id] = &CheckInfo{Title: row.C.Title, Severity: row.C.Severity, Type: row.Type}
		}
		if !row.C.Success {
			d.Failing = append(d.Failing, &ControlFinding{Type: row.Type, CheckFinding: row.AsFinding()})
		}
	}
	slices.SortFunc(d.Failing, byKey)
	slices.SortStableFunc(d.Failing, func(a, b *ControlFinding) int {
		return cmp.Or(cmp.Compare(a.Resource.String(), b.Resource.String()), cmp.Compare(a.Check.ID, b.Check.ID))
	})
	writeJSON(w, d)
}
