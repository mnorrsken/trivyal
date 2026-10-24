package api

import (
	"encoding/json"
	"log/slog"
	"mime"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/mnorrsken/trivyal/internal/index"
	"github.com/mnorrsken/trivyal/internal/store"
)

func (s *Server) registerMarks(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/marks", s.markList)
	mux.HandleFunc("POST /api/v1/marks", s.markPut)
	mux.HandleFunc("DELETE /api/v1/marks/{id}", s.markDelete)
}

// userID is who marks belong to. Everyone is the anonymous user until
// marks are tied to logins.
func (s *Server) userID(_ *http.Request) int64 { return s.store.Anonymous() }

// userView is one user's view of a snapshot (hidden findings left out,
// flagged ones marked), cached until the snapshot or the marks change.
type userView struct {
	base   *index.Snapshot
	view   *index.Snapshot
	ver    uint64
	marks  []store.Mark
	byKey  map[string]*store.Mark // kind|key
	hidden bool                   // some marks hide
}

func (s *Server) userView(r *http.Request) (*userView, error) {
	uid := s.userID(r)
	base := s.snapshot()
	ver := s.store.Version()
	s.mu.Lock()
	uv := s.views[uid]
	s.mu.Unlock()
	if uv != nil && uv.base == base && uv.ver == ver {
		return uv, nil
	}
	list, err := s.store.Marks(r.Context(), uid)
	if err != nil {
		return nil, err
	}
	uv = &userView{base: base, ver: ver, marks: list, byKey: map[string]*store.Mark{}}
	var ms []index.Mark
	for i := range list {
		m := &list[i]
		uv.byKey[m.Kind+"|"+m.Key] = m
		t, err := index.ParseTarget(m.Kind, m.Key)
		if err != nil {
			slog.Warn("skipping mark", "id", m.ID, "err", err)
			continue
		}
		im := index.Mark{Target: t, Flag: m.State == store.Flagged, Findings: make(map[string]bool, len(m.Findings))}
		for _, f := range m.Findings {
			im.Findings[f] = true
		}
		uv.hidden = uv.hidden || !im.Flag
		ms = append(ms, im)
	}
	uv.view = base.Apply(ms)
	s.mu.Lock()
	s.views[uid] = uv
	s.mu.Unlock()
	return uv, nil
}

// visible returns the snapshot as the user sees it. On error it has written
// the response.
func (s *Server) visible(w http.ResponseWriter, r *http.Request) (*index.Snapshot, *userView, bool) {
	uv, err := s.userView(r)
	if err != nil {
		slog.Error("loading marks", "err", err)
		writeError(w, http.StatusInternalServerError, "loading marks failed")
		return nil, nil, false
	}
	return uv.view, uv, true
}

// hiddenIn counts the findings of t the user does not see.
func (uv *userView) hiddenIn(t index.Target) int {
	if !uv.hidden {
		return 0
	}
	all, _ := uv.base.Findings(t)
	seen, _ := uv.view.Findings(t)
	return len(all) - len(seen)
}

// hiddenRows counts what hides leave out of a list: items of rows (all
// matching rows) minus items of seen (the ones the user sees).
func hiddenRows[R any, T any](uv *userView, all, seen []R, items func([]R) []T) int {
	if !uv.hidden {
		return 0
	}
	return len(items(all)) - len(items(seen))
}

// flagged reports whether the user flagged t itself.
func (uv *userView) flagged(t index.Target) bool {
	key, err := t.Key()
	if err != nil {
		return false
	}
	m := uv.byKey[t.Kind+"|"+key]
	return m != nil && m.State == store.Flagged
}

// MarkInfo is a flagged or hidden target as the UI shows it.
type MarkInfo struct {
	ID      int64        `json:"id"`
	Target  index.Target `json:"target"`
	State   string       `json:"state"`
	Note    string       `json:"note"`
	Created time.Time    `json:"created"`
	Updated time.Time    `json:"updated"`
	Counts  *MarkCounts  `json:"counts,omitempty"`
}

// MarkCounts compares the target's findings now with when it was marked:
// Findings then, Now in the target, New of those that were not there then
// (a hide does not cover them).
type MarkCounts struct {
	Findings int `json:"findings"`
	Now      int `json:"now"`
	New      int `json:"new"`
}

func (uv *userView) info(m *store.Mark, counts bool) *MarkInfo {
	t, err := index.ParseTarget(m.Kind, m.Key)
	if err != nil {
		t = index.Target{Kind: m.Kind}
	}
	mi := &MarkInfo{ID: m.ID, Target: t, State: m.State, Note: m.Note, Created: m.Created, Updated: m.Updated}
	if !counts {
		return mi
	}
	c := &MarkCounts{Findings: len(m.Findings)}
	now, _ := uv.base.Findings(t)
	c.Now = len(now)
	for _, f := range now {
		if _, found := slices.BinarySearch(m.Findings, f); !found {
			c.New++
		}
	}
	mi.Counts = c
	return mi
}

// markList lists the user's marks; ?counts=1 adds MarkCounts, which costs a
// pass over the findings per mark.
func (s *Server) markList(w http.ResponseWriter, r *http.Request) {
	_, uv, ok := s.visible(w, r)
	if !ok {
		return
	}
	counts := r.URL.Query().Get("counts") == "1"
	out := make([]*MarkInfo, len(uv.marks))
	for i := range uv.marks {
		out[i] = uv.info(&uv.marks[i], counts)
	}
	writeJSON(w, out)
}

// markRequest sets the State of Target. A nil Note keeps the note of an
// earlier mark on the same target. Hiding a target again also hides what is
// new in it.
type markRequest struct {
	Target index.Target `json:"target"`
	State  string       `json:"state"`
	Note   *string      `json:"note"`
}

func (s *Server) markPut(w http.ResponseWriter, r *http.Request) {
	// A JSON body cannot come from a plain cross-site form.
	if ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); ct != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "send application/json")
		return
	}
	var req markRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "bad request body: "+err.Error())
		return
	}
	if req.State != store.Hidden && req.State != store.Flagged {
		writeError(w, http.StatusBadRequest, "state must be hidden or flagged")
		return
	}
	key, err := req.Target.Key()
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	_, uv, ok := s.visible(w, r)
	if !ok {
		return
	}
	findings, _ := uv.base.Findings(req.Target)
	// A flag also covers findings to come, so it can go on a clean target.
	if len(findings) == 0 && req.State == store.Hidden {
		writeError(w, http.StatusNotFound, "nothing found to hide")
		return
	}
	m := &store.Mark{UserID: s.userID(r), Kind: req.Target.Kind, Key: key, State: req.State, Findings: findings}
	if req.Note != nil {
		m.Note = *req.Note
	} else if old := uv.byKey[m.Kind+"|"+key]; old != nil {
		m.Note = old.Note
	}
	if err := s.store.PutMark(r.Context(), m); err != nil {
		slog.Error("saving mark", "err", err)
		writeError(w, http.StatusInternalServerError, "saving failed")
		return
	}
	s.hub.Notify()
	writeJSON(w, uv.info(m, true))
}

func (s *Server) markDelete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad id")
		return
	}
	ok, err := s.store.DeleteMark(r.Context(), s.userID(r), id)
	if err != nil {
		slog.Error("deleting mark", "err", err)
		writeError(w, http.StatusInternalServerError, "deleting failed")
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "not marked")
		return
	}
	s.hub.Notify()
	w.WriteHeader(http.StatusNoContent)
}
