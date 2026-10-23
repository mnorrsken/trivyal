package api

import (
	"encoding/json"
	"log/slog"
	"mime"
	"net/http"
	"strconv"
	"time"

	"github.com/mnorrsken/trivyal/internal/index"
	"github.com/mnorrsken/trivyal/internal/store"
)

func (s *Server) registerHidden(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/hidden", s.hiddenList)
	mux.HandleFunc("POST /api/v1/hidden", s.hide)
	mux.HandleFunc("DELETE /api/v1/hidden/{id}", s.unhide)
}

// userID is who marks belong to. Everyone is the anonymous user until
// marks are tied to logins.
func (s *Server) userID(_ *http.Request) int64 { return s.store.Anonymous() }

// userView is one user's view of a snapshot, cached until the snapshot or
// the marks change.
type userView struct {
	base  *index.Snapshot
	view  *index.Snapshot
	ver   uint64
	marks []store.Mark
	byKey map[string]*store.Mark // kind|key
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
			slog.Warn("skipping hidden item", "id", m.ID, "err", err)
			continue
		}
		im := index.Mark{Target: t, Findings: make(map[string]bool, len(m.Findings))}
		for _, f := range m.Findings {
			im.Findings[f] = true
		}
		ms = append(ms, im)
	}
	uv.view = base.Hide(ms)
	s.mu.Lock()
	s.views[uid] = uv
	s.mu.Unlock()
	return uv, nil
}

// visible returns the snapshot without what the user hid, or with
// everything for ?hidden=1. On error it has written the response.
func (s *Server) visible(w http.ResponseWriter, r *http.Request) (*index.Snapshot, *userView, bool) {
	uv, err := s.userView(r)
	if err != nil {
		slog.Error("loading hidden items", "err", err)
		writeError(w, http.StatusInternalServerError, "loading hidden items failed")
		return nil, nil, false
	}
	if v := r.URL.Query().Get("hidden"); v == "1" || v == "true" {
		return uv.base, uv, true
	}
	return uv.view, uv, true
}

// MarkInfo is a hidden target as the UI shows it.
type MarkInfo struct {
	ID      int64        `json:"id"`
	Target  index.Target `json:"target"`
	Note    string       `json:"note"`
	Created time.Time    `json:"created"`
	Updated time.Time    `json:"updated"`
	// Findings is how many findings were hidden, Hiding how many of them
	// are still there, New how many turned up since and show again.
	Findings int `json:"findings"`
	Hiding   int `json:"hiding"`
	New      int `json:"new"`
}

func (uv *userView) info(m *store.Mark) *MarkInfo {
	t, err := index.ParseTarget(m.Kind, m.Key)
	if err != nil {
		t = index.Target{Kind: m.Kind}
	}
	mi := &MarkInfo{ID: m.ID, Target: t, Note: m.Note, Created: m.Created, Updated: m.Updated, Findings: len(m.Findings)}
	had := make(map[string]bool, len(m.Findings))
	for _, f := range m.Findings {
		had[f] = true
	}
	now, _ := uv.base.Findings(t)
	for _, f := range now {
		if had[f] {
			mi.Hiding++
		} else {
			mi.New++
		}
	}
	return mi
}

// mark returns the user's mark on t, nil when t is not hidden.
func (uv *userView) mark(t index.Target) *MarkInfo {
	key, err := t.Key()
	if err != nil {
		return nil
	}
	if m := uv.byKey[t.Kind+"|"+key]; m != nil {
		return uv.info(m)
	}
	return nil
}

func (s *Server) hiddenList(w http.ResponseWriter, r *http.Request) {
	_, uv, ok := s.visible(w, r)
	if !ok {
		return
	}
	out := make([]*MarkInfo, len(uv.marks))
	for i := range uv.marks {
		out[i] = uv.info(&uv.marks[i])
	}
	writeJSON(w, out)
}

// hideRequest hides Target. A nil Note keeps the note of an earlier mark on
// the same target. Hiding a target again also hides what is new in it.
type hideRequest struct {
	Target index.Target `json:"target"`
	Note   *string      `json:"note"`
}

func (s *Server) hide(w http.ResponseWriter, r *http.Request) {
	// A JSON body cannot come from a plain cross-site form.
	if ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); ct != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "send application/json")
		return
	}
	var req hideRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "bad request body: "+err.Error())
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
	if len(findings) == 0 {
		writeError(w, http.StatusNotFound, "nothing found to hide")
		return
	}
	m := &store.Mark{UserID: s.userID(r), Kind: req.Target.Kind, Key: key, Findings: findings}
	if req.Note != nil {
		m.Note = *req.Note
	} else if old := uv.byKey[m.Kind+"|"+key]; old != nil {
		m.Note = old.Note
	}
	if err := s.store.PutMark(r.Context(), m); err != nil {
		slog.Error("hiding", "err", err)
		writeError(w, http.StatusInternalServerError, "saving failed")
		return
	}
	s.hub.Notify()
	writeJSON(w, uv.info(m))
}

func (s *Server) unhide(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad id")
		return
	}
	ok, err := s.store.DeleteMark(r.Context(), s.userID(r), id)
	if err != nil {
		slog.Error("unhiding", "err", err)
		writeError(w, http.StatusInternalServerError, "deleting failed")
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "not hidden")
		return
	}
	s.hub.Notify()
	w.WriteHeader(http.StatusNoContent)
}
