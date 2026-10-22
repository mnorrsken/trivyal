// Package api serves the JSON API used by the web UI.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/mnorrsken/trivyal/internal/index"
	"github.com/mnorrsken/trivyal/internal/query"
	"github.com/mnorrsken/trivyal/internal/version"
)

// Backend is what the API needs from the kube cache.
type Backend interface {
	Cluster
	Synced() bool
	Get(ctx context.Context, resource, namespace, name string) (map[string]any, error)
}

// Server holds the API handlers.
type Server struct {
	idx     *index.Index
	backend Backend
	cluster Cluster
	hub     *Hub
	metrics *Metrics
}

// New returns an API server.
func New(idx *index.Index, backend Backend, hub *Hub, metrics *Metrics) *Server {
	return &Server{idx: idx, backend: backend, cluster: backend, hub: hub, metrics: metrics}
}

// Register adds the API routes to mux.
func (s *Server) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok\n")) })
	mux.HandleFunc("GET /readyz", s.readyz)
	mux.HandleFunc("GET /api/v1/version", s.version)
	mux.HandleFunc("GET /api/v1/summary", s.summary)
	mux.HandleFunc("GET /api/v1/schema", s.schema)
	mux.HandleFunc("GET /api/v1/events", s.hub.ServeHTTP)
	mux.HandleFunc("GET /api/v1/vulnerabilities", s.vulnerabilities)
	mux.HandleFunc("GET /api/v1/vulnerabilities.csv", s.vulnerabilitiesCSV)
	mux.HandleFunc("GET /api/v1/image", s.image)
	mux.HandleFunc("GET /api/v1/cve/{id}", s.cve)
	mux.HandleFunc("GET /api/v1/checks/{type}", s.checks)
	mux.HandleFunc("GET /api/v1/checks/{type}/{id}", s.check)
	mux.HandleFunc("GET /api/v1/secrets", s.secrets)
	mux.HandleFunc("GET /api/v1/sbom", s.sbom)
	mux.HandleFunc("GET /api/v1/sbom/download", s.sbomDownload)
	mux.HandleFunc("GET /api/v1/compliance", s.complianceList)
	mux.HandleFunc("GET /api/v1/compliance/{name}", s.compliance)
	mux.HandleFunc("GET /api/v1/compliance/{name}/{control}", s.complianceControl)
	mux.HandleFunc("GET /api/v1/report/{type}/{name}", s.report)
	mux.HandleFunc("GET /api/v1/report/{type}/{ns}/{name}", s.report)
	mux.HandleFunc("GET /api/v1/search", s.search)
	s.registerResources(mux)
	mux.HandleFunc("/api/", func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusNotFound, "not found")
	})
}

func (s *Server) readyz(w http.ResponseWriter, _ *http.Request) {
	if !s.backend.Synced() {
		http.Error(w, "caches not synced", http.StatusServiceUnavailable)
		return
	}
	_, _ = w.Write([]byte("ok\n"))
}

func (s *Server) version(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]string{"version": version.Version, "commit": version.Commit})
}

func (s *Server) summary(w http.ResponseWriter, _ *http.Request) {
	sum := s.snapshot().Summary()
	writeJSON(w, struct {
		*index.Summary
		Synced bool `json:"synced"`
	}{sum, s.backend.Synced()})
}

func (s *Server) snapshot() *index.Snapshot {
	snap := s.idx.Snapshot()
	s.metrics.observeSnapshot(snap)
	return snap
}

// schemaField describes one filter for the UI's help and autocomplete.
type schemaField struct {
	Name    string   `json:"name"`
	Aliases []string `json:"aliases,omitempty"`
	Help    string   `json:"help"`
}

func toFields(s query.Schema) []schemaField {
	out := make([]schemaField, len(s))
	for i, f := range s {
		out[i] = schemaField{Name: f.Name, Aliases: f.Aliases, Help: f.Help}
	}
	return out
}

func (s *Server) schema(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string][]schemaField{
		"vulnerabilities": toFields(index.VulnSchema),
		"checks":          toFields(index.CheckSchema),
		"secrets":         toFields(index.SecretSchema),
		"sbom":            toFields(index.ComponentSchema),
		"workloads":       toFields(WorkloadSchema),
	})
}

// listParams are the common query parameters of list endpoints.
type listParams struct {
	q     query.Query
	group string
	sort  string
	page  int
	size  int
	stale bool
}

func parseList(r *http.Request, schema query.Schema) (listParams, error) {
	v := r.URL.Query()
	q, err := query.Parse(v.Get("q"), schema)
	if err != nil {
		return listParams{}, err
	}
	p := listParams{q: q, group: v.Get("group"), sort: v.Get("sort"), page: 1, size: 50}
	if n, err := strconv.Atoi(v.Get("page")); err == nil && n > 0 {
		p.page = n
	}
	if n, err := strconv.Atoi(v.Get("size")); err == nil && n > 0 {
		p.size = min(n, 1000)
	}
	p.stale = v.Get("stale") == "1" || v.Get("stale") == "true"
	return p, nil
}

// List is the response of every list endpoint.
type List struct {
	Total  int                           `json:"total"`
	Page   int                           `json:"page"`
	Size   int                           `json:"size"`
	Group  string                        `json:"group"`
	Sort   string                        `json:"sort"`
	Items  any                           `json:"items"`
	Facets map[string][]query.FacetValue `json:"facets,omitempty"`
	// Rows is the number of matching rows before grouping.
	Rows int `json:"rows"`
}

// page sorts items with sortKey ("-" prefix reverses) and returns one page.
func page[T any](items []T, sortKey, def string, sorts map[string]func(a, b T) int, p listParams) ([]T, string) {
	fn, ok := sorts[strings.TrimPrefix(sortKey, "-")]
	if !ok {
		sortKey, fn = def, sorts[def]
	}
	if strings.HasPrefix(sortKey, "-") {
		slices.SortStableFunc(items, func(a, b T) int { return -fn(a, b) })
	} else {
		slices.SortStableFunc(items, fn)
	}
	start := (p.page - 1) * p.size
	if start >= len(items) {
		return []T{}, sortKey
	}
	return items[start:min(start+p.size, len(items))], sortKey
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if err := json.NewEncoder(w).Encode(v); err != nil && !errors.Is(err, context.Canceled) {
		slog.Debug("writing response", "err", err)
	}
}

func writeError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
