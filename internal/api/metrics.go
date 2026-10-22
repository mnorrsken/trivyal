package api

import (
	"fmt"
	"net/http"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mnorrsken/trivyal/internal/index"
)

// Metrics is a small hand-rolled Prometheus exposition.
type Metrics struct {
	requests atomic.Uint64
	hub      *Hub

	mu      sync.Mutex
	builds  uint64
	lastGen time.Time
	reports map[string]int
}

// NewMetrics returns metrics; hub may be nil.
func NewMetrics(hub *Hub) *Metrics {
	return &Metrics{hub: hub, reports: map[string]int{}}
}

func (m *Metrics) observeSnapshot(s *index.Snapshot) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s.Built.Equal(m.lastGen) {
		return
	}
	m.lastGen = s.Built
	m.builds++
	m.reports = s.Counts
}

// Wrap counts requests to h.
func (m *Metrics) Wrap(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.requests.Add(1)
		h.ServeHTTP(w, r)
	})
}

func (m *Metrics) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = fmt.Fprintf(w, "# HELP trivyal_http_requests_total HTTP requests served.\n# TYPE trivyal_http_requests_total counter\ntrivyal_http_requests_total %d\n", m.requests.Load())
	clients := 0
	if m.hub != nil {
		clients = m.hub.Clients()
	}
	_, _ = fmt.Fprintf(w, "# HELP trivyal_sse_clients Connected live-update clients.\n# TYPE trivyal_sse_clients gauge\ntrivyal_sse_clients %d\n", clients)
	m.mu.Lock()
	defer m.mu.Unlock()
	_, _ = fmt.Fprintf(w, "# HELP trivyal_snapshot_builds_total Index rebuilds.\n# TYPE trivyal_snapshot_builds_total counter\ntrivyal_snapshot_builds_total %d\n", m.builds)
	_, _ = fmt.Fprint(w, "# HELP trivyal_reports Reports in the cache by resource, as of the last rebuild.\n# TYPE trivyal_reports gauge\n")
	keys := make([]string, 0, len(m.reports))
	for k := range m.reports {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		_, _ = fmt.Fprintf(w, "trivyal_reports{resource=%q} %d\n", k, m.reports[k])
	}
}
