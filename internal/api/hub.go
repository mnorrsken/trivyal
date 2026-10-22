package api

import (
	"fmt"
	"net/http"
	"sync"
	"time"
)

// Hub pushes "changed" events to browsers over Server-Sent Events. Changes
// are debounced so a burst of report updates causes one refetch.
type Hub struct {
	gen      func() uint64
	debounce time.Duration

	mu      sync.Mutex
	clients map[chan uint64]struct{}
	timer   *time.Timer
}

// NewHub returns a hub; gen reports the index generation sent to clients.
func NewHub(gen func() uint64, debounce time.Duration) *Hub {
	return &Hub{gen: gen, debounce: debounce, clients: map[chan uint64]struct{}{}}
}

// Notify schedules a change event.
func (h *Hub) Notify() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.timer != nil {
		return
	}
	h.timer = time.AfterFunc(h.debounce, h.broadcast)
}

func (h *Hub) broadcast() {
	g := h.gen()
	h.mu.Lock()
	defer h.mu.Unlock()
	h.timer = nil
	for c := range h.clients {
		select {
		case c <- g:
		default: // client is slow; it will get the next one
		}
	}
}

// Clients returns the number of connected browsers.
func (h *Hub) Clients() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.clients)
}

func (h *Hub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rc := http.NewResponseController(w)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")

	c := make(chan uint64, 1)
	h.mu.Lock()
	h.clients[c] = struct{}{}
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		delete(h.clients, c)
		h.mu.Unlock()
	}()

	_, _ = fmt.Fprintf(w, "retry: 5000\nevent: hello\ndata: %d\n\n", h.gen())
	if err := rc.Flush(); err != nil {
		return
	}
	ping := time.NewTicker(30 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case g := <-c:
			_, _ = fmt.Fprintf(w, "event: changed\ndata: %d\n\n", g)
		case <-ping.C:
			_, _ = fmt.Fprint(w, ": ping\n\n")
		}
		if err := rc.Flush(); err != nil {
			return
		}
	}
}
