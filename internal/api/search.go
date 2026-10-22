package api

import (
	"net/http"
	"strings"

	"github.com/mnorrsken/trivyal/internal/index"
	"github.com/mnorrsken/trivyal/internal/kube"
)

const searchLimit = 8

func (s *Server) search(w http.ResponseWriter, r *http.Request) {
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	if len(q) < 2 {
		writeJSON(w, []index.SearchHit{})
		return
	}
	hits := s.snapshot().Search(q, searchLimit)
	// Nodes and pods are not in the reports; search them in the cache.
	n := 0
	for _, node := range s.cluster.Nodes() {
		if n < searchLimit && strings.Contains(strings.ToLower(node.Name), q) {
			hits = append(hits, index.SearchHit{Kind: "node", Label: node.Name, Sub: node.Kubelet, Key: node.Name})
			n++
		}
	}
	pods := s.cluster.Pods(func(p kube.PodInfo) bool { return strings.Contains(strings.ToLower(p.Name), q) })
	for _, p := range pods[:min(searchLimit, len(pods))] {
		hits = append(hits, index.SearchHit{Kind: "pod", Label: p.Name, Sub: p.Namespace + " · " + p.Phase, Key: p.Namespace + "/" + p.Name})
	}
	writeJSON(w, hits)
}
