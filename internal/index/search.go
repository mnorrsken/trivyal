package index

import (
	"cmp"
	"slices"
	"strings"
)

// SearchHit is one global search result. Kind tells the UI where to link.
type SearchHit struct {
	Kind  string `json:"kind"` // namespace, workload, image, cve, check, package, node, pod
	Label string `json:"label"`
	Sub   string `json:"sub,omitempty"`
	// Key identifies the target: image key, "type/id" for checks,
	// "namespace/kind/name" for workloads, and so on.
	Key string `json:"key"`
	// rank: 0 exact, 1 prefix, 2 substring.
	rank int
}

func rank(label, q string) int {
	l := strings.ToLower(label)
	switch {
	case l == q:
		return 0
	case strings.HasPrefix(l, q):
		return 1
	case strings.Contains(l, q):
		return 2
	}
	return -1
}

type hits struct {
	q     string
	seen  map[string]bool
	byKey map[string][]SearchHit
}

func (h *hits) add(kind, label, sub, key string, haystack ...string) {
	best := -1
	for _, s := range append([]string{label}, haystack...) {
		if r := rank(s, h.q); r >= 0 && (best < 0 || r < best) {
			best = r
		}
	}
	if best < 0 || h.seen[kind+"|"+key] {
		return
	}
	h.seen[kind+"|"+key] = true
	h.byKey[kind] = append(h.byKey[kind], SearchHit{Kind: kind, Label: label, Sub: sub, Key: key, rank: best})
}

// Search finds namespaces, workloads, images, vulnerabilities, checks and
// packages whose name contains q (lowercase). At most limit hits per kind.
func (s *Snapshot) Search(q string, limit int) []SearchHit {
	h := &hits{q: q, seen: map[string]bool{}, byKey: map[string][]SearchHit{}}
	for _, img := range s.Images {
		if allStale(img.Uses) {
			continue
		}
		for _, u := range img.Uses {
			w := u.Workload
			if w.Stale {
				continue
			}
			if w.Namespace != "" {
				h.add("namespace", w.Namespace, "", w.Namespace)
			}
			h.add("workload", w.Name, w.Namespace+" · "+w.Kind, w.Namespace+"/"+w.Kind+"/"+w.Name)
		}
		h.add("image", img.Ref, img.Digest, img.Key)
	}
	for _, r := range s.Vulns {
		h.add("cve", r.V.ID, r.V.Title, r.V.ID)
	}
	for _, r := range s.Checks {
		if r.Resource.Namespace != "" && !r.Resource.Stale {
			h.add("namespace", r.Resource.Namespace, "", r.Resource.Namespace)
		}
		h.add("check", r.C.ID, r.C.Title, r.Type+"/"+r.C.ID, r.C.Title)
	}
	for _, r := range s.Components {
		name := r.Field("name")[0]
		h.add("package", name, r.PkgType, name)
	}
	var out []SearchHit
	for _, kind := range []string{"namespace", "workload", "image", "cve", "check", "package"} {
		list := h.byKey[kind]
		slices.SortFunc(list, func(a, b SearchHit) int {
			return cmp.Or(cmp.Compare(a.rank, b.rank), cmp.Compare(len(a.Label), len(b.Label)), cmp.Compare(a.Label, b.Label))
		})
		out = append(out, list[:min(limit, len(list))]...)
	}
	if out == nil {
		out = []SearchHit{}
	}
	return out
}
