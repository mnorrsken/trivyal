// Package index turns the cached reports into rows, groups and summaries
// for the API. A snapshot is rebuilt lazily after the source changed.
package index

import (
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mnorrsken/trivyal/internal/reports"
)

// Source is where reports come from (the kube cache, or fixtures in tests).
type Source interface {
	Reports(resource string) []any
	Owner(kind, namespace, name string) (reports.Owner, bool)
	Installed() bool
}

// Index caches a snapshot of all reports and rebuilds it when invalidated.
type Index struct {
	src Source
	gen atomic.Uint64

	mu      sync.Mutex
	snap    *Snapshot
	snapGen uint64
}

// New returns an index over src.
func New(src Source) *Index {
	x := &Index{src: src}
	x.gen.Store(1)
	return x
}

// Invalidate marks the snapshot stale. Cheap; called on every cache event.
func (x *Index) Invalidate() { x.gen.Add(1) }

// Generation changes whenever the data may have changed.
func (x *Index) Generation() uint64 { return x.gen.Load() }

// Snapshot returns the current snapshot, rebuilding it if needed.
func (x *Index) Snapshot() *Snapshot {
	x.mu.Lock()
	defer x.mu.Unlock()
	g := x.gen.Load()
	if x.snap == nil || x.snapGen != g {
		x.snap = build(x.src)
		x.snapGen = g
	}
	return x.snap
}

// Workload is the user-facing owner of a report: a Deployment instead of
// its ReplicaSet, a CronJob instead of its Job.
type Workload struct {
	reports.Resource
	// Stale is true for ReplicaSets scaled to zero (old Deployment revisions).
	Stale bool `json:"stale,omitempty"`
}

// ReportRef identifies one report object.
type ReportRef struct {
	Type      string `json:"type"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
}

// Snapshot is an immutable view over all reports at one point in time.
type Snapshot struct {
	Built     time.Time
	Installed bool

	Vulns       []*VulnRow
	Images      map[string]*Image // by image key (digest, else ref)
	Checks      []*CheckRow
	Secrets     []*SecretRow
	SecretScans []*SecretScan
	Components  []*ComponentRow
	SBOMs       map[string]*SBOMInfo // by image key
	Compliance  []*reports.ComplianceReport

	// Raw parsed reports by ReportRef, for detail pages.
	ReportsByRef map[ReportRef]any
	Counts       map[string]int
	Scanners     map[string]int
	Oldest       time.Time
	Newest       time.Time
}

type resolver struct {
	src   Source
	cache map[string]Workload
}

func (r *resolver) workload(res reports.Resource) Workload {
	key := res.String()
	if w, ok := r.cache[key]; ok {
		return w
	}
	w := Workload{Resource: res}
	// Follow controllers: ReplicaSet -> Deployment, Job -> CronJob, and a
	// Pod reported on its own -> the custom resource that owns it (an
	// operator's database cluster, say). Static pods stay pods.
	for range 3 {
		if w.Kind != "ReplicaSet" && w.Kind != "Job" && w.Kind != "Pod" {
			break
		}
		o, ok := r.src.Owner(w.Kind, w.Namespace, w.Name)
		if !ok || o.Kind == "" || o.Kind == "Node" {
			break
		}
		if w.Kind == "ReplicaSet" && o.Replicas != nil && *o.Replicas == 0 {
			w.Stale = true
		}
		w.Kind, w.Name = o.Kind, o.Name
	}
	r.cache[key] = w
	return w
}

func build(src Source) *Snapshot {
	s := &Snapshot{
		Built:        time.Now(),
		Installed:    src.Installed(),
		Images:       map[string]*Image{},
		SBOMs:        map[string]*SBOMInfo{},
		ReportsByRef: map[ReportRef]any{},
		Counts:       map[string]int{},
		Scanners:     map[string]int{},
	}
	res := &resolver{src: src, cache: map[string]Workload{}}
	for _, kind := range reports.Resources {
		items := src.Reports(kind)
		s.Counts[kind] = len(items)
		for _, it := range items {
			s.add(kind, it, res)
		}
	}
	s.finish()
	return s
}

func (s *Snapshot) track(kind string, c *reports.Common) {
	if c.Scanner.Version != "" {
		s.Scanners[c.Scanner.Name+" "+c.Scanner.Version]++
	}
	if !c.Updated.IsZero() {
		if s.Oldest.IsZero() || c.Updated.Before(s.Oldest) {
			s.Oldest = c.Updated
		}
		if c.Updated.After(s.Newest) {
			s.Newest = c.Updated
		}
	}
}

func (s *Snapshot) add(kind string, it any, res *resolver) {
	switch r := it.(type) {
	case *reports.VulnerabilityReport:
		s.track(kind, &r.Common)
		s.ReportsByRef[ReportRef{kind, r.Namespace, r.Name}] = r
		s.addVulns(kind, r, res.workload(r.Resource))
	case *reports.CheckReport:
		s.track(kind, &r.Common)
		s.ReportsByRef[ReportRef{kind, r.Namespace, r.Name}] = r
		s.addChecks(kind, r, res.workload(r.Resource))
	case *reports.ExposedSecretReport:
		s.track(kind, &r.Common)
		s.ReportsByRef[ReportRef{kind, r.Namespace, r.Name}] = r
		s.addSecrets(kind, r, res.workload(r.Resource))
	case *reports.SBOMReport:
		s.track(kind, &r.Common)
		s.ReportsByRef[ReportRef{kind, r.Namespace, r.Name}] = r
		s.addSBOM(kind, r, res.workload(r.Resource))
	case *reports.ComplianceReport:
		s.ReportsByRef[ReportRef{kind, "", r.Name}] = r
		s.Compliance = append(s.Compliance, r)
	}
}

func (s *Snapshot) finish() {
	s.markDuplicateChecks()
	s.finishSBOM()
}

// ImageRef formats registry, repository and tag the way users write images.
func ImageRef(reg reports.Registry, a reports.Artifact) string {
	server := reg.Server
	switch server {
	case "index.docker.io", "registry-1.docker.io":
		server = "docker.io"
	}
	ref := a.Repository
	if server != "" {
		ref = server + "/" + ref
	}
	if tag := cleanTag(a.Tag); tag != "" {
		ref += ":" + tag
	}
	return ref
}

// cleanTag works around reports whose tag holds the whole image reference
// ("repo/name:tag" instead of "tag").
func cleanTag(tag string) string {
	if i := strings.LastIndexByte(tag, ':'); i >= 0 && strings.ContainsRune(tag[:i], '/') {
		return tag[i+1:]
	}
	return tag
}

// imageKey is the identity used to dedupe images across workloads.
func imageKey(reg reports.Registry, a reports.Artifact) string {
	if a.Digest != "" {
		return a.Digest
	}
	return ImageRef(reg, a)
}

func lower(ss ...string) string {
	return strings.ToLower(strings.Join(ss, " "))
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
