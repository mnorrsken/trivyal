package api

import (
	"cmp"
	"net/http"
	"slices"
	"strings"

	"github.com/mnorrsken/trivyal/internal/index"
	"github.com/mnorrsken/trivyal/internal/kube"
	"github.com/mnorrsken/trivyal/internal/query"
	"github.com/mnorrsken/trivyal/internal/reports"
)

// Cluster is the read access to Kubernetes objects the resource pages use.
type Cluster interface {
	Workloads() []kube.WorkloadInfo
	Workload(kind, namespace, name string) (kube.WorkloadInfo, bool)
	Pod(namespace, name string) (kube.PodInfo, bool)
	Pods(match func(kube.PodInfo) bool) []kube.PodInfo
	Nodes() []kube.NodeInfo
	Node(name string) (kube.NodeInfo, bool)
	Namespaces() []kube.NamespaceInfo
	Namespace(name string) (kube.NamespaceInfo, bool)
}

func (s *Server) registerResources(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/workloads", s.workloads)
	mux.HandleFunc("GET /api/v1/workload/{ns}/{kind}/{name}", s.workload)
	mux.HandleFunc("GET /api/v1/pod/{ns}/{name}", s.pod)
	mux.HandleFunc("GET /api/v1/namespaces", s.namespaces)
	mux.HandleFunc("GET /api/v1/namespace/{name}", s.namespace)
	mux.HandleFunc("GET /api/v1/nodes", s.nodes)
	mux.HandleFunc("GET /api/v1/node/{name}", s.node)
}

// WorkloadRow is a workload with its report totals.
type WorkloadRow struct {
	kube.WorkloadInfo
	Stats *index.WorkloadStat `json:"stats"`
	text  string
}

// WorkloadSchema lists the filters for the workload list.
var WorkloadSchema = query.Schema{
	{Name: "ns", Aliases: []string{"namespace"}, Help: "namespace"},
	{Name: "kind", Help: "Deployment, StatefulSet, DaemonSet, CronJob, Pod"},
	{Name: "name", Aliases: []string{"workload"}, Mode: query.Contains, Help: "workload name"},
	{Name: "image", Mode: query.Contains, Help: "container image"},
	{Name: "sev", Aliases: []string{"severity"}, Help: "has vulnerabilities of this severity"},
	{Name: "fixable", Help: "yes when some vulnerability has a fix"},
	{Name: "secrets", Help: "yes when exposed secrets were found"},
}

var workloadFacets = []string{"ns", "kind", "sev", "fixable", "secrets"}

func (r *WorkloadRow) Field(name string) []string {
	switch name {
	case "ns":
		return []string{r.Namespace}
	case "kind":
		return []string{r.Kind}
	case "name":
		return []string{r.Name}
	case "image":
		out := make([]string, len(r.Containers))
		for i, c := range r.Containers {
			out[i] = c.Image
		}
		return out
	case "sev":
		var out []string
		v := r.Stats.Vulns
		for sev, n := range map[string]int{reports.SeverityCritical: v.Critical, reports.SeverityHigh: v.High, reports.SeverityMedium: v.Medium, reports.SeverityLow: v.Low} {
			if n > 0 {
				out = append(out, sev)
			}
		}
		return out
	case "fixable":
		return []string{yesNo(r.Stats.Fixable > 0)}
	case "secrets":
		return []string{yesNo(r.Stats.Secrets > 0)}
	}
	return nil
}

func (r *WorkloadRow) Text() string { return r.text }

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func sevCmp(a, b reports.SeveritySummary) int {
	return cmp.Or(cmp.Compare(b.Critical, a.Critical), cmp.Compare(b.High, a.High), cmp.Compare(b.Medium, a.Medium), cmp.Compare(b.Low, a.Low))
}

var workloadSorts = map[string]func(a, b *WorkloadRow) int{
	"severity": func(a, b *WorkloadRow) int {
		return cmp.Or(sevCmp(a.Stats.Vulns, b.Stats.Vulns), cmp.Compare(a.Namespace, b.Namespace), cmp.Compare(a.Name, b.Name))
	},
	"config": func(a, b *WorkloadRow) int {
		return cmp.Or(sevCmp(a.Stats.Config, b.Stats.Config), cmp.Compare(a.Name, b.Name))
	},
	"name": func(a, b *WorkloadRow) int { return cmp.Compare(a.Name, b.Name) },
	"namespace": func(a, b *WorkloadRow) int {
		return cmp.Or(cmp.Compare(a.Namespace, b.Namespace), cmp.Compare(a.Name, b.Name))
	},
	"kind":    func(a, b *WorkloadRow) int { return cmp.Or(cmp.Compare(a.Kind, b.Kind), cmp.Compare(a.Name, b.Name)) },
	"fixable": func(a, b *WorkloadRow) int { return cmp.Compare(b.Stats.Fixable, a.Stats.Fixable) },
}

func (s *Server) workloadRows() []*WorkloadRow {
	stats := s.snapshot().WorkloadStats()
	var rows []*WorkloadRow
	for _, w := range s.cluster.Workloads() {
		st := stats[w.String()]
		if st == nil {
			st = &index.WorkloadStat{}
		}
		var b strings.Builder
		b.WriteString(strings.ToLower(w.Namespace + " " + w.Kind + " " + w.Name))
		for _, c := range w.Containers {
			b.WriteString(" " + strings.ToLower(c.Image))
		}
		rows = append(rows, &WorkloadRow{WorkloadInfo: w, Stats: st, text: b.String()})
	}
	return rows
}

func (s *Server) workloads(w http.ResponseWriter, r *http.Request) {
	p, err := parseList(r, WorkloadSchema)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	rows := s.workloadRows()
	m := query.NewMatcher(p.q, WorkloadSchema)
	all := make([]query.Row, len(rows))
	var matched []*WorkloadRow
	for i, row := range rows {
		all[i] = row
		if m.Match(row) {
			matched = append(matched, row)
		}
	}
	res := List{Page: p.page, Size: p.size, Group: "workload", Rows: len(matched), Total: len(matched), Facets: m.Facets(all, workloadFacets, 50)}
	res.Items, res.Sort = page(matched, p.sort, "severity", workloadSorts, p)
	writeJSON(w, res)
}

// WorkloadDetail is the workload page.
type WorkloadDetail struct {
	Workload *kube.WorkloadInfo     `json:"workload,omitempty"`
	Resource reports.Resource       `json:"resource"`
	Pods     []kube.PodInfo         `json:"pods"`
	Reports  *index.WorkloadReports `json:"reports"`
}

func (s *Server) workload(w http.ResponseWriter, r *http.Request) {
	ns := r.PathValue("ns")
	if ns == "_" {
		ns = ""
	}
	res := reports.Resource{Kind: r.PathValue("kind"), Namespace: ns, Name: r.PathValue("name")}
	d := WorkloadDetail{Resource: res, Pods: []kube.PodInfo{}}
	if info, ok := s.cluster.Workload(res.Kind, res.Namespace, res.Name); ok {
		d.Workload = &info
	}
	d.Reports = s.snapshot().ForWorkload(res)
	if d.Workload == nil && len(d.Reports.Reports) == 0 {
		writeError(w, http.StatusNotFound, "workload not found")
		return
	}
	d.Pods = s.cluster.Pods(func(p kube.PodInfo) bool { return p.Workload == res })
	if d.Pods == nil {
		d.Pods = []kube.PodInfo{}
	}
	writeJSON(w, d)
}

// PodDetail is the pod page. Images maps container names to image keys
// for linking.
type PodDetail struct {
	kube.PodInfo
	Images map[string]string `json:"images"`
}

func (s *Server) pod(w http.ResponseWriter, r *http.Request) {
	p, ok := s.cluster.Pod(r.PathValue("ns"), r.PathValue("name"))
	if !ok {
		writeError(w, http.StatusNotFound, "pod not found")
		return
	}
	snap := s.snapshot()
	byDigest := snap.ImagesByDigest()
	d := PodDetail{PodInfo: p, Images: map[string]string{}}
	// Prefer the digest; fall back to the workload's report for the
	// same container (digests differ for multi-arch images).
	wr := snap.ForWorkload(p.Workload)
	for _, c := range p.Containers {
		if k, ok := byDigest[c.Digest]; ok {
			d.Images[c.Name] = k
			continue
		}
		for _, img := range wr.Images {
			if img.Container == c.Name {
				d.Images[c.Name] = img.Key
			}
		}
	}
	writeJSON(w, d)
}

// NamespaceRow is a namespace with totals over its workloads.
type NamespaceRow struct {
	kube.NamespaceInfo
	Workloads int                     `json:"workloads"`
	Vulns     reports.SeveritySummary `json:"vulns"`
	Config    reports.SeveritySummary `json:"config"`
	Secrets   int                     `json:"secrets"`
}

func (s *Server) namespaceRows() []*NamespaceRow {
	byName := map[string]*NamespaceRow{}
	var out []*NamespaceRow
	for _, ns := range s.cluster.Namespaces() {
		row := &NamespaceRow{NamespaceInfo: ns}
		byName[ns.Name] = row
		out = append(out, row)
	}
	for _, w := range s.workloadRows() {
		row := byName[w.Namespace]
		if row == nil {
			continue
		}
		row.Workloads++
		row.Vulns.Add(w.Stats.Vulns)
		row.Config.Add(w.Stats.Config)
		row.Secrets += w.Stats.Secrets
	}
	return out
}

func (s *Server) namespaces(w http.ResponseWriter, _ *http.Request) {
	rows := s.namespaceRows()
	slices.SortFunc(rows, func(a, b *NamespaceRow) int {
		return cmp.Or(sevCmp(a.Vulns, b.Vulns), cmp.Compare(a.Name, b.Name))
	})
	writeJSON(w, rows)
}

// NamespaceDetail is the namespace page. Vulnerability totals are summed
// per workload, so an image shared by two workloads counts twice.
type NamespaceDetail struct {
	*NamespaceRow
	WorkloadList []*WorkloadRow        `json:"workloadList"`
	Config       []*index.CheckFinding `json:"configFindings"`
	RBAC         []*index.CheckFinding `json:"rbacFindings"`
}

func (s *Server) namespace(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var row *NamespaceRow
	for _, n := range s.namespaceRows() {
		if n.Name == name {
			row = n
		}
	}
	if row == nil {
		writeError(w, http.StatusNotFound, "namespace not found")
		return
	}
	d := NamespaceDetail{NamespaceRow: row, WorkloadList: []*WorkloadRow{}}
	for _, wr := range s.workloadRows() {
		if wr.Namespace == name {
			d.WorkloadList = append(d.WorkloadList, wr)
		}
	}
	slices.SortStableFunc(d.WorkloadList, workloadSorts["severity"])
	snap := s.snapshot()
	inNS := func(w index.Workload) bool { return w.Namespace == name }
	// Workload misconfigurations are on the workload rows; list the other
	// resources (services, ingresses, PVCs...) here.
	isWorkload := map[string]bool{"Deployment": true, "StatefulSet": true, "DaemonSet": true, "CronJob": true, "Pod": true, "ReplicaSet": true, "Job": true}
	d.Config = snap.ChecksFor(index.CheckConfig, func(w index.Workload) bool { return inNS(w) && !isWorkload[w.Kind] })
	d.RBAC = snap.ChecksFor(index.CheckRBAC, inNS)
	writeJSON(w, d)
}

func (s *Server) nodes(w http.ResponseWriter, _ *http.Request) {
	nodes := s.cluster.Nodes()
	if nodes == nil {
		nodes = []kube.NodeInfo{}
	}
	writeJSON(w, nodes)
}

// NodeDetail is the node page.
type NodeDetail struct {
	kube.NodeInfo
	Infra []*index.CheckFinding `json:"infra"`
	Pods  []kube.PodInfo        `json:"podList"`
}

func (s *Server) node(w http.ResponseWriter, r *http.Request) {
	n, ok := s.cluster.Node(r.PathValue("name"))
	if !ok {
		writeError(w, http.StatusNotFound, "node not found")
		return
	}
	d := NodeDetail{NodeInfo: n}
	d.Infra = s.snapshot().ChecksFor(index.CheckInfra, func(w index.Workload) bool { return w.Kind == "Node" && w.Name == n.Name })
	d.Pods = s.cluster.Pods(func(p kube.PodInfo) bool { return p.Node == n.Name })
	if d.Pods == nil {
		d.Pods = []kube.PodInfo{}
	}
	writeJSON(w, d)
}
