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
	// Flagged is set when the workload or some of its findings are flagged.
	Flagged bool `json:"flagged,omitempty"`
	text    string
}

func (r *WorkloadRow) IsFlagged() bool { return r.Flagged }
func (r *WorkloadRow) SortKey() string { return r.String() }

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

func (s *Server) workloadRows(uv *userView) []*WorkloadRow {
	stats := uv.view.WorkloadStats()
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
		res := w.Resource
		flagged := st.Flagged || uv.flagged(index.Target{Kind: index.TargetWorkload, Resource: &res})
		rows = append(rows, &WorkloadRow{WorkloadInfo: w, Stats: st, Flagged: flagged, text: b.String()})
	}
	return rows
}

func (s *Server) workloads(w http.ResponseWriter, r *http.Request) {
	p, err := parseList(r, WorkloadSchema)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	_, uv, ok := s.visible(w, r)
	if !ok {
		return
	}
	rows := s.workloadRows(uv)
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
	// HiddenFindings counts the workload's findings the user hid.
	HiddenFindings int `json:"hiddenFindings"`
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
	snap, uv, ok := s.visible(w, r)
	if !ok {
		return
	}
	d.Reports = snap.ForWorkload(res)
	if d.Workload == nil && len(d.Reports.Reports) == 0 {
		writeError(w, http.StatusNotFound, "workload not found")
		return
	}
	d.HiddenFindings = uv.hiddenIn(index.Target{Kind: index.TargetWorkload, Resource: &res})
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
	// Flagged is set when the namespace or some of its findings are flagged.
	Flagged bool `json:"flagged,omitempty"`
}

func (s *Server) namespaceRows(uv *userView) []*NamespaceRow {
	byName := map[string]*NamespaceRow{}
	var out []*NamespaceRow
	for _, ns := range s.cluster.Namespaces() {
		row := &NamespaceRow{NamespaceInfo: ns, Flagged: uv.flagged(index.Target{Kind: index.TargetNamespace, Namespace: ns.Name})}
		byName[ns.Name] = row
		out = append(out, row)
	}
	for _, w := range s.cluster.Workloads() {
		if row := byName[w.Namespace]; row != nil {
			row.Workloads++
		}
	}
	// Totals count each image's finding once per namespace, the same way
	// the dashboard does.
	for _, n := range uv.view.Summary().Namespaces {
		if row := byName[n.Namespace]; row != nil {
			row.Vulns, row.Config, row.Secrets = n.Vulns, n.Config, n.Secrets
			row.Flagged = row.Flagged || n.Flagged
		}
	}
	return out
}

func (s *Server) namespaces(w http.ResponseWriter, r *http.Request) {
	_, uv, ok := s.visible(w, r)
	if !ok {
		return
	}
	rows := s.namespaceRows(uv)
	slices.SortFunc(rows, func(a, b *NamespaceRow) int {
		return cmp.Or(cmp.Compare(boolInt(b.Flagged), boolInt(a.Flagged)), sevCmp(a.Vulns, b.Vulns), cmp.Compare(a.Name, b.Name))
	})
	writeJSON(w, rows)
}

// NamespaceDetail is the namespace page.
type NamespaceDetail struct {
	*NamespaceRow
	WorkloadList []*WorkloadRow        `json:"workloadList"`
	Config       []*index.CheckFinding `json:"configFindings"`
	RBAC         []*index.CheckFinding `json:"rbacFindings"`
	// HiddenFindings counts the namespace's findings the user hid.
	HiddenFindings int `json:"hiddenFindings"`
}

func (s *Server) namespace(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	snap, uv, ok := s.visible(w, r)
	if !ok {
		return
	}
	var row *NamespaceRow
	for _, n := range s.namespaceRows(uv) {
		if n.Name == name {
			row = n
		}
	}
	if row == nil {
		writeError(w, http.StatusNotFound, "namespace not found")
		return
	}
	d := NamespaceDetail{NamespaceRow: row, WorkloadList: []*WorkloadRow{}, HiddenFindings: uv.hiddenIn(index.Target{Kind: index.TargetNamespace, Namespace: name})}
	// Workload misconfigurations are on the workload rows; list the other
	// resources (services, ingresses, PVCs...) here.
	isWorkload := map[string]bool{}
	for _, wr := range s.workloadRows(uv) {
		if wr.Namespace == name {
			d.WorkloadList = append(d.WorkloadList, wr)
			isWorkload[wr.String()] = true
		}
	}
	slices.SortFunc(d.WorkloadList, byKey)
	slices.SortStableFunc(d.WorkloadList, workloadSorts["severity"])
	slices.SortStableFunc(d.WorkloadList, index.FlaggedFirst)
	inNS := func(w index.Workload) bool { return w.Namespace == name }
	podLike := map[string]bool{"Pod": true, "ReplicaSet": true, "Job": true}
	d.Config = snap.ChecksFor(index.CheckConfig, func(w index.Workload) bool {
		return inNS(w) && !isWorkload[w.String()] && !podLike[w.Kind]
	})
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
	snap, _, ok := s.visible(w, r)
	if !ok {
		return
	}
	d := NodeDetail{NodeInfo: n}
	d.Infra = snap.ChecksFor(index.CheckInfra, func(w index.Workload) bool { return w.Kind == "Node" && w.Name == n.Name })
	d.Pods = s.cluster.Pods(func(p kube.PodInfo) bool { return p.Node == n.Name })
	if d.Pods == nil {
		d.Pods = []kube.PodInfo{}
	}
	writeJSON(w, d)
}
