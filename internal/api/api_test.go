package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mnorrsken/trivyal/internal/fixture"
	"github.com/mnorrsken/trivyal/internal/index"
	"github.com/mnorrsken/trivyal/internal/kube"
	"github.com/mnorrsken/trivyal/internal/reports"
)

// fakeBackend serves the fixture reports plus a few cluster objects.
type fakeBackend struct{ synced bool }

func (fakeBackend) Workloads() []kube.WorkloadInfo {
	return []kube.WorkloadInfo{
		{Resource: reports.Resource{Kind: "Deployment", Namespace: "shop", Name: "web"}, Containers: []kube.Container{{Name: "web", Image: "registry.example.com/shop/web:1.0"}}},
		{Resource: reports.Resource{Kind: "Deployment", Namespace: "shop", Name: "quiet"}},
		{Resource: reports.Resource{Kind: "Cluster", Namespace: "shop", Name: "db"}},
	}
}

func (b fakeBackend) Workload(kind, ns, name string) (kube.WorkloadInfo, bool) {
	for _, w := range b.Workloads() {
		if w.Kind == kind && w.Namespace == ns && w.Name == name {
			return w, true
		}
	}
	return kube.WorkloadInfo{}, false
}

var testPod = kube.PodInfo{
	Namespace: "shop", Name: "web-new-x1", Phase: "Running", Node: "node-a",
	Workload:   reports.Resource{Kind: "Deployment", Namespace: "shop", Name: "web"},
	Containers: []kube.PodContainer{{Name: "web", Digest: "sha256:aaa"}, {Name: "sidecar", Digest: "sha256:unknown"}},
}

func (fakeBackend) Pod(ns, name string) (kube.PodInfo, bool) {
	return testPod, ns == testPod.Namespace && name == testPod.Name
}

func (fakeBackend) Pods(match func(kube.PodInfo) bool) []kube.PodInfo {
	if match == nil || match(testPod) {
		return []kube.PodInfo{testPod}
	}
	return nil
}

func (fakeBackend) Nodes() []kube.NodeInfo { return []kube.NodeInfo{{Name: "node-a", Ready: true}} }
func (b fakeBackend) Node(name string) (kube.NodeInfo, bool) {
	return b.Nodes()[0], name == "node-a"
}
func (fakeBackend) Namespaces() []kube.NamespaceInfo {
	return []kube.NamespaceInfo{{Name: "shop"}, {Name: "demo"}}
}
func (b fakeBackend) Namespace(name string) (kube.NamespaceInfo, bool) {
	return kube.NamespaceInfo{Name: name}, name == "shop" || name == "demo"
}
func (b fakeBackend) Synced() bool { return b.synced }
func (fakeBackend) Get(_ context.Context, resource, ns, name string) (map[string]any, error) {
	return map[string]any{"report": map[string]any{"components": map[string]any{"bomFormat": "CycloneDX"}}}, nil
}

func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	idx := index.New(fixture.New(t))
	hub := NewHub(idx.Generation, 10*time.Millisecond)
	mux := http.NewServeMux()
	New(idx, fakeBackend{synced: true}, hub, NewMetrics(hub)).Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func get(t *testing.T, srv *httptest.Server, path string, want int, v any) string {
	t.Helper()
	res, err := http.Get(srv.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != want {
		t.Fatalf("GET %s: status %d, want %d", path, res.StatusCode, want)
	}
	if v != nil {
		if err := json.NewDecoder(res.Body).Decode(v); err != nil {
			t.Fatalf("GET %s: decoding: %v", path, err)
		}
		return ""
	}
	var b strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := res.Body.Read(buf)
		b.Write(buf[:n])
		if err != nil {
			break
		}
	}
	return b.String()
}

type list struct {
	Total  int                         `json:"total"`
	Rows   int                         `json:"rows"`
	Group  string                      `json:"group"`
	Sort   string                      `json:"sort"`
	Items  []map[string]any            `json:"items"`
	Facets map[string][]map[string]any `json:"facets"`
}

func TestLists(t *testing.T) {
	srv := newTestServer(t)
	tests := []struct {
		path  string
		total int
		group string
	}{
		{"/api/v1/vulnerabilities", 4, "image"},
		{"/api/v1/vulnerabilities?group=workload", 5, "workload"},
		{"/api/v1/vulnerabilities?group=cve&q=sev:critical", 1, "cve"},
		{"/api/v1/vulnerabilities?group=finding&stale=1", 8, "finding"},
		{"/api/v1/vulnerabilities?group=nonsense", 4, "image"},
		{"/api/v1/checks/config", 3, "resource"},
		{"/api/v1/checks/config?group=check", 4, "check"},
		{"/api/v1/checks/rbac?group=finding", 1, "finding"},
		{"/api/v1/secrets", 2, "finding"},
		{"/api/v1/sbom", 2, "component"},
		{"/api/v1/sbom?group=image&q=name:zlib", 1, "image"},
		{"/api/v1/workloads?q=sev:critical", 1, "workload"},
	}
	for _, tt := range tests {
		var l list
		get(t, srv, tt.path, http.StatusOK, &l)
		if l.Total != tt.total || l.Group != tt.group || len(l.Items) != tt.total {
			t.Errorf("%s: total %d group %q items %d, want %d %q", tt.path, l.Total, l.Group, len(l.Items), tt.total, tt.group)
		}
	}
}

func TestListPagingAndSort(t *testing.T) {
	srv := newTestServer(t)
	var l list
	get(t, srv, "/api/v1/vulnerabilities?group=finding&size=1&page=2&sort=-severity", http.StatusOK, &l)
	if l.Total != 7 || len(l.Items) != 1 || l.Sort != "-severity" {
		t.Errorf("paging: %+v", l)
	}
	get(t, srv, "/api/v1/vulnerabilities?group=finding&page=99", http.StatusOK, &l)
	if len(l.Items) != 0 {
		t.Errorf("page past the end returned %d items", len(l.Items))
	}
}

func TestBadFilter(t *testing.T) {
	srv := newTestServer(t)
	var e map[string]string
	get(t, srv, "/api/v1/vulnerabilities?q=nope:x", http.StatusBadRequest, &e)
	if !strings.Contains(e["error"], "unknown filter") {
		t.Errorf("error = %q", e["error"])
	}
	get(t, srv, "/api/v1/checks/bogus", http.StatusNotFound, nil)
	get(t, srv, "/api/v1/nothing", http.StatusNotFound, nil)
}

func TestDetails(t *testing.T) {
	srv := newTestServer(t)
	var img ImageDetail
	get(t, srv, "/api/v1/image?key=sha256:aaa", http.StatusOK, &img)
	if len(img.Vulnerabilities) != 3 || img.Vulnerabilities[0].Severity != "CRITICAL" || len(img.Secrets) != 1 || img.SBOM == nil {
		t.Errorf("image detail: %d vulns, %d secrets, sbom %v", len(img.Vulnerabilities), len(img.Secrets), img.SBOM != nil)
	}
	get(t, srv, "/api/v1/image?key=sha256:none", http.StatusNotFound, nil)

	var cve CVEDetail
	get(t, srv, "/api/v1/cve/CVE-2024-0001", http.StatusOK, &cve)
	if len(cve.Affected) != 2 {
		t.Errorf("cve affected = %d, want 2", len(cve.Affected))
	}

	var chk CheckDetail
	get(t, srv, "/api/v1/checks/config/avd-ksv-0014", http.StatusOK, &chk)
	if len(chk.Resources) != 1 {
		t.Errorf("check resources = %d", len(chk.Resources))
	}

	var ctl ControlDetail
	get(t, srv, "/api/v1/compliance/demo-benchmark/1.1", http.StatusOK, &ctl)
	if len(ctl.Failing) != 1 || ctl.Failing[0].Resource.Name != "web" {
		t.Errorf("control failing = %+v", ctl.Failing)
	}

	var rep map[string]any
	get(t, srv, "/api/v1/report/clusterrbacassessmentreports/clusterrole-admin", http.StatusOK, &rep)
	get(t, srv, "/api/v1/report/configauditreports/shop/service-web", http.StatusOK, &rep)

	body := get(t, srv, "/api/v1/sbom/download?key=sha256:aaa", http.StatusOK, nil)
	if !strings.Contains(body, "CycloneDX") {
		t.Errorf("download body = %q", body)
	}
	csv := get(t, srv, "/api/v1/vulnerabilities.csv?q=sev:critical", http.StatusOK, nil)
	if lines := strings.Count(csv, "\n"); lines != 3 {
		t.Errorf("csv has %d lines, want header + 2:\n%s", lines, csv)
	}
}

func TestResources(t *testing.T) {
	srv := newTestServer(t)
	var wd WorkloadDetail
	get(t, srv, "/api/v1/workload/shop/Deployment/web", http.StatusOK, &wd)
	if wd.Workload == nil || len(wd.Pods) != 1 || len(wd.Reports.Images) != 1 {
		t.Errorf("workload detail = %+v", wd)
	}
	// Known only from reports (not in the cluster fake): still served.
	get(t, srv, "/api/v1/workload/demo/CronJob/backup", http.StatusOK, &wd)
	get(t, srv, "/api/v1/workload/demo/CronJob/missing", http.StatusNotFound, nil)

	var pd PodDetail
	get(t, srv, "/api/v1/pod/shop/web-new-x1", http.StatusOK, &pd)
	if pd.Images["web"] != "sha256:aaa" || pd.Images["sidecar"] != "" {
		t.Errorf("pod images = %v", pd.Images)
	}

	var nd NamespaceDetail
	get(t, srv, "/api/v1/namespace/shop", http.StatusOK, &nd)
	// web and api run the same image: its critical counts once.
	if nd.Workloads != 3 || nd.Vulns.Critical != 1 || len(nd.Config) != 1 || nd.Config[0].Resource.Kind != "Service" {
		t.Errorf("namespace detail: workloads %d, config %+v", nd.Workloads, nd.Config)
	}
	var node NodeDetail
	get(t, srv, "/api/v1/node/node-a", http.StatusOK, &node)
	if len(node.Pods) != 1 {
		t.Errorf("node pods = %d", len(node.Pods))
	}

	var hits []index.SearchHit
	get(t, srv, "/api/v1/search?q=node", http.StatusOK, &hits)
	if len(hits) == 0 || hits[len(hits)-1].Kind != "node" {
		t.Errorf("search hits = %+v", hits)
	}
}

func TestSummaryAndHealth(t *testing.T) {
	srv := newTestServer(t)
	var s struct {
		index.Summary
		Synced bool `json:"synced"`
	}
	get(t, srv, "/api/v1/summary", http.StatusOK, &s)
	if !s.Synced || s.Vulns.Images != 4 {
		t.Errorf("summary = %+v", s)
	}
	get(t, srv, "/healthz", http.StatusOK, nil)
	get(t, srv, "/readyz", http.StatusOK, nil)
}

func TestEvents(t *testing.T) {
	idx := index.New(fixture.New(t))
	hub := NewHub(idx.Generation, 10*time.Millisecond)
	srv := httptest.NewServer(hub)
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", srv.URL, nil)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	buf := make([]byte, 256)
	n, _ := res.Body.Read(buf)
	if !strings.Contains(string(buf[:n]), "event: hello") {
		t.Fatalf("first event = %q", buf[:n])
	}
	idx.Invalidate()
	hub.Notify()
	n, _ = res.Body.Read(buf)
	if !strings.Contains(string(buf[:n]), "event: changed") {
		t.Errorf("second event = %q", buf[:n])
	}
}
