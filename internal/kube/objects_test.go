package kube

import (
	"context"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"

	"github.com/mnorrsken/trivyal/internal/reports"
)

func ctrl(kind, name string) []metav1.OwnerReference {
	yes := true
	return []metav1.OwnerReference{{Kind: kind, Name: name, Controller: &yes}}
}

func pod(ns, name string, owners []metav1.OwnerReference, ready bool) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, OwnerReferences: owners},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "registry.example.com/" + name}}},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, ContainerStatuses: []corev1.ContainerStatus{
			{Name: "c", Ready: ready, ImageID: "registry.example.com/x@sha256:abc"},
		}},
	}
}

func testCache(t *testing.T, objs ...runtime.Object) *Cache {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	c := &Cache{core: fake.NewClientset(objs...), onChange: func() {}}
	if err := c.startCore(ctx); err != nil {
		t.Fatal(err)
	}
	fns := []cache.InformerSynced{c.rsInf.HasSynced, c.jobInf.HasSynced}
	for _, inf := range c.objInf {
		fns = append(fns, inf.HasSynced)
	}
	if !cache.WaitForCacheSync(ctx.Done(), fns...) {
		t.Fatal("caches did not sync")
	}
	return c
}

func TestWorkloadsAndOwners(t *testing.T) {
	two := int32(2)
	c := testCache(t,
		&appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "web"}, Spec: appsv1.DeploymentSpec{Replicas: &two}},
		&appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "web-1", OwnerReferences: ctrl("Deployment", "web")}},
		pod("shop", "web-1-a", ctrl("ReplicaSet", "web-1"), true),
		pod("shop", "db-1", ctrl("Cluster", "db"), true),
		pod("shop", "db-2", ctrl("Cluster", "db"), false),
		&batchv1.Job{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "migrate"}},
		pod("shop", "migrate-x", ctrl("Job", "migrate"), false),
		pod("kube-system", "etcd-node-a", ctrl("Node", "node-a"), true),
		pod("shop", "debug", nil, true),
	)

	got := map[string]WorkloadInfo{}
	for _, w := range c.Workloads() {
		got[w.String()] = w
	}
	for _, want := range []string{"shop/Deployment/web", "shop/Cluster/db", "shop/Job/migrate", "kube-system/Pod/etcd-node-a", "shop/Pod/debug"} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing workload %s in %v", want, got)
		}
	}
	if len(got) != 5 {
		t.Errorf("got %d workloads, want 5: %v", len(got), got)
	}
	db := got["shop/Cluster/db"]
	if *db.Replicas != 2 || db.Ready != 1 {
		t.Errorf("db replicas %d ready %d, want 2 and 1", *db.Replicas, db.Ready)
	}
	if w, ok := c.Workload("Cluster", "shop", "db"); !ok || *w.Replicas != 2 {
		t.Errorf("Workload(Cluster db) = %+v, %v", w, ok)
	}
	if _, ok := c.Workload("Cluster", "shop", "nope"); ok {
		t.Error("unknown custom resource workload found")
	}

	p, ok := c.Pod("shop", "web-1-a")
	if !ok || p.Workload != (reports.Resource{Kind: "Deployment", Namespace: "shop", Name: "web"}) || p.Containers[0].Digest != "sha256:abc" {
		t.Errorf("pod = %+v", p)
	}
	if o, ok := c.Owner("Pod", "shop", "db-1"); !ok || o.Kind != "Cluster" || o.Name != "db" {
		t.Errorf("Owner(Pod db-1) = %+v, %v", o, ok)
	}
	if o, ok := c.Owner("ReplicaSet", "shop", "web-1"); !ok || o.Kind != "Deployment" {
		t.Errorf("Owner(ReplicaSet web-1) = %+v, %v", o, ok)
	}
}
