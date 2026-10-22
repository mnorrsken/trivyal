// Package kube watches trivy-operator reports and the few core objects the
// UI needs for owner resolution, and keeps them in informer caches.
package kube

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/mnorrsken/trivyal/internal/reports"
)

// RestConfig returns the in-cluster config, or the kubeconfig at path (or
// the default loading rules when path is empty) outside a cluster.
func RestConfig(path string) (*rest.Config, error) {
	if path == "" {
		if cfg, err := rest.InClusterConfig(); err == nil {
			return cfg, nil
		}
	}
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if path != "" {
		rules.ExplicitPath = path
	}
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, nil).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("loading kubeconfig: %w", err)
	}
	return cfg, nil
}

// Object is what the report informers store: the object metadata plus the
// parsed report. The unstructured object is dropped by the informer
// transform, so large reports (SBOMs) are only held in parsed form.
type Object struct {
	metav1.TypeMeta
	metav1.ObjectMeta
	Report any
}

// DeepCopyObject returns a shallow copy; parsed reports are never mutated.
func (o *Object) DeepCopyObject() runtime.Object {
	c := *o
	return &c
}

// Cache holds the informers.
type Cache struct {
	cfg      *rest.Config
	dyn      dynamic.Interface
	core     kubernetes.Interface
	onChange func()

	mu        sync.RWMutex
	informers map[string]cache.SharedIndexInformer
	factory   informers.SharedInformerFactory
	rsInf     cache.SharedIndexInformer
	jobInf    cache.SharedIndexInformer
	objInf    map[string]cache.SharedIndexInformer
	synced    bool
}

// New creates a cache. onChange is called after every add, update or
// delete of a watched object; it must be cheap.
func New(cfg *rest.Config, onChange func()) (*Cache, error) {
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("creating dynamic client: %w", err)
	}
	core, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("creating clientset: %w", err)
	}
	return &Cache{cfg: cfg, dyn: dyn, core: core, onChange: onChange, informers: map[string]cache.SharedIndexInformer{}}, nil
}

// Available returns the report resources served by the API server.
func (c *Cache) Available() ([]string, error) {
	list, err := c.core.Discovery().ServerResourcesForGroupVersion(reports.Group + "/" + reports.Version)
	if err != nil {
		return nil, fmt.Errorf("discovering %s: %w", reports.Group, err)
	}
	var out []string
	for _, r := range list.APIResources {
		if slices.Contains(reports.Resources, r.Name) {
			out = append(out, r.Name)
		}
	}
	return out, nil
}

// Start discovers the report CRDs, starts informers and waits for the
// initial sync. A missing trivy-operator is not an error: the UI shows an
// empty state, and discovery is retried every minute until CRDs appear.
func (c *Cache) Start(ctx context.Context) error {
	if err := c.startCore(ctx); err != nil {
		return err
	}

	if err := c.startReports(ctx); err != nil {
		slog.Warn("trivy-operator reports not available yet", "err", err)
	}
	if !c.waitSynced(ctx) {
		return ctx.Err()
	}
	go c.rediscover(ctx)
	return nil
}

// startCore starts the informers for core objects (everything but the
// reports).
func (c *Cache) startCore(ctx context.Context) error {
	c.factory = informers.NewSharedInformerFactoryWithOptions(c.core, 30*time.Minute)
	c.rsInf = c.factory.Apps().V1().ReplicaSets().Informer()
	c.jobInf = c.factory.Batch().V1().Jobs().Informer()
	for _, inf := range []cache.SharedIndexInformer{c.rsInf, c.jobInf} {
		if err := inf.SetTransform(trimOwner); err != nil {
			return fmt.Errorf("setting transform: %w", err)
		}
		if _, err := inf.AddEventHandler(c.handler()); err != nil {
			return fmt.Errorf("adding handler: %w", err)
		}
	}
	if err := c.startObjects(); err != nil {
		return fmt.Errorf("watching cluster objects: %w", err)
	}
	c.factory.Start(ctx.Done())
	return nil
}

func (c *Cache) startReports(ctx context.Context) error {
	avail, err := c.Available()
	if err != nil {
		return err
	}
	for _, res := range avail {
		c.mu.RLock()
		_, ok := c.informers[res]
		c.mu.RUnlock()
		if ok {
			continue
		}
		inf, err := c.reportInformer(res)
		if err != nil {
			return err
		}
		c.mu.Lock()
		c.informers[res] = inf
		c.mu.Unlock()
		go inf.Run(ctx.Done())
	}
	return nil
}

func (c *Cache) rediscover(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.mu.RLock()
			n := len(c.informers)
			c.mu.RUnlock()
			if n == len(reports.Resources) {
				return
			}
			if err := c.startReports(ctx); err != nil {
				slog.Debug("rediscovering reports", "err", err)
			}
		}
	}
}

func (c *Cache) waitSynced(ctx context.Context) bool {
	c.mu.RLock()
	fns := []cache.InformerSynced{c.rsInf.HasSynced, c.jobInf.HasSynced}
	for _, inf := range c.objInf {
		fns = append(fns, inf.HasSynced)
	}
	for _, inf := range c.informers {
		fns = append(fns, inf.HasSynced)
	}
	c.mu.RUnlock()
	if !cache.WaitForCacheSync(ctx.Done(), fns...) {
		return false
	}
	c.mu.Lock()
	c.synced = true
	c.mu.Unlock()
	c.onChange()
	return true
}

// Synced reports whether the initial list of all informers has completed.
func (c *Cache) Synced() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.synced {
		return false
	}
	for _, inf := range c.informers {
		if !inf.HasSynced() {
			return false
		}
	}
	return true
}

func (c *Cache) handler() cache.ResourceEventHandler {
	return cache.ResourceEventHandlerFuncs{
		AddFunc:    func(any) { c.onChange() },
		UpdateFunc: func(any, any) { c.onChange() },
		DeleteFunc: func(any) { c.onChange() },
	}
}

func (c *Cache) reportInformer(resource string) (cache.SharedIndexInformer, error) {
	gvr := schema.GroupVersionResource{Group: reports.Group, Version: reports.Version, Resource: resource}
	ri := c.dyn.Resource(gvr)
	lw := &cache.ListWatch{
		ListWithContextFunc: func(ctx context.Context, opts metav1.ListOptions) (runtime.Object, error) {
			return ri.List(ctx, opts)
		},
		WatchFuncWithContext: func(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error) {
			return ri.Watch(ctx, opts)
		},
	}
	inf := cache.NewSharedIndexInformer(lw, &unstructured.Unstructured{}, 30*time.Minute, cache.Indexers{})
	if err := inf.SetTransform(parseTransform(resource)); err != nil {
		return nil, fmt.Errorf("setting transform: %w", err)
	}
	if _, err := inf.AddEventHandler(c.handler()); err != nil {
		return nil, fmt.Errorf("adding handler: %w", err)
	}
	return inf, nil
}

func parseTransform(resource string) cache.TransformFunc {
	return func(in any) (any, error) {
		u, ok := in.(*unstructured.Unstructured)
		if !ok {
			// Tombstones and already transformed objects pass through.
			return in, nil
		}
		data, err := json.Marshal(u.Object)
		if err != nil {
			return nil, fmt.Errorf("encoding %s/%s: %w", resource, u.GetName(), err)
		}
		rep, err := reports.Parse(resource, data)
		if err != nil {
			slog.Warn("skipping unparsable report", "resource", resource, "name", u.GetName(), "err", err)
		}
		return &Object{
			TypeMeta: metav1.TypeMeta{Kind: u.GetKind(), APIVersion: u.GetAPIVersion()},
			ObjectMeta: metav1.ObjectMeta{
				Name: u.GetName(), Namespace: u.GetNamespace(), UID: u.GetUID(),
				ResourceVersion: u.GetResourceVersion(),
			},
			Report: rep,
		}, nil
	}
}

// trimOwner keeps only what owner resolution needs from ReplicaSets and Jobs.
func trimOwner(in any) (any, error) {
	switch o := in.(type) {
	case *appsv1.ReplicaSet:
		return &appsv1.ReplicaSet{
			ObjectMeta: trimMeta(o.ObjectMeta),
			Spec:       appsv1.ReplicaSetSpec{Replicas: o.Spec.Replicas},
		}, nil
	case *batchv1.Job:
		return &batchv1.Job{ObjectMeta: trimMeta(o.ObjectMeta)}, nil
	}
	return in, nil
}

func trimMeta(m metav1.ObjectMeta) metav1.ObjectMeta {
	return metav1.ObjectMeta{
		Name: m.Name, Namespace: m.Namespace, UID: m.UID,
		ResourceVersion: m.ResourceVersion, OwnerReferences: m.OwnerReferences,
	}
}

// Reports returns the parsed reports of one resource.
func (c *Cache) Reports(resource string) []any {
	c.mu.RLock()
	inf := c.informers[resource]
	c.mu.RUnlock()
	if inf == nil {
		return nil
	}
	items := inf.GetStore().List()
	out := make([]any, 0, len(items))
	for _, it := range items {
		if o, ok := it.(*Object); ok && o.Report != nil {
			out = append(out, o.Report)
		}
	}
	return out
}

// Installed reports whether any trivy-operator CRD was found.
func (c *Cache) Installed() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.informers) > 0
}

// Owner returns the controller owner of a ReplicaSet, Job or Pod, and the
// replica count of a ReplicaSet. ok is false when the object is not in the
// cache.
func (c *Cache) Owner(kind, namespace, name string) (reports.Owner, bool) {
	var inf cache.SharedIndexInformer
	switch kind {
	case "ReplicaSet":
		inf = c.rsInf
	case "Job":
		inf = c.jobInf
	case "Pod":
		inf = c.objInf["Pod"]
	default:
		return reports.Owner{}, false
	}
	if inf == nil {
		return reports.Owner{}, false
	}
	obj, ok, err := inf.GetStore().GetByKey(namespace + "/" + name)
	if err != nil || !ok {
		return reports.Owner{}, false
	}
	var o reports.Owner
	var refs []metav1.OwnerReference
	switch v := obj.(type) {
	case *appsv1.ReplicaSet:
		o.Replicas = v.Spec.Replicas
		refs = v.OwnerReferences
	case *batchv1.Job:
		refs = v.OwnerReferences
	case *corev1.Pod:
		refs = v.OwnerReferences
	}
	for _, r := range refs {
		if r.Controller != nil && *r.Controller {
			o.Kind, o.Name = r.Kind, r.Name
		}
	}
	return o, true
}

// Get fetches one report object from the API server, unparsed. Used for
// downloads of data the cache does not keep (full SBOM documents).
func (c *Cache) Get(ctx context.Context, resource, namespace, name string) (map[string]any, error) {
	gvr := schema.GroupVersionResource{Group: reports.Group, Version: reports.Version, Resource: resource}
	var ri dynamic.ResourceInterface = c.dyn.Resource(gvr)
	if namespace != "" {
		ri = c.dyn.Resource(gvr).Namespace(namespace)
	}
	u, err := ri.Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("getting %s %s/%s: %w", resource, namespace, name, err)
	}
	return u.Object, nil
}
