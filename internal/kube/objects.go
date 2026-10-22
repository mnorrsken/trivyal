package kube

import (
	"cmp"
	"slices"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"

	"github.com/mnorrsken/trivyal/internal/reports"
)

// The resource pages read workloads, pods, nodes and namespaces. Informer
// transforms keep only the fields below, so the cache stays small.

// Container is a container of a workload or pod template.
type Container struct {
	Name           string `json:"name"`
	Image          string `json:"image"`
	Init           bool   `json:"init,omitempty"`
	RunAsNonRoot   *bool  `json:"runAsNonRoot,omitempty"`
	RunAsUser      *int64 `json:"runAsUser,omitempty"`
	ReadOnlyRootFS *bool  `json:"readOnlyRootFilesystem,omitempty"`
	Privileged     *bool  `json:"privileged,omitempty"`
	AllowPrivEsc   *bool  `json:"allowPrivilegeEscalation,omitempty"`
	CPURequest     string `json:"cpuRequest,omitempty"`
	CPULimit       string `json:"cpuLimit,omitempty"`
	MemoryRequest  string `json:"memoryRequest,omitempty"`
	MemoryLimit    string `json:"memoryLimit,omitempty"`
}

// WorkloadInfo summarises a Deployment, StatefulSet, DaemonSet, CronJob,
// Job or Pod.
type WorkloadInfo struct {
	reports.Resource
	Labels         map[string]string `json:"labels,omitempty"`
	Created        time.Time         `json:"created"`
	Owner          *reports.Resource `json:"owner,omitempty"`
	Replicas       *int32            `json:"replicas,omitempty"`
	Ready          int32             `json:"ready"`
	Schedule       string            `json:"schedule,omitempty"`
	Suspended      bool              `json:"suspended,omitempty"`
	LastSchedule   *time.Time        `json:"lastSchedule,omitempty"`
	ServiceAccount string            `json:"serviceAccount,omitempty"`
	HostNetwork    bool              `json:"hostNetwork,omitempty"`
	HostPID        bool              `json:"hostPID,omitempty"`
	Containers     []Container       `json:"containers"`
}

// PodContainer is a container's runtime state.
type PodContainer struct {
	Name     string `json:"name"`
	Image    string `json:"image"`
	Digest   string `json:"digest,omitempty"`
	Init     bool   `json:"init,omitempty"`
	Ready    bool   `json:"ready"`
	Restarts int32  `json:"restarts"`
	State    string `json:"state"`
}

// PodInfo summarises a pod.
type PodInfo struct {
	Namespace  string            `json:"namespace"`
	Name       string            `json:"name"`
	Phase      string            `json:"phase"`
	Node       string            `json:"node,omitempty"`
	IP         string            `json:"ip,omitempty"`
	Started    *time.Time        `json:"started,omitempty"`
	Labels     map[string]string `json:"labels,omitempty"`
	Workload   reports.Resource  `json:"workload"`
	Containers []PodContainer    `json:"containers"`
	Spec       []Container       `json:"spec"`
}

// NodeInfo summarises a node.
type NodeInfo struct {
	Name          string    `json:"name"`
	Roles         []string  `json:"roles"`
	Ready         bool      `json:"ready"`
	Unschedulable bool      `json:"unschedulable,omitempty"`
	Kubelet       string    `json:"kubelet"`
	OSImage       string    `json:"osImage"`
	Kernel        string    `json:"kernel"`
	Runtime       string    `json:"runtime"`
	Arch          string    `json:"arch"`
	CPU           string    `json:"cpu"`
	Memory        string    `json:"memory"`
	Created       time.Time `json:"created"`
	Pods          int       `json:"pods"`
}

// NamespaceInfo summarises a namespace.
type NamespaceInfo struct {
	Name    string            `json:"name"`
	Phase   string            `json:"phase"`
	Labels  map[string]string `json:"labels,omitempty"`
	Created time.Time         `json:"created"`
}

func (c *Cache) startObjects() error {
	f := c.factory
	c.objInf = map[string]cache.SharedIndexInformer{
		"Deployment":  f.Apps().V1().Deployments().Informer(),
		"StatefulSet": f.Apps().V1().StatefulSets().Informer(),
		"DaemonSet":   f.Apps().V1().DaemonSets().Informer(),
		"CronJob":     f.Batch().V1().CronJobs().Informer(),
		"Pod":         f.Core().V1().Pods().Informer(),
		"Node":        f.Core().V1().Nodes().Informer(),
		"Namespace":   f.Core().V1().Namespaces().Informer(),
	}
	for _, inf := range c.objInf {
		if err := inf.SetTransform(trimObject); err != nil {
			return err
		}
		if _, err := inf.AddEventHandler(c.handler()); err != nil {
			return err
		}
	}
	return nil
}

func trimObject(in any) (any, error) {
	switch o := in.(type) {
	case *appsv1.Deployment:
		return &appsv1.Deployment{ObjectMeta: trimMetaLabels(o.ObjectMeta), Spec: appsv1.DeploymentSpec{Replicas: o.Spec.Replicas, Template: trimTemplate(o.Spec.Template)}, Status: o.Status}, nil
	case *appsv1.StatefulSet:
		return &appsv1.StatefulSet{ObjectMeta: trimMetaLabels(o.ObjectMeta), Spec: appsv1.StatefulSetSpec{Replicas: o.Spec.Replicas, Template: trimTemplate(o.Spec.Template)}, Status: o.Status}, nil
	case *appsv1.DaemonSet:
		return &appsv1.DaemonSet{ObjectMeta: trimMetaLabels(o.ObjectMeta), Spec: appsv1.DaemonSetSpec{Template: trimTemplate(o.Spec.Template)}, Status: o.Status}, nil
	case *batchv1.CronJob:
		return &batchv1.CronJob{
			ObjectMeta: trimMetaLabels(o.ObjectMeta),
			Spec: batchv1.CronJobSpec{Schedule: o.Spec.Schedule, Suspend: o.Spec.Suspend, JobTemplate: batchv1.JobTemplateSpec{
				Spec: batchv1.JobSpec{Template: trimTemplate(o.Spec.JobTemplate.Spec.Template)},
			}},
			Status: batchv1.CronJobStatus{LastScheduleTime: o.Status.LastScheduleTime},
		}, nil
	case *corev1.Pod:
		return &corev1.Pod{
			ObjectMeta: trimMetaLabels(o.ObjectMeta),
			Spec:       trimPodSpec(o.Spec),
			Status: corev1.PodStatus{
				Phase: o.Status.Phase, PodIP: o.Status.PodIP, StartTime: o.Status.StartTime,
				ContainerStatuses: o.Status.ContainerStatuses, InitContainerStatuses: o.Status.InitContainerStatuses,
			},
		}, nil
	case *corev1.Node:
		return &corev1.Node{
			ObjectMeta: trimMetaLabels(o.ObjectMeta),
			Spec:       corev1.NodeSpec{Unschedulable: o.Spec.Unschedulable},
			Status: corev1.NodeStatus{
				Capacity: o.Status.Capacity, Conditions: o.Status.Conditions, NodeInfo: o.Status.NodeInfo,
			},
		}, nil
	case *corev1.Namespace:
		return &corev1.Namespace{ObjectMeta: trimMetaLabels(o.ObjectMeta), Status: o.Status}, nil
	}
	return in, nil
}

func trimMetaLabels(m metav1.ObjectMeta) metav1.ObjectMeta {
	t := trimMeta(m)
	t.Labels = m.Labels
	t.CreationTimestamp = m.CreationTimestamp
	return t
}

func trimTemplate(t corev1.PodTemplateSpec) corev1.PodTemplateSpec {
	return corev1.PodTemplateSpec{Spec: trimPodSpec(t.Spec)}
}

func trimPodSpec(s corev1.PodSpec) corev1.PodSpec {
	trim := func(cs []corev1.Container) []corev1.Container {
		out := make([]corev1.Container, len(cs))
		for i, c := range cs {
			out[i] = corev1.Container{Name: c.Name, Image: c.Image, SecurityContext: c.SecurityContext, Resources: c.Resources}
		}
		return out
	}
	return corev1.PodSpec{
		Containers: trim(s.Containers), InitContainers: trim(s.InitContainers),
		NodeName: s.NodeName, ServiceAccountName: s.ServiceAccountName,
		HostNetwork: s.HostNetwork, HostPID: s.HostPID, SecurityContext: s.SecurityContext,
	}
}

func containers(s corev1.PodSpec) []Container {
	conv := func(c corev1.Container, init bool) Container {
		out := Container{Name: c.Name, Image: c.Image, Init: init}
		if p := s.SecurityContext; p != nil {
			out.RunAsNonRoot, out.RunAsUser = p.RunAsNonRoot, p.RunAsUser
		}
		if sc := c.SecurityContext; sc != nil {
			if sc.RunAsNonRoot != nil {
				out.RunAsNonRoot = sc.RunAsNonRoot
			}
			if sc.RunAsUser != nil {
				out.RunAsUser = sc.RunAsUser
			}
			out.ReadOnlyRootFS, out.Privileged, out.AllowPrivEsc = sc.ReadOnlyRootFilesystem, sc.Privileged, sc.AllowPrivilegeEscalation
		}
		q := func(l corev1.ResourceList, n corev1.ResourceName) string {
			if v, ok := l[n]; ok {
				return v.String()
			}
			return ""
		}
		out.CPURequest, out.CPULimit = q(c.Resources.Requests, corev1.ResourceCPU), q(c.Resources.Limits, corev1.ResourceCPU)
		out.MemoryRequest, out.MemoryLimit = q(c.Resources.Requests, corev1.ResourceMemory), q(c.Resources.Limits, corev1.ResourceMemory)
		return out
	}
	var out []Container
	for _, c := range s.InitContainers {
		out = append(out, conv(c, true))
	}
	for _, c := range s.Containers {
		out = append(out, conv(c, false))
	}
	return out
}

func (c *Cache) objects(kind string) []any {
	inf := c.objInf[kind]
	if inf == nil {
		return nil
	}
	return inf.GetStore().List()
}

func (c *Cache) object(kind, namespace, name string) (any, bool) {
	inf := c.objInf[kind]
	if inf == nil {
		return nil, false
	}
	key := name
	if namespace != "" {
		key = namespace + "/" + name
	}
	o, ok, err := inf.GetStore().GetByKey(key)
	return o, ok && err == nil
}

func controller(refs []metav1.OwnerReference) *metav1.OwnerReference {
	for i := range refs {
		if refs[i].Controller != nil && *refs[i].Controller {
			return &refs[i]
		}
	}
	return nil
}

// TopOwner follows controller owners through ReplicaSets and Jobs to the
// workload a user manages. Pods owned by custom resources stay pods, the
// same way trivy-operator reports them.
func (c *Cache) TopOwner(namespace string, refs []metav1.OwnerReference, self reports.Resource) reports.Resource {
	ref := controller(refs)
	if ref == nil {
		return self
	}
	switch ref.Kind {
	case "ReplicaSet", "Job":
		if o, ok := c.Owner(ref.Kind, namespace, ref.Name); ok && o.Kind != "" {
			if o.Kind == "Deployment" || o.Kind == "CronJob" {
				return reports.Resource{Kind: o.Kind, Namespace: namespace, Name: o.Name}
			}
		}
		return reports.Resource{Kind: ref.Kind, Namespace: namespace, Name: ref.Name}
	case "StatefulSet", "DaemonSet", "Deployment", "CronJob":
		return reports.Resource{Kind: ref.Kind, Namespace: namespace, Name: ref.Name}
	}
	return self
}

func workloadInfo(o any) (WorkloadInfo, bool) {
	var w WorkloadInfo
	var meta metav1.ObjectMeta
	switch v := o.(type) {
	case *appsv1.Deployment:
		meta = v.ObjectMeta
		w.Kind, w.Replicas, w.Ready = "Deployment", v.Spec.Replicas, v.Status.ReadyReplicas
		w.Containers = containers(v.Spec.Template.Spec)
		w.ServiceAccount, w.HostNetwork, w.HostPID = v.Spec.Template.Spec.ServiceAccountName, v.Spec.Template.Spec.HostNetwork, v.Spec.Template.Spec.HostPID
	case *appsv1.StatefulSet:
		meta = v.ObjectMeta
		w.Kind, w.Replicas, w.Ready = "StatefulSet", v.Spec.Replicas, v.Status.ReadyReplicas
		w.Containers = containers(v.Spec.Template.Spec)
		w.ServiceAccount, w.HostNetwork, w.HostPID = v.Spec.Template.Spec.ServiceAccountName, v.Spec.Template.Spec.HostNetwork, v.Spec.Template.Spec.HostPID
	case *appsv1.DaemonSet:
		meta = v.ObjectMeta
		n := v.Status.DesiredNumberScheduled
		w.Kind, w.Replicas, w.Ready = "DaemonSet", &n, v.Status.NumberReady
		w.Containers = containers(v.Spec.Template.Spec)
		w.ServiceAccount, w.HostNetwork, w.HostPID = v.Spec.Template.Spec.ServiceAccountName, v.Spec.Template.Spec.HostNetwork, v.Spec.Template.Spec.HostPID
	case *batchv1.CronJob:
		meta = v.ObjectMeta
		ps := v.Spec.JobTemplate.Spec.Template.Spec
		w.Kind, w.Schedule = "CronJob", v.Spec.Schedule
		w.Suspended = v.Spec.Suspend != nil && *v.Spec.Suspend
		if t := v.Status.LastScheduleTime; t != nil {
			lt := t.Time
			w.LastSchedule = &lt
		}
		w.Containers = containers(ps)
		w.ServiceAccount, w.HostNetwork, w.HostPID = ps.ServiceAccountName, ps.HostNetwork, ps.HostPID
	case *corev1.Pod:
		meta = v.ObjectMeta
		w.Kind = "Pod"
		one := int32(1)
		w.Replicas = &one
		for _, s := range v.Status.ContainerStatuses {
			if !s.Ready {
				w.Ready = 0
				break
			}
			w.Ready = 1
		}
		w.Containers = containers(v.Spec)
		w.ServiceAccount, w.HostNetwork, w.HostPID = v.Spec.ServiceAccountName, v.Spec.HostNetwork, v.Spec.HostPID
	default:
		return w, false
	}
	w.Namespace, w.Name, w.Labels, w.Created = meta.Namespace, meta.Name, meta.Labels, meta.CreationTimestamp.Time
	if ref := controller(meta.OwnerReferences); ref != nil {
		w.Owner = &reports.Resource{Kind: ref.Kind, Namespace: meta.Namespace, Name: ref.Name}
	}
	return w, true
}

// Workload returns one workload. Kind Pod also finds pods that are not
// top-level (the UI links pods by their own name).
func (c *Cache) Workload(kind, namespace, name string) (WorkloadInfo, bool) {
	o, ok := c.object(kind, namespace, name)
	if !ok {
		return WorkloadInfo{}, false
	}
	return workloadInfo(o)
}

// Workloads lists the top-level workloads: Deployments, StatefulSets,
// DaemonSets, CronJobs and pods without a built-in controller.
func (c *Cache) Workloads() []WorkloadInfo {
	var out []WorkloadInfo
	for _, kind := range []string{"Deployment", "StatefulSet", "DaemonSet", "CronJob"} {
		for _, o := range c.objects(kind) {
			if w, ok := workloadInfo(o); ok {
				out = append(out, w)
			}
		}
	}
	for _, o := range c.objects("Pod") {
		p := o.(*corev1.Pod)
		self := reports.Resource{Kind: "Pod", Namespace: p.Namespace, Name: p.Name}
		if c.TopOwner(p.Namespace, p.OwnerReferences, self) != self {
			continue
		}
		if w, ok := workloadInfo(p); ok {
			out = append(out, w)
		}
	}
	slices.SortFunc(out, func(a, b WorkloadInfo) int {
		return cmp.Or(cmp.Compare(a.Namespace, b.Namespace), cmp.Compare(a.Kind, b.Kind), cmp.Compare(a.Name, b.Name))
	})
	return out
}

func (c *Cache) podInfo(p *corev1.Pod) PodInfo {
	pi := PodInfo{
		Namespace: p.Namespace, Name: p.Name, Phase: string(p.Status.Phase), Node: p.Spec.NodeName,
		IP: p.Status.PodIP, Labels: p.Labels, Spec: containers(p.Spec),
		Workload: c.TopOwner(p.Namespace, p.OwnerReferences, reports.Resource{Kind: "Pod", Namespace: p.Namespace, Name: p.Name}),
	}
	if p.Status.StartTime != nil {
		t := p.Status.StartTime.Time
		pi.Started = &t
	}
	conv := func(s corev1.ContainerStatus, init bool) PodContainer {
		pc := PodContainer{Name: s.Name, Image: s.Image, Init: init, Ready: s.Ready, Restarts: s.RestartCount}
		if _, d, ok := strings.Cut(s.ImageID, "@"); ok {
			pc.Digest = d
		}
		switch {
		case s.State.Running != nil:
			pc.State = "running"
		case s.State.Waiting != nil:
			pc.State = "waiting: " + s.State.Waiting.Reason
		case s.State.Terminated != nil:
			pc.State = "terminated: " + s.State.Terminated.Reason
		}
		return pc
	}
	for _, s := range p.Status.InitContainerStatuses {
		pi.Containers = append(pi.Containers, conv(s, true))
	}
	for _, s := range p.Status.ContainerStatuses {
		pi.Containers = append(pi.Containers, conv(s, false))
	}
	return pi
}

// Pod returns one pod.
func (c *Cache) Pod(namespace, name string) (PodInfo, bool) {
	o, ok := c.object("Pod", namespace, name)
	if !ok {
		return PodInfo{}, false
	}
	return c.podInfo(o.(*corev1.Pod)), true
}

// Pods returns pods matching the filter (nil = all), sorted by name.
func (c *Cache) Pods(match func(PodInfo) bool) []PodInfo {
	var out []PodInfo
	for _, o := range c.objects("Pod") {
		pi := c.podInfo(o.(*corev1.Pod))
		if match == nil || match(pi) {
			out = append(out, pi)
		}
	}
	slices.SortFunc(out, func(a, b PodInfo) int {
		return cmp.Or(cmp.Compare(a.Namespace, b.Namespace), cmp.Compare(a.Name, b.Name))
	})
	return out
}

func nodeInfo(n *corev1.Node) NodeInfo {
	ni := NodeInfo{
		Name: n.Name, Unschedulable: n.Spec.Unschedulable, Created: n.CreationTimestamp.Time,
		Kubelet: n.Status.NodeInfo.KubeletVersion, OSImage: n.Status.NodeInfo.OSImage,
		Kernel: n.Status.NodeInfo.KernelVersion, Runtime: n.Status.NodeInfo.ContainerRuntimeVersion,
		Arch: n.Status.NodeInfo.Architecture,
	}
	if v, ok := n.Status.Capacity[corev1.ResourceCPU]; ok {
		ni.CPU = v.String()
	}
	if v, ok := n.Status.Capacity[corev1.ResourceMemory]; ok {
		ni.Memory = v.String()
	}
	for k := range n.Labels {
		if r, ok := strings.CutPrefix(k, "node-role.kubernetes.io/"); ok && r != "" {
			ni.Roles = append(ni.Roles, r)
		}
	}
	slices.Sort(ni.Roles)
	for _, cond := range n.Status.Conditions {
		if cond.Type == corev1.NodeReady {
			ni.Ready = cond.Status == corev1.ConditionTrue
		}
	}
	return ni
}

// Nodes lists the nodes with their pod counts.
func (c *Cache) Nodes() []NodeInfo {
	counts := map[string]int{}
	for _, o := range c.objects("Pod") {
		counts[o.(*corev1.Pod).Spec.NodeName]++
	}
	var out []NodeInfo
	for _, o := range c.objects("Node") {
		ni := nodeInfo(o.(*corev1.Node))
		ni.Pods = counts[ni.Name]
		out = append(out, ni)
	}
	slices.SortFunc(out, func(a, b NodeInfo) int { return cmp.Compare(a.Name, b.Name) })
	return out
}

// Node returns one node.
func (c *Cache) Node(name string) (NodeInfo, bool) {
	o, ok := c.object("Node", "", name)
	if !ok {
		return NodeInfo{}, false
	}
	ni := nodeInfo(o.(*corev1.Node))
	for _, p := range c.objects("Pod") {
		if p.(*corev1.Pod).Spec.NodeName == name {
			ni.Pods++
		}
	}
	return ni, true
}

// Namespace returns one namespace.
func (c *Cache) Namespace(name string) (NamespaceInfo, bool) {
	o, ok := c.object("Namespace", "", name)
	if !ok {
		return NamespaceInfo{}, false
	}
	ns := o.(*corev1.Namespace)
	return NamespaceInfo{Name: ns.Name, Phase: string(ns.Status.Phase), Labels: ns.Labels, Created: ns.CreationTimestamp.Time}, true
}

// Namespaces lists all namespaces.
func (c *Cache) Namespaces() []NamespaceInfo {
	var out []NamespaceInfo
	for _, o := range c.objects("Namespace") {
		ns := o.(*corev1.Namespace)
		out = append(out, NamespaceInfo{Name: ns.Name, Phase: string(ns.Status.Phase), Labels: ns.Labels, Created: ns.CreationTimestamp.Time})
	}
	slices.SortFunc(out, func(a, b NamespaceInfo) int { return cmp.Compare(a.Name, b.Name) })
	return out
}
