package kube

import (
	"encoding/json"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"

	"github.com/mnorrsken/trivyal/internal/reports"
)

// isScanJob reports whether trivy-operator created the job to scan images
// or collect node settings.
func isScanJob(j *batchv1.Job) bool {
	if j.Labels[reports.LabelManagedBy] != reports.ManagedByTrivyOperator {
		return false
	}
	_, vuln := j.Labels[reports.LabelVulnScanner]
	_, node := j.Labels[reports.LabelNodeInfoCollector]
	return vuln || node
}

// trimScanJob keeps what the scans list shows from a scan job.
func trimScanJob(j *batchv1.Job) *batchv1.Job {
	m := trimMeta(j.ObjectMeta)
	m.Labels, m.CreationTimestamp = j.Labels, j.CreationTimestamp
	for _, k := range []string{reports.AnnotationContainerImages, reports.LabelResourceName} {
		if v, ok := j.Annotations[k]; ok {
			if m.Annotations == nil {
				m.Annotations = map[string]string{}
			}
			m.Annotations[k] = v
		}
	}
	return &batchv1.Job{ObjectMeta: m, Status: batchv1.JobStatus{
		Conditions: j.Status.Conditions, StartTime: j.Status.StartTime, CompletionTime: j.Status.CompletionTime,
	}}
}

// scanJob converts a trimmed scan job.
func scanJob(j *batchv1.Job) reports.ScanJob {
	sj := reports.ScanJob{
		Namespace: j.Namespace, Name: j.Name, Type: reports.JobVulnerability, State: reports.JobRunning,
		Resource: reports.Resource{
			Kind:      j.Labels[reports.LabelResourceKind],
			Namespace: j.Labels[reports.LabelResourceNamespace],
			Name:      j.Labels[reports.LabelResourceName],
		},
		Started: j.CreationTimestamp.Time,
	}
	// Names that are not valid label values are in an annotation.
	if sj.Resource.Name == "" {
		sj.Resource.Name = j.Annotations[reports.LabelResourceName]
	}
	if _, ok := j.Labels[reports.LabelNodeInfoCollector]; ok {
		sj.Type = reports.JobInfra
		if sj.Resource.Kind == "" {
			sj.Resource.Kind = "Node"
		}
	}
	if v := j.Annotations[reports.AnnotationContainerImages]; v != "" {
		_ = json.Unmarshal([]byte(v), &sj.Images)
	}
	if t := j.Status.StartTime; t != nil {
		sj.Started = t.Time
	}
	for _, c := range j.Status.Conditions {
		if c.Status != corev1.ConditionTrue {
			continue
		}
		switch c.Type {
		case batchv1.JobComplete:
			sj.State, sj.Finished = reports.JobDone, finished(j, c)
		case batchv1.JobFailed:
			sj.State, sj.Finished, sj.Message = reports.JobFailed, finished(j, c), c.Message
			if sj.Message == "" {
				sj.Message = c.Reason
			}
		}
	}
	return sj
}

func finished(j *batchv1.Job, c batchv1.JobCondition) time.Time {
	if j.Status.CompletionTime != nil {
		return j.Status.CompletionTime.Time
	}
	return c.LastTransitionTime.Time
}

// ScanJobs returns trivy-operator's scan jobs.
func (c *Cache) ScanJobs() []reports.ScanJob {
	var out []reports.ScanJob
	for _, o := range c.jobInf.GetStore().List() {
		if j, ok := o.(*batchv1.Job); ok && isScanJob(j) {
			out = append(out, scanJob(j))
		}
	}
	return out
}
