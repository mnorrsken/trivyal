package index

import (
	"cmp"
	"slices"

	"github.com/mnorrsken/trivyal/internal/reports"
)

// WorkloadStat sums up all reports of one workload.
type WorkloadStat struct {
	Vulns   reports.SeveritySummary `json:"vulns"`
	Fixable int                     `json:"fixable"`
	Config  reports.SeveritySummary `json:"config"`
	Secrets int                     `json:"secrets"`
	Images  int                     `json:"images"`
}

// WorkloadStats returns stats per workload (key: Resource.String()),
// leaving out old ReplicaSets.
func (s *Snapshot) WorkloadStats() map[string]*WorkloadStat {
	out := map[string]*WorkloadStat{}
	get := func(r reports.Resource) *WorkloadStat {
		k := r.String()
		st := out[k]
		if st == nil {
			st = &WorkloadStat{}
			out[k] = st
		}
		return st
	}
	seen := map[string]bool{}
	for _, r := range s.Vulns {
		w := r.Use.Workload
		if w.Stale {
			continue
		}
		st := get(w.Resource)
		ik := w.String() + "|" + r.Image.Key
		if !seen[ik] {
			seen[ik] = true
			st.Images++
		}
		fk := w.String() + "|" + findingKey(r.Image, r.V)
		if seen[fk] {
			continue
		}
		seen[fk] = true
		st.Vulns.Inc(r.V.Severity)
		if r.V.FixedVersion != "" {
			st.Fixable++
		}
	}
	for _, r := range uniqueChecks(s.Checks) {
		if r.Type != CheckConfig || r.Resource.Stale || r.C.Success {
			continue
		}
		get(r.Resource.Resource).Config.Inc(r.C.Severity)
	}
	for _, r := range s.Secrets {
		if !r.Scan.Workload.Stale {
			get(r.Scan.Workload.Resource).Secrets++
		}
	}
	return out
}

// WorkloadImage is one container image of a workload with its findings.
type WorkloadImage struct {
	Container string                  `json:"container"`
	Key       string                  `json:"key"`
	Ref       string                  `json:"ref"`
	Digest    string                  `json:"digest,omitempty"`
	OS        reports.OS              `json:"os"`
	Counts    reports.SeveritySummary `json:"counts"`
	Fixable   int                     `json:"fixable"`
	HasSBOM   bool                    `json:"hasSbom"`
}

// WorkloadReports is everything trivy found for one workload.
type WorkloadReports struct {
	Images  []*WorkloadImage `json:"images"`
	Config  []*CheckFinding  `json:"config"`
	Secrets []*SecretFinding `json:"secrets"`
	Reports []ReportRef      `json:"reports"`
}

func sameWorkload(w Workload, r reports.Resource) bool {
	return !w.Stale && w.Kind == r.Kind && w.Namespace == r.Namespace && w.Name == r.Name
}

// ForWorkload collects the reports of one workload.
func (s *Snapshot) ForWorkload(res reports.Resource) *WorkloadReports {
	out := &WorkloadReports{Images: []*WorkloadImage{}, Config: []*CheckFinding{}, Secrets: []*SecretFinding{}, Reports: []ReportRef{}}
	refs := map[ReportRef]bool{}
	addRef := func(r ReportRef) {
		if !refs[r] {
			refs[r] = true
			out.Reports = append(out.Reports, r)
		}
	}
	seenImg := map[string]bool{}
	for _, img := range s.Images {
		for _, u := range img.Uses {
			if !sameWorkload(u.Workload, res) {
				continue
			}
			addRef(u.Report)
			k := u.Container + "|" + img.Key
			if seenImg[k] {
				continue
			}
			seenImg[k] = true
			_, sb := s.SBOMs[img.Key]
			out.Images = append(out.Images, &WorkloadImage{
				Container: u.Container, Key: img.Key, Ref: img.Ref, Digest: img.Digest, OS: img.OS,
				Counts: img.Summary, Fixable: img.Fixable, HasSBOM: sb,
			})
		}
	}
	slices.SortFunc(out.Images, func(a, b *WorkloadImage) int { return cmp.Compare(a.Container, b.Container) })
	for _, r := range s.Checks {
		if r.Type == CheckConfig && sameWorkload(r.Resource, res) {
			addRef(r.Report)
			if !r.C.Success && !r.Dup {
				out.Config = append(out.Config, &CheckFinding{Resource: r.Resource, Report: r.Report, Check: r.C})
			}
		}
	}
	slices.SortStableFunc(out.Config, CheckFindingSorts["severity"])
	for _, sc := range s.SecretScans {
		if sameWorkload(sc.Workload, res) {
			addRef(sc.Report)
		}
	}
	for _, r := range s.Secrets {
		if sameWorkload(r.Scan.Workload, res) {
			out.Secrets = append(out.Secrets, SecretFindings([]*SecretRow{r})...)
		}
	}
	for _, info := range s.SBOMs {
		for _, u := range info.Uses {
			if sameWorkload(u.Workload, res) {
				addRef(u.Report)
			}
		}
	}
	// Config audit reports with no failed checks have no rows; find them
	// through the report list.
	for ref, rep := range s.ReportsByRef {
		if cr, ok := rep.(*reports.CheckReport); ok && CheckType(ref.Type) == CheckConfig && len(cr.Checks) == 0 {
			if cr.Resource == res {
				addRef(ref)
			}
		}
	}
	slices.SortFunc(out.Reports, func(a, b ReportRef) int { return cmp.Or(cmp.Compare(a.Type, b.Type), cmp.Compare(a.Name, b.Name)) })
	return out
}

// ChecksFor returns the failed checks of one check family on resources
// matching keep, worst first.
func (s *Snapshot) ChecksFor(typ string, keep func(Workload) bool) []*CheckFinding {
	out := []*CheckFinding{}
	for _, r := range uniqueChecks(s.Checks) {
		if r.Type == typ && !r.C.Success && !r.Resource.Stale && keep(r.Resource) {
			out = append(out, &CheckFinding{Resource: r.Resource, Report: r.Report, Check: r.C})
		}
	}
	slices.SortStableFunc(out, CheckFindingSorts["severity"])
	return out
}

// ImagesByDigest maps image digests to image keys, for linking pod
// containers to their reports.
func (s *Snapshot) ImagesByDigest() map[string]string {
	out := map[string]string{}
	for k, img := range s.Images {
		if img.Digest != "" {
			out[img.Digest] = k
		}
	}
	for k, info := range s.SBOMs {
		if info.Digest != "" {
			out[info.Digest] = k
		}
	}
	return out
}
