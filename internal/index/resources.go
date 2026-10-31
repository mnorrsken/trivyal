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
	// Flagged is set when a flag covers some of the findings.
	Flagged bool `json:"flagged,omitempty"`
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
		st.Flagged = st.Flagged || r.flagged
		ik := w.String() + "|" + r.Image.Key
		if !seen[ik] {
			seen[ik] = true
			st.Images++
		}
		fk := w.String() + "|" + findingKey(r.Image.Key, r.V)
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
		st := get(r.Resource.Resource)
		st.Config.Inc(r.C.Severity)
		st.Flagged = st.Flagged || r.flagged
	}
	for _, r := range UniqueSecrets(s.Secrets) {
		if !r.Scan.Workload.Stale {
			st := get(r.Scan.Workload.Resource)
			st.Secrets++
			st.Flagged = st.Flagged || r.flagged
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
	Flagged   bool                    `json:"flagged,omitempty"`
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
	slices.SortFunc(out.Images, func(a, b *WorkloadImage) int {
		return cmp.Or(cmp.Compare(a.Container, b.Container), cmp.Compare(a.Key, b.Key))
	})
	if s.hidden || s.flags {
		// What is hidden or flagged can differ per workload: go through this
		// workload's rows, and count them when some are hidden.
		byKey := map[string]*WorkloadImage{}
		for _, wi := range out.Images {
			if s.hidden {
				wi.Counts, wi.Fixable = reports.SeveritySummary{}, 0
			}
			byKey[wi.Container+"|"+wi.Key] = wi
		}
		seen := map[string]bool{}
		for _, r := range s.Vulns {
			if !sameWorkload(r.Use.Workload, res) {
				continue
			}
			k := r.Use.Container + "|" + r.Image.Key
			wi := byKey[k]
			if wi == nil {
				continue
			}
			wi.Flagged = wi.Flagged || r.flagged
			fk := k + "|" + findingKey(r.Image.Key, r.V)
			if !s.hidden || seen[fk] {
				continue
			}
			seen[fk] = true
			wi.Counts.Inc(r.V.Severity)
			if r.V.FixedVersion != "" {
				wi.Fixable++
			}
		}
	}
	for _, r := range s.Checks {
		if r.Type == CheckConfig && sameWorkload(r.Resource, res) {
			addRef(r.Report)
			if !r.C.Success && !r.Dup {
				out.Config = append(out.Config, r.AsFinding())
			}
		}
	}
	slices.SortStableFunc(out.Config, CheckFindingSorts["severity"])
	slices.SortStableFunc(out.Config, FlaggedFirst)
	for _, sc := range s.SecretScans {
		if sameWorkload(sc.Workload, res) {
			addRef(sc.Report)
		}
	}
	for _, r := range UniqueSecrets(s.Secrets) {
		if sameWorkload(r.Scan.Workload, res) {
			out.Secrets = append(out.Secrets, SecretFindings([]*SecretRow{r})...)
		}
	}
	slices.SortFunc(out.Secrets, CompareSecrets)
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
			out = append(out, r.AsFinding())
		}
	}
	slices.SortStableFunc(out, CheckFindingSorts["severity"])
	slices.SortStableFunc(out, FlaggedFirst)
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
