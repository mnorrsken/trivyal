package index

import (
	"fmt"
	"slices"
	"strings"

	"github.com/mnorrsken/trivyal/internal/reports"
)

// Kinds of targets a user can flag or hide.
const (
	TargetImage         = "image"          // Image (repository without tag)
	TargetImageCVE      = "image-cve"      // ID in Image
	TargetCVE           = "cve"            // ID everywhere
	TargetSecret        = "secret"         // Rule in File of Image
	TargetCheck         = "check"          // Type and ID everywhere
	TargetResourceCheck = "resource-check" // Type and ID on Resource
	TargetWorkload      = "workload"       // everything found on Resource
	TargetNamespace     = "namespace"      // everything found in Namespace
)

// Target is something a user can flag or hide. Only the fields its kind
// needs are set.
type Target struct {
	Kind      string            `json:"kind"`
	Image     string            `json:"image,omitempty"`
	ID        string            `json:"id,omitempty"`
	Type      string            `json:"type,omitempty"`
	Rule      string            `json:"rule,omitempty"`
	File      string            `json:"file,omitempty"`
	Resource  *reports.Resource `json:"resource,omitempty"`
	Namespace string            `json:"namespace,omitempty"`
}

// Key is the target's identity, the form it is stored in.
func (t Target) Key() (string, error) {
	need := func(vals ...string) error {
		if slices.Contains(vals, "") {
			return fmt.Errorf("%s target is missing a field", t.Kind)
		}
		return nil
	}
	res := func() string {
		if t.Resource == nil || t.Resource.Kind == "" || t.Resource.Name == "" {
			return ""
		}
		return t.Resource.String()
	}
	switch t.Kind {
	case TargetImage:
		return t.Image, need(t.Image)
	case TargetImageCVE:
		return t.Image + "|" + t.ID, need(t.Image, t.ID)
	case TargetCVE:
		return t.ID, need(t.ID)
	case TargetSecret:
		return t.Image + "|" + t.Rule + "|" + t.File, need(t.Image, t.Rule, t.File)
	case TargetCheck:
		return t.Type + "|" + strings.ToUpper(t.ID), need(t.Type, t.ID)
	case TargetResourceCheck:
		r := res()
		return t.Type + "|" + strings.ToUpper(t.ID) + "|" + r, need(t.Type, t.ID, r)
	case TargetWorkload:
		r := res()
		return r, need(r)
	case TargetNamespace:
		return t.Namespace, need(t.Namespace)
	}
	return "", fmt.Errorf("unknown target kind %q", t.Kind)
}

// ParseTarget turns a stored kind and key back into a target.
func ParseTarget(kind, key string) (Target, error) {
	t := Target{Kind: kind}
	var ok bool
	switch kind {
	case TargetImage:
		t.Image, ok = key, key != ""
	case TargetImageCVE:
		t.Image, t.ID, ok = strings.Cut(key, "|")
	case TargetCVE:
		t.ID, ok = key, key != ""
	case TargetSecret:
		p := strings.SplitN(key, "|", 3)
		if ok = len(p) == 3; ok {
			t.Image, t.Rule, t.File = p[0], p[1], p[2]
		}
	case TargetCheck:
		t.Type, t.ID, ok = strings.Cut(key, "|")
	case TargetResourceCheck:
		p := strings.SplitN(key, "|", 3)
		if ok = len(p) == 3; ok {
			t.Type, t.ID = p[0], p[1]
			t.Resource, ok = parseResource(p[2])
		}
	case TargetWorkload:
		t.Resource, ok = parseResource(key)
	case TargetNamespace:
		t.Namespace, ok = key, key != ""
	}
	if !ok {
		return Target{}, fmt.Errorf("bad %s key %q", kind, key)
	}
	return t, nil
}

// parseResource reverses reports.Resource.String.
func parseResource(s string) (*reports.Resource, bool) {
	switch p := strings.Split(s, "/"); len(p) {
	case 2:
		return &reports.Resource{Kind: p[0], Name: p[1]}, p[0] != "" && p[1] != ""
	case 3:
		return &reports.Resource{Namespace: p[0], Kind: p[1], Name: p[2]}, p[1] != "" && p[2] != ""
	}
	return nil, false
}

// Mark flags or hides a target. A hide covers the findings the target had
// when it was hidden (Findings), so findings that show up later are not
// hidden. A flag covers everything in the target, now and later.
type Mark struct {
	Target   Target
	Flag     bool
	Findings map[string]bool
}

// Finding IDs leave out the image digest and tag, so a new build of an
// image with the same packages stays hidden.

func (r *VulnRow) findingID() string {
	return "vuln|" + r.V.ID + "|" + r.V.Resource + "|" + r.V.InstalledVersion
}

func (r *SecretRow) findingID() string {
	return "secret|" + r.S.RuleID + "|" + r.S.Target + "|" + r.S.Match
}

func (r *CheckRow) findingID() string {
	return "check|" + r.Type + "|" + strings.ToUpper(r.C.ID) + "|" + r.Resource.String()
}

// scope returns the key of the target of this kind that covers the row, or
// "" when no target of the kind does.
func (r *VulnRow) scope(kind string) string {
	switch kind {
	case TargetImage:
		return r.Image.Name
	case TargetImageCVE:
		return r.Image.Name + "|" + r.V.ID
	case TargetCVE:
		return r.V.ID
	case TargetWorkload:
		return r.Use.Workload.String()
	case TargetNamespace:
		return r.Use.Workload.Namespace
	}
	return ""
}

func (r *SecretRow) scope(kind string) string {
	switch kind {
	case TargetImage:
		return r.Scan.ImageName
	case TargetSecret:
		return r.Scan.ImageName + "|" + r.S.RuleID + "|" + r.S.Target
	case TargetWorkload:
		return r.Scan.Workload.String()
	case TargetNamespace:
		return r.Scan.Workload.Namespace
	}
	return ""
}

func (r *CheckRow) scope(kind string) string {
	if r.C.Success {
		return "" // only failed checks are findings
	}
	switch kind {
	case TargetCheck:
		return r.Type + "|" + strings.ToUpper(r.C.ID)
	case TargetResourceCheck:
		return r.Type + "|" + strings.ToUpper(r.C.ID) + "|" + r.Resource.String()
	case TargetWorkload:
		return r.Resource.String()
	case TargetNamespace:
		return r.Resource.Namespace
	}
	return ""
}

type markable interface {
	scope(kind string) string
	findingID() string
}

var (
	vulnKinds   = []string{TargetImage, TargetImageCVE, TargetCVE, TargetWorkload, TargetNamespace}
	secretKinds = []string{TargetImage, TargetSecret, TargetWorkload, TargetNamespace}
	checkKinds  = []string{TargetCheck, TargetResourceCheck, TargetWorkload, TargetNamespace}
)

// marks indexes marks by kind and key.
type marks map[string]map[string]*Mark

func (ms marks) add(m *Mark) {
	key, err := m.Target.Key()
	if err != nil {
		return
	}
	if ms[m.Target.Kind] == nil {
		ms[m.Target.Kind] = map[string]*Mark{}
	}
	ms[m.Target.Kind][key] = m
}

// find returns the first mark of kinds covering r for which match is true.
func (ms marks) find(r markable, kinds []string, match func(*Mark) bool) bool {
	for _, k := range kinds {
		if len(ms[k]) == 0 {
			continue
		}
		if key := r.scope(k); key != "" {
			if m := ms[k][key]; m != nil && match(m) {
				return true
			}
		}
	}
	return false
}

// hidden reports whether a hide covers the finding of r.
func (ms marks) hidden(r markable, kinds []string) bool {
	id := ""
	return ms.find(r, kinds, func(m *Mark) bool {
		if id == "" {
			id = r.findingID()
		}
		return m.Findings[id]
	})
}

// flagged reports whether a flag covers r.
func (ms marks) flagged(r markable, kinds []string) bool {
	return ms.find(r, kinds, func(*Mark) bool { return true })
}

// Findings returns the IDs of the findings target t covers now, sorted.
func (s *Snapshot) Findings(t Target) ([]string, error) {
	key, err := t.Key()
	if err != nil {
		return nil, err
	}
	set := map[string]bool{}
	add := func(r markable) {
		if r.scope(t.Kind) == key {
			set[r.findingID()] = true
		}
	}
	for _, r := range s.Vulns {
		add(r)
	}
	for _, r := range s.Secrets {
		add(r)
	}
	for _, r := range s.Checks {
		add(r)
	}
	out := make([]string, 0, len(set))
	for id := range set {
		out = append(out, id)
	}
	slices.Sort(out)
	return out, nil
}

// filterRows drops the rows hidden finds and copies the rows flagged finds
// with flag set; the original rows are shared with other users' views.
func filterRows[R any](rows []R, hidden, flagged func(R) bool, flag func(R) R) []R {
	out := make([]R, 0, len(rows))
	for _, r := range rows {
		switch {
		case hidden(r):
		case flagged(r):
			out = append(out, flag(r))
		default:
			out = append(out, r)
		}
	}
	return out
}

// Apply returns a copy of the snapshot without the findings that list
// hides and with the findings it flags marked as flagged. A hide wins over
// a flag. Counts of images that lost findings are redone from the rows that
// are left.
func (s *Snapshot) Apply(list []Mark) *Snapshot {
	hides, flags := marks{}, marks{}
	for i := range list {
		if list[i].Flag {
			flags.add(&list[i])
		} else {
			hides.add(&list[i])
		}
	}
	if len(hides) == 0 && len(flags) == 0 {
		return s
	}
	v := *s
	v.hidden, v.flags = len(hides) > 0, len(flags) > 0
	touched := map[string]bool{}
	v.Vulns = filterRows(s.Vulns,
		func(r *VulnRow) bool {
			h := hides.hidden(r, vulnKinds)
			if h {
				touched[r.Image.Key] = true
			}
			return h
		},
		func(r *VulnRow) bool { return flags.flagged(r, vulnKinds) },
		func(r *VulnRow) *VulnRow { c := *r; c.flagged = true; return &c })
	v.Secrets = filterRows(s.Secrets,
		func(r *SecretRow) bool { return hides.hidden(r, secretKinds) },
		func(r *SecretRow) bool { return flags.flagged(r, secretKinds) },
		func(r *SecretRow) *SecretRow { c := *r; c.flagged = true; return &c })
	v.Checks = filterRows(s.Checks,
		func(r *CheckRow) bool { return hides.hidden(r, checkKinds) },
		func(r *CheckRow) bool { return flags.flagged(r, checkKinds) },
		func(r *CheckRow) *CheckRow { c := *r; c.flagged = true; return &c })
	if len(touched) == 0 {
		return &v
	}

	v.Images = make(map[string]*Image, len(s.Images))
	for k, img := range s.Images {
		if !touched[k] {
			v.Images[k] = img
			continue
		}
		c := *img
		c.Summary, c.Fixable, c.vulns = reports.SeveritySummary{}, 0, nil
		v.Images[k] = &c
	}
	seen := map[string]bool{}
	for _, r := range v.Vulns {
		if !touched[r.Image.Key] {
			continue
		}
		fk := findingKey(r.Image, r.V)
		if seen[fk] {
			continue
		}
		seen[fk] = true
		img := v.Images[r.Image.Key]
		img.Summary.Inc(r.V.Severity)
		if r.V.FixedVersion != "" {
			img.Fixable++
		}
		img.vulns = append(img.vulns, *r.V)
	}
	return &v
}
