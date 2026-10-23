package index

import (
	"fmt"
	"slices"
	"strings"

	"github.com/mnorrsken/trivyal/internal/reports"
)

// Kinds of targets a user can hide.
const (
	HideImage         = "image"          // Image (repository without tag)
	HideImageCVE      = "image-cve"      // ID in Image
	HideCVE           = "cve"            // ID everywhere
	HideSecret        = "secret"         // Rule in File of Image
	HideCheck         = "check"          // Type and ID everywhere
	HideResourceCheck = "resource-check" // Type and ID on Resource
	HideWorkload      = "workload"       // everything found on Resource
	HideNamespace     = "namespace"      // everything found in Namespace
)

// Target is something a user can hide. Only the fields its kind needs are
// set.
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
	case HideImage:
		return t.Image, need(t.Image)
	case HideImageCVE:
		return t.Image + "|" + t.ID, need(t.Image, t.ID)
	case HideCVE:
		return t.ID, need(t.ID)
	case HideSecret:
		return t.Image + "|" + t.Rule + "|" + t.File, need(t.Image, t.Rule, t.File)
	case HideCheck:
		return t.Type + "|" + strings.ToUpper(t.ID), need(t.Type, t.ID)
	case HideResourceCheck:
		r := res()
		return t.Type + "|" + strings.ToUpper(t.ID) + "|" + r, need(t.Type, t.ID, r)
	case HideWorkload:
		r := res()
		return r, need(r)
	case HideNamespace:
		return t.Namespace, need(t.Namespace)
	}
	return "", fmt.Errorf("unknown target kind %q", t.Kind)
}

// ParseTarget turns a stored kind and key back into a target.
func ParseTarget(kind, key string) (Target, error) {
	t := Target{Kind: kind}
	var ok bool
	switch kind {
	case HideImage:
		t.Image, ok = key, key != ""
	case HideImageCVE:
		t.Image, t.ID, ok = strings.Cut(key, "|")
	case HideCVE:
		t.ID, ok = key, key != ""
	case HideSecret:
		p := strings.SplitN(key, "|", 3)
		if ok = len(p) == 3; ok {
			t.Image, t.Rule, t.File = p[0], p[1], p[2]
		}
	case HideCheck:
		t.Type, t.ID, ok = strings.Cut(key, "|")
	case HideResourceCheck:
		p := strings.SplitN(key, "|", 3)
		if ok = len(p) == 3; ok {
			t.Type, t.ID = p[0], p[1]
			t.Resource, ok = parseResource(p[2])
		}
	case HideWorkload:
		t.Resource, ok = parseResource(key)
	case HideNamespace:
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

// Mark is a hidden target with the IDs of the findings it had when it was
// hidden. Findings that show up in the target later are not hidden.
type Mark struct {
	Target   Target
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
	case HideImage:
		return r.Image.Name
	case HideImageCVE:
		return r.Image.Name + "|" + r.V.ID
	case HideCVE:
		return r.V.ID
	case HideWorkload:
		return r.Use.Workload.String()
	case HideNamespace:
		return r.Use.Workload.Namespace
	}
	return ""
}

func (r *SecretRow) scope(kind string) string {
	switch kind {
	case HideImage:
		return r.Scan.ImageName
	case HideSecret:
		return r.Scan.ImageName + "|" + r.S.RuleID + "|" + r.S.Target
	case HideWorkload:
		return r.Scan.Workload.String()
	case HideNamespace:
		return r.Scan.Workload.Namespace
	}
	return ""
}

func (r *CheckRow) scope(kind string) string {
	if r.C.Success {
		return "" // only failed checks are findings
	}
	switch kind {
	case HideCheck:
		return r.Type + "|" + strings.ToUpper(r.C.ID)
	case HideResourceCheck:
		return r.Type + "|" + strings.ToUpper(r.C.ID) + "|" + r.Resource.String()
	case HideWorkload:
		return r.Resource.String()
	case HideNamespace:
		return r.Resource.Namespace
	}
	return ""
}

type hideable interface {
	scope(kind string) string
	findingID() string
}

var (
	vulnKinds   = []string{HideImage, HideImageCVE, HideCVE, HideWorkload, HideNamespace}
	secretKinds = []string{HideImage, HideSecret, HideWorkload, HideNamespace}
	checkKinds  = []string{HideCheck, HideResourceCheck, HideWorkload, HideNamespace}
)

// marks indexes marks by kind and key.
type marks map[string]map[string]*Mark

func (ms marks) hidden(r hideable, kinds []string) bool {
	id := ""
	for _, k := range kinds {
		byKey := ms[k]
		if len(byKey) == 0 {
			continue
		}
		key := r.scope(k)
		if key == "" {
			continue
		}
		if m := byKey[key]; m != nil {
			if id == "" {
				id = r.findingID()
			}
			if m.Findings[id] {
				return true
			}
		}
	}
	return false
}

// Findings returns the IDs of the findings target t covers now, sorted.
func (s *Snapshot) Findings(t Target) ([]string, error) {
	key, err := t.Key()
	if err != nil {
		return nil, err
	}
	set := map[string]bool{}
	add := func(r hideable) {
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

// Hide returns a copy of the snapshot without the findings that list
// hides. Counts of images that lost findings are redone from the rows
// that are left.
func (s *Snapshot) Hide(list []Mark) *Snapshot {
	ms := marks{}
	for i := range list {
		m := &list[i]
		key, err := m.Target.Key()
		if err != nil {
			continue
		}
		if ms[m.Target.Kind] == nil {
			ms[m.Target.Kind] = map[string]*Mark{}
		}
		ms[m.Target.Kind][key] = m
	}
	if len(ms) == 0 {
		return s
	}
	v := *s
	v.hidden = true
	touched := map[string]bool{}
	v.Vulns = slices.DeleteFunc(slices.Clone(s.Vulns), func(r *VulnRow) bool {
		h := ms.hidden(r, vulnKinds)
		if h {
			touched[r.Image.Key] = true
		}
		return h
	})
	v.Secrets = slices.DeleteFunc(slices.Clone(s.Secrets), func(r *SecretRow) bool { return ms.hidden(r, secretKinds) })
	v.Checks = slices.DeleteFunc(slices.Clone(s.Checks), func(r *CheckRow) bool { return ms.hidden(r, checkKinds) })
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
