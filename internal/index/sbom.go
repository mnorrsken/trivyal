package index

import (
	"cmp"
	"time"

	"github.com/mnorrsken/trivyal/internal/query"
	"github.com/mnorrsken/trivyal/internal/reports"
)

// SBOMInfo is the SBOM of one image, deduplicated by digest.
type SBOMInfo struct {
	Key          string     `json:"key"`
	Ref          string     `json:"ref"`
	Digest       string     `json:"digest,omitempty"`
	Components   int        `json:"components"`
	Dependencies int        `json:"dependencies"`
	Updated      time.Time  `json:"updated"`
	Report       ReportRef  `json:"report"`
	Uses         []ImageUse `json:"uses"`

	bom *reports.BOM
}

// BOM returns the parsed components of the image.
func (i *SBOMInfo) BOM() *reports.BOM { return i.bom }

// ComponentRow is one component of one image.
type ComponentRow struct {
	SBOM *SBOMInfo
	C    *reports.Component
	// PkgType is trivy's package type property (debian, gobinary, jar...).
	PkgType string
	text    string
}

// ComponentSchema lists the filters for SBOM components.
var ComponentSchema = query.Schema{
	{Name: "name", Aliases: []string{"pkg", "package"}, Mode: query.Contains, Help: "component name"},
	{Name: "version", Help: "component version, e.g. <3.0.13"},
	{Name: "type", Help: "CycloneDX type: library, application, operating-system"},
	{Name: "pkgtype", Help: "package type: debian, alpine, gobinary, jar, npm..."},
	{Name: "license", Mode: query.Contains, Help: "license ID or expression"},
	{Name: "purl", Mode: query.Contains, Help: "package URL"},
	{Name: "image", Mode: query.Contains, Help: "image reference"},
	{Name: "ns", Aliases: []string{"namespace"}, Help: "namespace of a workload using the image"},
	{Name: "workload", Mode: query.Contains, Help: "workload using the image"},
}

// ComponentFacets are the fields shown as facets in the UI.
var ComponentFacets = []string{"type", "pkgtype", "license", "ns"}

func (r *ComponentRow) Field(name string) []string {
	switch name {
	case "name":
		if r.C.Group != "" {
			return []string{r.C.Group + "/" + r.C.Name}
		}
		return []string{r.C.Name}
	case "version":
		return []string{r.C.Version}
	case "type":
		return []string{r.C.Type}
	case "pkgtype":
		return []string{r.PkgType}
	case "license":
		return r.C.Licenses
	case "purl":
		return []string{r.C.PURL}
	case "image":
		return []string{r.SBOM.Ref}
	case "ns":
		out := make([]string, 0, len(r.SBOM.Uses))
		for _, u := range r.SBOM.Uses {
			out = append(out, u.Workload.Namespace)
		}
		return out
	case "workload":
		out := make([]string, 0, len(r.SBOM.Uses))
		for _, u := range r.SBOM.Uses {
			out = append(out, u.Workload.Name)
		}
		return out
	}
	return nil
}

func (r *ComponentRow) Text() string { return r.text }

func (s *Snapshot) addSBOM(kind string, r *reports.SBOMReport, w Workload) {
	key := imageKey(r.Registry, r.Artifact)
	info := s.SBOMs[key]
	ref := ReportRef{kind, r.Namespace, r.Name}
	if info == nil || r.Updated.After(info.Updated) {
		var uses []ImageUse
		if info != nil {
			uses = info.Uses
		}
		info = &SBOMInfo{
			Key: key, Ref: ImageRef(r.Registry, r.Artifact), Digest: r.Artifact.Digest,
			Components: r.Summary.Components, Dependencies: r.Summary.Dependencies,
			Updated: r.Updated, Report: ref, Uses: uses, bom: &r.BOM,
		}
		s.SBOMs[key] = info
	}
	info.Uses = append(info.Uses, ImageUse{Workload: w, Container: r.Container, Report: ref})
}

// finishSBOM builds one component row per image and component after all
// reports are in, so an image shared by many workloads is listed once.
func (s *Snapshot) finishSBOM() {
	for _, info := range s.SBOMs {
		for i := range info.bom.Components {
			c := &info.bom.Components[i]
			row := &ComponentRow{SBOM: info, C: c}
			for _, p := range c.Properties {
				// Libraries carry PkgType, application components Type.
				if p.Name == "aquasecurity:trivy:PkgType" || (p.Name == "aquasecurity:trivy:Type" && row.PkgType == "") {
					row.PkgType = p.Value
				}
			}
			row.text = lower(c.Group, c.Name, c.Version, c.PURL, info.Ref)
			s.Components = append(s.Components, row)
		}
	}
}

func allStale(uses []ImageUse) bool {
	if len(uses) == 0 {
		return false
	}
	for _, u := range uses {
		if !u.Workload.Stale {
			return false
		}
	}
	return true
}

// MatchComponents returns the component rows matching q, optionally only
// those of one image (key).
func (s *Snapshot) MatchComponents(q query.Query, withStale bool, key string) ([]*ComponentRow, []query.Row, *query.Matcher) {
	m := query.NewMatcher(q, ComponentSchema)
	var out []*ComponentRow
	var all []query.Row
	for _, r := range s.Components {
		if key != "" && r.SBOM.Key != key {
			continue
		}
		if key == "" && !withStale && allStale(r.SBOM.Uses) {
			continue
		}
		all = append(all, r)
		if m.Match(r) {
			out = append(out, r)
		}
	}
	return out, all, m
}

// ComponentGroup is one component name and version with the images that
// contain it.
type ComponentGroup struct {
	Name     string   `json:"name"`
	Version  string   `json:"version"`
	Type     string   `json:"type,omitempty"`
	PkgType  string   `json:"pkgType,omitempty"`
	PURL     string   `json:"purl,omitempty"`
	Licenses []string `json:"licenses,omitempty"`
	Images   []string `json:"images"`
}

func (g *ComponentGroup) SortKey() string { return g.Name + "@" + g.Version + "|" + g.PkgType }

// GroupByComponent lists each component version once.
func GroupByComponent(rows []*ComponentRow) []*ComponentGroup {
	groups := map[string]*ComponentGroup{}
	seen := map[string]bool{}
	var order []*ComponentGroup
	for _, r := range rows {
		name := r.Field("name")[0]
		k := name + "@" + r.C.Version + "|" + r.PkgType
		g := groups[k]
		if g == nil {
			g = &ComponentGroup{Name: name, Version: r.C.Version, Type: r.C.Type, PkgType: r.PkgType, PURL: r.C.PURL, Licenses: r.C.Licenses}
			groups[k] = g
			order = append(order, g)
		}
		if ik := k + "|" + r.SBOM.Key; !seen[ik] {
			seen[ik] = true
			g.Images = append(g.Images, r.SBOM.Key)
		}
	}
	return order
}

// SBOMGroup is one image with the number of matched components.
type SBOMGroup struct {
	*SBOMInfo
	Matched int `json:"matched"`
}

func (g *SBOMGroup) SortKey() string { return g.Key }

// GroupBySBOM counts matched components per image.
func GroupBySBOM(rows []*ComponentRow) []*SBOMGroup {
	groups := map[string]*SBOMGroup{}
	var order []*SBOMGroup
	for _, r := range rows {
		g := groups[r.SBOM.Key]
		if g == nil {
			g = &SBOMGroup{SBOMInfo: r.SBOM}
			groups[r.SBOM.Key] = g
			order = append(order, g)
		}
		g.Matched++
	}
	return order
}

var (
	ComponentSorts = map[string]func(a, b *ComponentGroup) int{
		"name": func(a, b *ComponentGroup) int {
			return cmp.Or(cmp.Compare(a.Name, b.Name), query.CompareVersions(a.Version, b.Version))
		},
		"images": func(a, b *ComponentGroup) int {
			return cmp.Or(cmp.Compare(len(b.Images), len(a.Images)), cmp.Compare(a.Name, b.Name))
		},
		"version": func(a, b *ComponentGroup) int { return query.CompareVersions(a.Version, b.Version) },
		"pkgtype": func(a, b *ComponentGroup) int {
			return cmp.Or(cmp.Compare(a.PkgType, b.PkgType), cmp.Compare(a.Name, b.Name))
		},
	}
	SBOMSorts = map[string]func(a, b *SBOMGroup) int{
		"image":      func(a, b *SBOMGroup) int { return cmp.Compare(a.Ref, b.Ref) },
		"components": func(a, b *SBOMGroup) int { return cmp.Compare(b.Components, a.Components) },
		"matched":    func(a, b *SBOMGroup) int { return cmp.Or(cmp.Compare(b.Matched, a.Matched), cmp.Compare(a.Ref, b.Ref)) },
	}
)
