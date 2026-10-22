package reports

import (
	"encoding/json"
	"fmt"
	"time"
)

// Plural resource names of the trivy-operator CRDs.
const (
	VulnerabilityReports          = "vulnerabilityreports"
	ClusterVulnerabilityReports   = "clustervulnerabilityreports"
	ConfigAuditReports            = "configauditreports"
	ClusterConfigAuditReports     = "clusterconfigauditreports"
	ExposedSecretReports          = "exposedsecretreports"
	RbacAssessmentReports         = "rbacassessmentreports"
	ClusterRbacAssessmentReports  = "clusterrbacassessmentreports"
	InfraAssessmentReports        = "infraassessmentreports"
	ClusterInfraAssessmentReports = "clusterinfraassessmentreports"
	SbomReports                   = "sbomreports"
	ClusterSbomReports            = "clustersbomreports"
	ClusterComplianceReports      = "clustercompliancereports"
)

// Group and Version of the trivy-operator API.
const (
	Group   = "aquasecurity.github.io"
	Version = "v1alpha1"
)

// Resources lists every report resource the UI reads.
var Resources = []string{
	VulnerabilityReports, ClusterVulnerabilityReports,
	ConfigAuditReports, ClusterConfigAuditReports,
	ExposedSecretReports,
	RbacAssessmentReports, ClusterRbacAssessmentReports,
	InfraAssessmentReports, ClusterInfraAssessmentReports,
	SbomReports, ClusterSbomReports,
	ClusterComplianceReports,
}

// Labels set by trivy-operator on reports.
const (
	LabelResourceKind      = "trivy-operator.resource.kind"
	LabelResourceName      = "trivy-operator.resource.name"
	LabelResourceNameHash  = "trivy-operator.resource.name-hash"
	LabelResourceNamespace = "trivy-operator.resource.namespace"
	LabelContainerName     = "trivy-operator.container.name"
)

type rawMeta struct {
	Kind     string `json:"kind"`
	Metadata struct {
		Namespace         string            `json:"namespace"`
		Name              string            `json:"name"`
		UID               string            `json:"uid"`
		Labels            map[string]string `json:"labels"`
		Annotations       map[string]string `json:"annotations"`
		CreationTimestamp time.Time         `json:"creationTimestamp"`
		OwnerReferences   []OwnerRef        `json:"ownerReferences"`
	} `json:"metadata"`
}

func (r rawMeta) meta() Meta {
	return Meta{
		Kind:        r.Kind,
		Namespace:   r.Metadata.Namespace,
		Name:        r.Metadata.Name,
		UID:         r.Metadata.UID,
		Labels:      r.Metadata.Labels,
		Annotations: r.Metadata.Annotations,
		Owners:      r.Metadata.OwnerReferences,
		Created:     r.Metadata.CreationTimestamp,
	}
}

// common builds the shared report fields. The resource comes from the
// labels; when only a name hash is set (long names), the owner reference
// with the matching kind gives the real name.
func (r rawMeta) common(updated *time.Time, scanner Scanner) Common {
	m := r.meta()
	res := Resource{
		Kind:      m.Labels[LabelResourceKind],
		Namespace: m.Labels[LabelResourceNamespace],
		Name:      m.Labels[LabelResourceName],
	}
	if res.Name == "" {
		for _, o := range m.Owners {
			if o.Kind == res.Kind || res.Kind == "" {
				res.Kind, res.Name = o.Kind, o.Name
				break
			}
		}
	}
	if res.Name == "" {
		res.Name = m.Name
	}
	c := Common{Meta: m, Resource: res, Container: m.Labels[LabelContainerName], Scanner: scanner}
	if updated != nil {
		c.Updated = *updated
	} else {
		c.Updated = m.Created
	}
	return c
}

// Each parse function takes the JSON of one object as returned by the API.

func ParseVulnerabilityReport(data []byte) (*VulnerabilityReport, error) {
	var raw struct {
		rawMeta
		Report struct {
			UpdateTimestamp *time.Time      `json:"updateTimestamp"`
			Scanner         Scanner         `json:"scanner"`
			Registry        Registry        `json:"registry"`
			Artifact        Artifact        `json:"artifact"`
			OS              OS              `json:"os"`
			Summary         SeveritySummary `json:"summary"`
			Vulnerabilities []Vulnerability `json:"vulnerabilities"`
		} `json:"report"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("decoding vulnerability report: %w", err)
	}
	rp := raw.Report
	return &VulnerabilityReport{
		Common:          raw.common(rp.UpdateTimestamp, rp.Scanner),
		Registry:        rp.Registry,
		Artifact:        rp.Artifact,
		OS:              rp.OS,
		Summary:         rp.Summary,
		Vulnerabilities: rp.Vulnerabilities,
	}, nil
}

func ParseCheckReport(data []byte) (*CheckReport, error) {
	var raw struct {
		rawMeta
		Report struct {
			UpdateTimestamp *time.Time      `json:"updateTimestamp"`
			Scanner         Scanner         `json:"scanner"`
			Summary         SeveritySummary `json:"summary"`
			Checks          []Check         `json:"checks"`
		} `json:"report"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("decoding check report: %w", err)
	}
	rp := raw.Report
	return &CheckReport{
		Common:  raw.common(rp.UpdateTimestamp, rp.Scanner),
		Summary: rp.Summary,
		Checks:  rp.Checks,
	}, nil
}

func ParseExposedSecretReport(data []byte) (*ExposedSecretReport, error) {
	var raw struct {
		rawMeta
		Report struct {
			UpdateTimestamp *time.Time      `json:"updateTimestamp"`
			Scanner         Scanner         `json:"scanner"`
			Registry        Registry        `json:"registry"`
			Artifact        Artifact        `json:"artifact"`
			Summary         SeveritySummary `json:"summary"`
			Secrets         []Secret        `json:"secrets"`
		} `json:"report"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("decoding exposed secret report: %w", err)
	}
	rp := raw.Report
	return &ExposedSecretReport{
		Common:   raw.common(rp.UpdateTimestamp, rp.Scanner),
		Registry: rp.Registry,
		Artifact: rp.Artifact,
		Summary:  rp.Summary,
		Secrets:  rp.Secrets,
	}, nil
}

func ParseSBOMReport(data []byte) (*SBOMReport, error) {
	var raw struct {
		rawMeta
		Report struct {
			UpdateTimestamp *time.Time      `json:"updateTimestamp"`
			Scanner         Scanner         `json:"scanner"`
			Registry        Registry        `json:"registry"`
			Artifact        Artifact        `json:"artifact"`
			Summary         SBOMSummary     `json:"summary"`
			Components      json.RawMessage `json:"components"`
		} `json:"report"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("decoding sbom report: %w", err)
	}
	rp := raw.Report
	bom, err := parseBOM(rp.Components)
	if err != nil {
		return nil, err
	}
	return &SBOMReport{
		Common:   raw.common(rp.UpdateTimestamp, rp.Scanner),
		Registry: rp.Registry,
		Artifact: rp.Artifact,
		Summary:  rp.Summary,
		BOM:      bom,
	}, nil
}

func parseBOM(data json.RawMessage) (BOM, error) {
	if len(data) == 0 {
		return BOM{}, nil
	}
	var raw struct {
		Components []struct {
			Ref      string `json:"bom-ref"`
			Type     string `json:"type"`
			Group    string `json:"group"`
			Name     string `json:"name"`
			Version  string `json:"version"`
			PURL     string `json:"purl"`
			Licenses []struct {
				License struct {
					ID   string `json:"id"`
					Name string `json:"name"`
				} `json:"license"`
				Expression string `json:"expression"`
			} `json:"licenses"`
			Properties []Property `json:"properties"`
		} `json:"components"`
		Dependencies []Dependency `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return BOM{}, fmt.Errorf("decoding cyclonedx bom: %w", err)
	}
	bom := BOM{Dependencies: raw.Dependencies}
	for _, c := range raw.Components {
		comp := Component{
			Ref: c.Ref, Type: c.Type, Group: c.Group, Name: c.Name,
			Version: c.Version, PURL: c.PURL,
		}
		// Layer digests and package IDs are most of an SBOM's size and the
		// UI does not use them.
		for _, p := range c.Properties {
			switch p.Name {
			case "aquasecurity:trivy:PkgType", "aquasecurity:trivy:Type", "aquasecurity:trivy:Class":
				comp.Properties = append(comp.Properties, p)
			}
		}
		for _, l := range c.Licenses {
			switch {
			case l.Expression != "":
				comp.Licenses = append(comp.Licenses, l.Expression)
			case l.License.ID != "":
				comp.Licenses = append(comp.Licenses, l.License.ID)
			case l.License.Name != "":
				comp.Licenses = append(comp.Licenses, l.License.Name)
			}
		}
		bom.Components = append(bom.Components, comp)
	}
	return bom, nil
}

func ParseComplianceReport(data []byte) (*ComplianceReport, error) {
	var raw struct {
		rawMeta
		Spec struct {
			Cron       string `json:"cron"`
			ReportType string `json:"reportType"`
			Compliance struct {
				ID          string `json:"id"`
				Title       string `json:"title"`
				Description string `json:"description"`
				Version     string `json:"version"`
				Platform    string `json:"platform"`
				Type        string `json:"type"`
				Controls    []struct {
					ID          string `json:"id"`
					Name        string `json:"name"`
					Description string `json:"description"`
					Severity    string `json:"severity"`
					Checks      []struct {
						ID string `json:"id"`
					} `json:"checks"`
				} `json:"controls"`
			} `json:"compliance"`
		} `json:"spec"`
		Status struct {
			UpdateTimestamp *time.Time `json:"updateTimestamp"`
			Summary         struct {
				Pass int `json:"passCount"`
				Fail int `json:"failCount"`
			} `json:"summary"`
			SummaryReport struct {
				ControlCheck []struct {
					ID        string `json:"id"`
					TotalFail *int   `json:"totalFail"`
				} `json:"controlCheck"`
			} `json:"summaryReport"`
			DetailReport struct {
				Results []struct {
					ID     string            `json:"id"`
					Checks []json.RawMessage `json:"checks"`
				} `json:"results"`
			} `json:"detailReport"`
		} `json:"status"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("decoding compliance report: %w", err)
	}
	spec, st := raw.Spec.Compliance, raw.Status
	fails := map[string]*int{}
	for _, c := range st.SummaryReport.ControlCheck {
		fails[c.ID] = c.TotalFail
	}
	for _, r := range st.DetailReport.Results {
		if _, ok := fails[r.ID]; !ok {
			n := len(r.Checks)
			fails[r.ID] = &n
		}
	}
	rep := &ComplianceReport{
		Meta:        raw.meta(),
		ID:          spec.ID,
		Title:       spec.Title,
		Description: spec.Description,
		Version:     spec.Version,
		Platform:    spec.Platform,
		Type:        spec.Type,
		Cron:        raw.Spec.Cron,
		ReportType:  raw.Spec.ReportType,
		Pass:        st.Summary.Pass,
		Fail:        st.Summary.Fail,
	}
	if st.UpdateTimestamp != nil {
		rep.Updated = *st.UpdateTimestamp
	}
	for _, c := range spec.Controls {
		ctl := Control{
			ID: c.ID, Name: c.Name, Description: c.Description,
			Severity: c.Severity, TotalFail: fails[c.ID],
			Manual: len(c.Checks) == 0,
		}
		for _, ch := range c.Checks {
			ctl.Checks = append(ctl.Checks, ch.ID)
		}
		rep.Controls = append(rep.Controls, ctl)
	}
	return rep, nil
}

// Parse decodes the JSON of one object of the given report resource.
func Parse(resource string, data []byte) (any, error) {
	switch resource {
	case VulnerabilityReports, ClusterVulnerabilityReports:
		return ParseVulnerabilityReport(data)
	case ConfigAuditReports, ClusterConfigAuditReports,
		RbacAssessmentReports, ClusterRbacAssessmentReports,
		InfraAssessmentReports, ClusterInfraAssessmentReports:
		return ParseCheckReport(data)
	case ExposedSecretReports:
		return ParseExposedSecretReport(data)
	case SbomReports, ClusterSbomReports:
		return ParseSBOMReport(data)
	case ClusterComplianceReports:
		return ParseComplianceReport(data)
	}
	return nil, fmt.Errorf("unknown report resource %q", resource)
}

// Namespaced reports whether the report resource is namespaced.
func Namespaced(resource string) bool {
	switch resource {
	case VulnerabilityReports, ConfigAuditReports, ExposedSecretReports,
		RbacAssessmentReports, InfraAssessmentReports, SbomReports:
		return true
	}
	return false
}
