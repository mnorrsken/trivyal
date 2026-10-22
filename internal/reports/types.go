// Package reports holds minimal Go types for the trivy-operator CRDs
// (aquasecurity.github.io/v1alpha1) and converters from unstructured objects.
// Only the fields the UI uses are modelled.
package reports

import (
	"time"
)

// Severity values as written by trivy.
const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
	SeverityUnknown  = "UNKNOWN"
)

// Severities in display order, most severe first.
var Severities = []string{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityUnknown}

// SeverityRank returns a sort key where a lower number is more severe.
func SeverityRank(s string) int {
	for i, v := range Severities {
		if v == s {
			return i
		}
	}
	return len(Severities)
}

// Meta is the object metadata shared by all reports.
type Meta struct {
	Kind        string            `json:"kind"`
	Namespace   string            `json:"namespace,omitempty"`
	Name        string            `json:"name"`
	UID         string            `json:"uid"`
	Labels      map[string]string `json:"-"`
	Annotations map[string]string `json:"-"`
	Owners      []OwnerRef        `json:"owners,omitempty"`
	Created     time.Time         `json:"created"`
}

// OwnerRef is a trimmed metav1.OwnerReference.
type OwnerRef struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
	UID  string `json:"uid"`
}

// Resource is the Kubernetes object a report was made for, read from the
// trivy-operator.resource.* labels and owner references.
type Resource struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
}

func (r Resource) String() string {
	if r.Namespace == "" {
		return r.Kind + "/" + r.Name
	}
	return r.Namespace + "/" + r.Kind + "/" + r.Name
}

type Scanner struct {
	Name    string `json:"name"`
	Vendor  string `json:"vendor"`
	Version string `json:"version"`
}

type Registry struct {
	Server string `json:"server"`
}

type Artifact struct {
	Repository string `json:"repository"`
	Tag        string `json:"tag,omitempty"`
	Digest     string `json:"digest,omitempty"`
}

type OS struct {
	Family string `json:"family,omitempty"`
	Name   string `json:"name,omitempty"`
	EOSL   bool   `json:"eosl,omitempty"`
}

// SeveritySummary is the summary block used by most report kinds.
type SeveritySummary struct {
	Critical int `json:"criticalCount"`
	High     int `json:"highCount"`
	Medium   int `json:"mediumCount"`
	Low      int `json:"lowCount"`
	Unknown  int `json:"unknownCount,omitempty"`
	None     int `json:"noneCount,omitempty"`
}

// Add adds o to s.
func (s *SeveritySummary) Add(o SeveritySummary) {
	s.Critical += o.Critical
	s.High += o.High
	s.Medium += o.Medium
	s.Low += o.Low
	s.Unknown += o.Unknown
	s.None += o.None
}

// Inc counts one finding of severity sev.
func (s *SeveritySummary) Inc(sev string) {
	switch sev {
	case SeverityCritical:
		s.Critical++
	case SeverityHigh:
		s.High++
	case SeverityMedium:
		s.Medium++
	case SeverityLow:
		s.Low++
	default:
		s.Unknown++
	}
}

// Total returns the number of findings with a severity.
func (s SeveritySummary) Total() int {
	return s.Critical + s.High + s.Medium + s.Low + s.Unknown
}

// Report fields common to all namespaced and cluster report kinds.
type Common struct {
	Meta
	Resource  Resource  `json:"resource"`
	Container string    `json:"container,omitempty"`
	Updated   time.Time `json:"updated"`
	Scanner   Scanner   `json:"scanner"`
}

type VulnerabilityReport struct {
	Common
	Registry        Registry        `json:"registry"`
	Artifact        Artifact        `json:"artifact"`
	OS              OS              `json:"os"`
	Summary         SeveritySummary `json:"summary"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

type Vulnerability struct {
	ID               string   `json:"vulnerabilityID"`
	Resource         string   `json:"resource"`
	InstalledVersion string   `json:"installedVersion"`
	FixedVersion     string   `json:"fixedVersion,omitempty"`
	Severity         string   `json:"severity"`
	Title            string   `json:"title,omitempty"`
	Description      string   `json:"description,omitempty"`
	PrimaryLink      string   `json:"primaryLink,omitempty"`
	Links            []string `json:"links,omitempty"`
	Score            *float64 `json:"score,omitempty"`
	Target           string   `json:"target,omitempty"`
	Class            string   `json:"class,omitempty"`
	PackagePath      string   `json:"packagePath,omitempty"`
	PackagePURL      string   `json:"packagePURL,omitempty"`
	PublishedDate    string   `json:"publishedDate,omitempty"`
	LastModifiedDate string   `json:"lastModifiedDate,omitempty"`
}

// CheckReport covers ConfigAudit, RbacAssessment and InfraAssessment reports
// and their cluster-scoped variants, which all share one shape.
type CheckReport struct {
	Common
	Summary SeveritySummary `json:"summary"`
	Checks  []Check         `json:"checks"`
}

type Check struct {
	ID          string   `json:"checkID"`
	Title       string   `json:"title,omitempty"`
	Description string   `json:"description,omitempty"`
	Severity    string   `json:"severity"`
	Category    string   `json:"category,omitempty"`
	Messages    []string `json:"messages,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
	Success     bool     `json:"success"`
}

type ExposedSecretReport struct {
	Common
	Registry Registry        `json:"registry"`
	Artifact Artifact        `json:"artifact"`
	Summary  SeveritySummary `json:"summary"`
	Secrets  []Secret        `json:"secrets"`
}

type Secret struct {
	Target   string `json:"target"`
	RuleID   string `json:"ruleID"`
	Title    string `json:"title"`
	Category string `json:"category"`
	Severity string `json:"severity"`
	Match    string `json:"match"`
}

type SBOMReport struct {
	Common
	Registry Registry    `json:"registry"`
	Artifact Artifact    `json:"artifact"`
	Summary  SBOMSummary `json:"summary"`
	BOM      BOM         `json:"bom"`
}

type SBOMSummary struct {
	Components   int `json:"componentsCount"`
	Dependencies int `json:"dependenciesCount"`
}

// BOM is the part of a CycloneDX document the UI uses. The full document
// is fetched from the API on download, so it is not kept in memory.
type BOM struct {
	Components   []Component  `json:"components"`
	Dependencies []Dependency `json:"dependencies,omitempty"`
}

type Component struct {
	Ref        string     `json:"bom-ref,omitempty"`
	Type       string     `json:"type,omitempty"`
	Group      string     `json:"group,omitempty"`
	Name       string     `json:"name"`
	Version    string     `json:"version,omitempty"`
	PURL       string     `json:"purl,omitempty"`
	Licenses   []string   `json:"licenses,omitempty"`
	Properties []Property `json:"properties,omitempty"`
}

type Property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type Dependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn,omitempty"`
}

type ComplianceReport struct {
	Meta
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	Description string    `json:"description,omitempty"`
	Version     string    `json:"version,omitempty"`
	Platform    string    `json:"platform,omitempty"`
	Type        string    `json:"type,omitempty"`
	Cron        string    `json:"cron,omitempty"`
	ReportType  string    `json:"reportType,omitempty"`
	Updated     time.Time `json:"updated"`
	Pass        int       `json:"passCount"`
	Fail        int       `json:"failCount"`
	Controls    []Control `json:"controls"`
}

// Control merges the spec control with its status (fail count).
type Control struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Severity    string   `json:"severity"`
	Checks      []string `json:"checks,omitempty"`
	TotalFail   *int     `json:"totalFail,omitempty"`
	// Manual is true for controls with no automated checks.
	Manual bool `json:"manual,omitempty"`
}

// Owner is the controller owner of a ReplicaSet or Job, used to map reports
// to the workload a user knows (Deployment, CronJob).
type Owner struct {
	Kind     string
	Name     string
	Replicas *int32
}
