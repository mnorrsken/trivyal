// Types mirror the Go API (internal/api, internal/index, internal/reports).

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';

export interface Counts {
	criticalCount: number;
	highCount: number;
	mediumCount: number;
	lowCount: number;
	unknownCount?: number;
	noneCount?: number;
}

export interface Resource {
	kind: string;
	namespace?: string;
	name: string;
}

export interface Workload extends Resource {
	stale?: boolean;
}

export interface ReportRef {
	type: string;
	namespace?: string;
	name: string;
}

export interface FacetValue {
	value: string;
	count: number;
}

export interface List<T> {
	total: number;
	page: number;
	size: number;
	group: string;
	sort: string;
	rows: number;
	items: T[];
	facets?: Record<string, FacetValue[]>;
}

export interface SchemaField {
	name: string;
	aliases?: string[];
	help: string;
}

export interface OS {
	family?: string;
	name?: string;
	eosl?: boolean;
}

export interface Vulnerability {
	vulnerabilityID: string;
	resource: string;
	installedVersion: string;
	fixedVersion?: string;
	severity: Severity;
	title?: string;
	description?: string;
	primaryLink?: string;
	links?: string[];
	score?: number;
	target?: string;
	class?: string;
	packagePath?: string;
	packagePURL?: string;
	publishedDate?: string;
	lastModifiedDate?: string;
}

export interface ImageUse {
	workload: Workload;
	container?: string;
	report: ReportRef;
}

export interface ImageGroup {
	key: string;
	ref: string;
	digest?: string;
	os: OS;
	counts: Counts;
	fixable: number;
	workloads: Workload[];
	updated: string;
}

export interface WorkloadGroup {
	workload: Workload;
	images: string[];
	counts: Counts;
	fixable: number;
}

export interface CVEGroup {
	id: string;
	severity: Severity;
	title?: string;
	score?: number;
	published?: string;
	link?: string;
	packages: string[];
	images: number;
	workloads: number;
	fixable: boolean;
}

export interface Finding {
	imageKey: string;
	image: string;
	vuln: Vulnerability;
	workloads: Workload[];
}

export interface Check {
	checkID: string;
	title?: string;
	description?: string;
	severity: Severity;
	category?: string;
	messages?: string[];
	remediation?: string;
	success: boolean;
}

export interface ResourceGroup {
	resource: Workload;
	report: ReportRef;
	counts: Counts;
	passed: number;
}

export interface CheckGroup {
	id: string;
	title: string;
	severity: Severity;
	category?: string;
	description?: string;
	remediation?: string;
	failed: number;
	passed: number;
}

export interface CheckFinding {
	resource: Workload;
	report: ReportRef;
	check: Check;
}

export interface Secret {
	target: string;
	ruleID: string;
	title: string;
	category: string;
	severity: Severity;
	match: string;
}

export interface SecretFinding {
	workload: Workload;
	container?: string;
	image: string;
	imageKey: string;
	report: ReportRef;
	secret: Secret;
}

export interface SBOMInfo {
	key: string;
	ref: string;
	digest?: string;
	components: number;
	dependencies: number;
	updated: string;
	report: ReportRef;
	uses: ImageUse[];
}

export interface Component {
	'bom-ref'?: string;
	type?: string;
	group?: string;
	name: string;
	version?: string;
	purl?: string;
	licenses?: string[];
	properties?: { name: string; value: string }[];
}

export interface ComponentGroup {
	name: string;
	version: string;
	type?: string;
	pkgType?: string;
	purl?: string;
	licenses?: string[];
	images: string[];
}

export interface SBOMGroup extends SBOMInfo {
	matched: number;
}

export interface ComplianceSummary {
	name: string;
	id: string;
	title: string;
	pass: number;
	fail: number;
	updated: string;
}

export interface Control {
	id: string;
	name: string;
	description?: string;
	severity: Severity;
	checks?: string[];
	totalFail?: number;
	manual?: boolean;
}

export interface ComplianceReport {
	kind: string;
	name: string;
	id: string;
	title: string;
	description?: string;
	version?: string;
	platform?: string;
	type?: string;
	cron?: string;
	reportType?: string;
	updated: string;
	passCount: number;
	failCount: number;
	controls: Control[];
}

export interface CheckSummary {
	counts: Counts;
	resources: number;
	failing: number;
}

export interface NamespaceSummary {
	namespace: string;
	vulns: Counts;
	config: Counts;
	secrets: number;
	workloads: number;
}

export interface Summary {
	installed: boolean;
	synced: boolean;
	built: string;
	reports: Record<string, number>;
	scanners: string[];
	oldest?: string;
	newest?: string;
	vulns: { counts: Counts; fixable: number; images: number; workloads: number };
	config: CheckSummary;
	rbac: CheckSummary;
	infra: CheckSummary;
	secrets: { counts: Counts; scanned: number; affected: number };
	compliance: ComplianceSummary[] | null;
	topImages: ImageGroup[];
	namespaces: NamespaceSummary[] | null;
	staleWorkloads: number;
}

export interface SearchHit {
	kind: 'namespace' | 'workload' | 'image' | 'cve' | 'check' | 'package' | 'node' | 'pod';
	label: string;
	sub?: string;
	key: string;
}

export interface Container {
	name: string;
	image: string;
	init?: boolean;
	runAsNonRoot?: boolean;
	runAsUser?: number;
	readOnlyRootFilesystem?: boolean;
	privileged?: boolean;
	allowPrivilegeEscalation?: boolean;
	cpuRequest?: string;
	cpuLimit?: string;
	memoryRequest?: string;
	memoryLimit?: string;
}

export interface WorkloadInfo extends Resource {
	labels?: Record<string, string>;
	created: string;
	owner?: Resource;
	replicas?: number;
	ready: number;
	schedule?: string;
	suspended?: boolean;
	lastSchedule?: string;
	serviceAccount?: string;
	hostNetwork?: boolean;
	hostPID?: boolean;
	containers: Container[] | null;
}

export interface WorkloadStat {
	vulns: Counts;
	fixable: number;
	config: Counts;
	secrets: number;
	images: number;
}

export interface WorkloadRow extends WorkloadInfo {
	stats: WorkloadStat;
}

export interface PodContainer {
	name: string;
	image: string;
	digest?: string;
	init?: boolean;
	ready: boolean;
	restarts: number;
	state: string;
}

export interface PodInfo {
	namespace: string;
	name: string;
	phase: string;
	node?: string;
	ip?: string;
	started?: string;
	labels?: Record<string, string>;
	workload: Resource;
	containers: PodContainer[] | null;
	spec: Container[] | null;
}

export interface NodeInfo {
	name: string;
	roles: string[] | null;
	ready: boolean;
	unschedulable?: boolean;
	kubelet: string;
	osImage: string;
	kernel: string;
	runtime: string;
	arch: string;
	cpu: string;
	memory: string;
	created: string;
	pods: number;
}

export interface NamespaceRow {
	name: string;
	phase: string;
	labels?: Record<string, string>;
	created: string;
	workloads: number;
	vulns: Counts;
	config: Counts;
	secrets: number;
}

export interface WorkloadImage {
	container: string;
	key: string;
	ref: string;
	digest?: string;
	os: OS;
	counts: Counts;
	fixable: number;
	hasSbom: boolean;
}
