// Display text for the three check report families.

export interface CheckTypeInfo {
	title: string;
	subtitle: string;
	placeholder: string;
	empty: string;
}

export const checkTypes: Record<string, CheckTypeInfo> = {
	config: {
		title: 'Config audit',
		subtitle: 'Misconfigured workloads, services and other resources (ConfigAuditReports).',
		placeholder: 'sev:high kind:Deployment check:KSV-0014',
		empty: 'No misconfigurations found'
	},
	rbac: {
		title: 'RBAC',
		subtitle: 'Risky permissions in Roles and ClusterRoles (RbacAssessmentReports).',
		placeholder: 'sev:critical scope:cluster secrets',
		empty: 'No RBAC findings'
	},
	infra: {
		title: 'Infrastructure',
		subtitle: 'Node and control plane configuration (InfraAssessmentReports).',
		placeholder: 'sev:high kind:Node',
		empty: 'No infrastructure findings'
	}
};
