import type { Counts, Resource, Severity } from './types';

export const severities: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];

export const sevKey: Record<Severity, keyof Counts> = {
	CRITICAL: 'criticalCount',
	HIGH: 'highCount',
	MEDIUM: 'mediumCount',
	LOW: 'lowCount',
	UNKNOWN: 'unknownCount'
};

export function sevLabel(s: string): string {
	return s.charAt(0) + s.slice(1).toLowerCase();
}

export function total(c: Counts): number {
	return c.criticalCount + c.highCount + c.mediumCount + c.lowCount + (c.unknownCount ?? 0);
}

const compactFmt = new Intl.NumberFormat(undefined, { notation: 'compact', maximumFractionDigits: 1 });
const intFmt = new Intl.NumberFormat();

/** 1,284 / 12.9K: compact only from 10,000 up. */
export function compact(n: number): string {
	return n >= 10000 ? compactFmt.format(n) : intFmt.format(n);
}

export function int(n: number): string {
	return intFmt.format(n);
}

const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' });

export function ago(iso?: string): string {
	if (!iso) return '';
	const t = new Date(iso).getTime();
	if (!t || t < 0) return '';
	const s = (t - Date.now()) / 1000;
	const abs = Math.abs(s);
	if (abs < 60) return rtf.format(Math.round(s), 'second');
	if (abs < 3600) return rtf.format(Math.round(s / 60), 'minute');
	if (abs < 86400) return rtf.format(Math.round(s / 3600), 'hour');
	return rtf.format(Math.round(s / 86400), 'day');
}

export function date(iso?: string): string {
	if (!iso) return '';
	const d = new Date(iso);
	return isNaN(d.getTime()) ? iso : d.toISOString().slice(0, 10);
}

export function shortDigest(d?: string): string {
	if (!d) return '';
	const [algo, hex] = d.includes(':') ? d.split(':') : ['', d];
	return (algo ? algo + ':' : '') + hex.slice(0, 12);
}

/** Splits an image reference into repository and tag for display. */
export function splitImage(ref: string): { repo: string; tag: string } {
	const slash = ref.lastIndexOf('/');
	const colon = ref.lastIndexOf(':');
	if (colon > slash) return { repo: ref.slice(0, colon), tag: ref.slice(colon + 1) };
	return { repo: ref, tag: '' };
}

// Kinds that only have config or RBAC findings; everything else (built-in
// workloads, pods, custom resources that own pods) has a workload page.
const findingKinds = new Set([
	'Service',
	'Ingress',
	'PersistentVolumeClaim',
	'NetworkPolicy',
	'ConfigMap',
	'Secret',
	'ServiceAccount',
	'Role',
	'ClusterRole',
	'RoleBinding',
	'ClusterRoleBinding',
	'LimitRange',
	'ResourceQuota',
	'PodDisruptionBudget',
	'HorizontalPodAutoscaler',
	'CustomResourceDefinition',
	'Namespace'
]);

/**
 * Where a resource links: workloads (built-in or custom resources that own
 * pods) and nodes have pages; other resources link to their findings.
 */
export function workloadHref(w: Resource): string {
	if (w.kind === 'Node') return '/node/' + encodeURIComponent(w.name);
	if (findingKinds.has(w.kind)) {
		const type = w.kind.endsWith('Role') || w.kind.endsWith('RoleBinding') ? 'rbac' : 'config';
		const q = `kind:${w.kind}` + (w.namespace ? ` ns:${w.namespace}` : '') + ` resource:=${w.name}`;
		return `/checks/${type}` + qs({ q, group: 'finding' });
	}
	return `/workload/${encodeURIComponent(w.namespace || '_')}/${encodeURIComponent(w.kind)}/${encodeURIComponent(w.name)}`;
}

export function imageHref(key: string): string {
	return '/image?key=' + encodeURIComponent(key);
}

export function reportHref(r: { type: string; namespace?: string; name: string }): string {
	return '/report/' + [r.type, r.namespace, r.name].filter((p): p is string => !!p).map(encodeURIComponent).join('/');
}

export function qs(params: Record<string, string | number | undefined>): string {
	const sp = new URLSearchParams();
	for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== '') sp.set(k, String(v));
	const s = sp.toString();
	return s ? '?' + s : '';
}

export function podHref(namespace: string, name: string): string {
	return `/pod/${encodeURIComponent(namespace)}/${encodeURIComponent(name)}`;
}

/** Formats a Kubernetes memory quantity ("16432524Ki") as GiB. */
export function memory(q: string): string {
	const m = /^(\d+(?:\.\d+)?)(Ki|Mi|Gi|Ti|K|M|G|T)?$/.exec(q);
	if (!m) return q;
	const mult: Record<string, number> = { Ki: 2 ** 10, Mi: 2 ** 20, Gi: 2 ** 30, Ti: 2 ** 40, K: 1e3, M: 1e6, G: 1e9, T: 1e12 };
	const bytes = Number(m[1]) * (m[2] ? mult[m[2]] : 1);
	return (bytes / 2 ** 30).toFixed(1) + ' GiB';
}
