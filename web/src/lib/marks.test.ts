import { describe, expect, it } from 'vitest';
import { markKey } from './marks.svelte';

describe('markKey', () => {
	it('matches the keys the server stores', () => {
		expect(markKey({ kind: 'image', image: 'registry.example.com/shop/web' })).toBe('image|registry.example.com/shop/web');
		expect(markKey({ kind: 'image-cve', image: 'registry.example.com/shop/web', id: 'CVE-2024-0001' })).toBe(
			'image-cve|registry.example.com/shop/web|CVE-2024-0001'
		);
		expect(markKey({ kind: 'check', type: 'config', id: 'avd-ksv-0014' })).toBe('check|config|AVD-KSV-0014');
		expect(
			markKey({ kind: 'resource-check', type: 'rbac', id: 'AVD-KSV-0041', resource: { kind: 'ClusterRole', name: 'admin' } })
		).toBe('resource-check|rbac|AVD-KSV-0041|ClusterRole/admin');
		expect(markKey({ kind: 'workload', resource: { kind: 'Deployment', namespace: 'shop', name: 'web' } })).toBe(
			'workload|shop/Deployment/web'
		);
		expect(markKey({ kind: 'namespace', namespace: 'demo' })).toBe('namespace|demo');
	});
});
