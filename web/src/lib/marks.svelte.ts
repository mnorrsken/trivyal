// The user's flagged and hidden targets. The layout reloads them when the
// server says something changed; changes here refetch pages right away.

import { api, apiSend } from './api';
import { live } from './live.svelte';
import type { MarkInfo, MarkState, MarkTarget, Resource } from './types';

function resourceKey(r?: Resource): string {
	if (!r?.kind || !r.name) return '';
	return r.namespace ? `${r.namespace}/${r.kind}/${r.name}` : `${r.kind}/${r.name}`;
}

/** The target's identity, the same as Target.Key in internal/index. */
export function markKey(t: MarkTarget): string {
	const k = (() => {
		switch (t.kind) {
			case 'image':
				return t.image;
			case 'image-cve':
				return `${t.image}|${t.id}`;
			case 'cve':
				return t.id;
			case 'secret':
				return `${t.image}|${t.rule}|${t.file}`;
			case 'check':
				return `${t.type}|${t.id?.toUpperCase()}`;
			case 'resource-check':
				return `${t.type}|${t.id?.toUpperCase()}|${resourceKey(t.resource)}`;
			case 'workload':
				return resourceKey(t.resource);
			case 'namespace':
				return t.namespace;
		}
	})();
	return t.kind + '|' + (k ?? '');
}

class Marks {
	byKey = $state(new Map<string, MarkInfo>());

	async load() {
		try {
			const list = await api<MarkInfo[]>('marks');
			this.byKey = new Map(list.map((m) => [markKey(m.target), m]));
		} catch {
			/* keep what we had */
		}
	}

	get(t: MarkTarget): MarkInfo | undefined {
		return this.byKey.get(markKey(t));
	}

	/** Flags or hides t. A note of undefined keeps the note it has. */
	async set(target: MarkTarget, state: MarkState, note?: string): Promise<MarkInfo> {
		const m = await apiSend<MarkInfo>('POST', 'marks', { target, state, note });
		live.bump();
		return m;
	}

	async clear(id: number): Promise<void> {
		await apiSend<void>('DELETE', 'marks/' + id);
		live.bump();
	}
}

export const marks = new Marks();
