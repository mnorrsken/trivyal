// Filter schemas from the API, loaded once and shared by all list pages.
import { api } from './api';
import type { SchemaField } from './types';

type Schemas = Record<'vulnerabilities' | 'checks' | 'secrets' | 'sbom' | 'workloads', SchemaField[]>;

class SchemaStore {
	value = $state<Schemas>({ vulnerabilities: [], checks: [], secrets: [], sbom: [], workloads: [] });
	#loaded = false;

	load() {
		if (this.#loaded) return;
		this.#loaded = true;
		api<Schemas>('schema')
			.then((s) => (this.value = s))
			.catch(() => (this.#loaded = false));
	}
}

export const schemas = new SchemaStore();
