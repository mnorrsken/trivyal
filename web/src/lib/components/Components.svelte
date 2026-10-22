<script lang="ts">
	// SBOM components of one image with its own filter (not kept in the URL).
	import { api } from '../api';
	import { Fetcher } from '../fetcher.svelte';
	import { schemas } from '../schema.svelte';
	import type { ComponentGroup, List } from '../types';
	import Empty from './Empty.svelte';
	import FilterBar from './FilterBar.svelte';
	import Pager from './Pager.svelte';

	let { imageKey }: { imageKey: string } = $props();
	let q = $state('');
	let pg = $state(1);
	const size = 100;
	const f = new Fetcher<List<ComponentGroup>>();
	$effect(() => {
		const params = { key: imageKey, q, page: pg, size, group: 'component' };
		f.run(() => api<List<ComponentGroup>>('sbom', params));
	});
	const d = $derived(f.data);
</script>

<div class="bar">
	<FilterBar
		{q}
		schema={schemas.value.sbom}
		facets={d?.facets ?? {}}
		error={f.error}
		placeholder="name:openssl pkgtype:debian license:gpl*"
		onchange={(v) => {
			q = v;
			pg = 1;
		}}
	/>
</div>
{#if d && d.items.length === 0}
	<Empty title="No components match" />
{:else if d}
	<div class="wrap">
		<table class="table">
			<thead><tr><th>Component</th><th>Version</th><th>Type</th><th>Licenses</th></tr></thead>
			<tbody>
				{#each d.items as c (c.name + c.version + c.pkgType)}
					<tr>
						<td class="mono small" title={c.purl}>{c.name}</td>
						<td class="mono small">{c.version}</td>
						<td class="small ink2">{c.pkgType || c.type}</td>
						<td class="small ink2">{c.licenses?.join(', ') ?? ''}</td>
					</tr>
				{/each}
			</tbody>
		</table>
	</div>
	<div class="pager"><Pager page={pg} {size} total={d.total} onpage={(p) => (pg = p)} /></div>
{/if}

<style>
	.bar {
		padding: 12px;
		border-bottom: 1px solid var(--hairline);
	}
	.wrap {
		overflow-x: auto;
	}
	.small {
		font-size: 12px;
	}
	.pager {
		padding: 0 12px 12px;
	}
</style>
