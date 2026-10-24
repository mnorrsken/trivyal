<script lang="ts">
	import { api } from '#lib/api.ts';
	import { Fetcher } from '#lib/fetcher.svelte.ts';
	import { ListState } from '#lib/list.svelte.ts';
	import { live } from '#lib/live.svelte.ts';
	import { schemas } from '#lib/schema.svelte.ts';
	import { ago, int, qs } from '#lib/format.ts';
	import type { ComponentGroup, List, SBOMGroup } from '#lib/types.ts';
	import Empty from '#lib/components/Empty.svelte';
	import ImageName from '#lib/components/ImageName.svelte';
	import ListLayout from '#lib/components/ListLayout.svelte';
	import SortTh from '#lib/components/SortTh.svelte';
	import WorkloadLink from '#lib/components/WorkloadLink.svelte';

	type Item = ComponentGroup | SBOMGroup;

	const ls = new ListState({ group: 'component' });
	const f = new Fetcher<List<Item>>();
	$effect(() => {
		const p = ls.params;
		live.generation;
		f.run(() => api<List<Item>>('sbom', p));
	});
	const d = $derived(f.data);
	const sort = $derived(d?.sort ?? '');
	const onsort = (k: string) => ls.toggleSort(k, sort);

	const q1 = (v: string) => (/[\s,]/.test(v) ? `"${v}"` : v);

	const groups = [
		{ value: 'component', label: 'Components' },
		{ value: 'image', label: 'Images' }
	];
	const facetLabels = { type: 'Type', pkgtype: 'Package type', license: 'License', ns: 'Namespace' };
</script>

<svelte:head><title>SBOM · trivyal</title></svelte:head>

<ListLayout
	title="Software bill of materials"
	subtitle="Every package in every scanned image. Find which images ship a library or license."
	{ls}
	{groups}
	schema={schemas.value.sbom}
	facets={d?.facets ?? {}}
	{facetLabels}
	total={d?.total ?? 0}
	rows={d?.rows}
	size={ls.size}
	error={f.error}
	loading={f.loading}
	noun={(d?.group ?? ls.group) === 'image' ? 'images' : 'component versions'}
	placeholder="name:openssl version:<3.0.13 license:gpl*"
	markable={false}
>
	{#if d && d.items.length === 0}
		<Empty title={ls.q ? 'No components match' : 'No SBOM reports'}>
			{#if ls.q}Try removing a filter.{:else}Enable SBOM generation in trivy-operator to fill this page.{/if}
		</Empty>
	{:else if d?.group === 'image'}
		<table class="table">
			<thead>
				<tr>
					<SortTh key="image" current={sort} {onsort}>Image</SortTh>
					<SortTh key="matched" current={sort} {onsort} align="right">Matching</SortTh>
					<SortTh key="components" current={sort} {onsort} align="right">Components</SortTh>
					<th>Used by</th>
					<th>Scanned</th>
					<th></th>
				</tr>
			</thead>
			<tbody>
				{#each d.items as SBOMGroup[] as g (g.key)}
					<tr>
						<td class="img"><ImageName ref={g.ref} key={g.key} /></td>
						<td class="r num">{int(g.matched)}</td>
						<td class="r num">{int(g.components)}</td>
						<td class="wls">
							{#each g.uses.filter((u) => !u.workload.stale).slice(0, 2) as u (u.report.name)}
								<div><WorkloadLink w={u.workload} /></div>
							{/each}
						</td>
						<td class="small ink2">{ago(g.updated)}</td>
						<td class="small"><a class="link" href="/api/v1/sbom/download{qs({ key: g.key })}" download>CycloneDX</a></td>
					</tr>
				{/each}
			</tbody>
		</table>
	{:else if d}
		<table class="table">
			<thead>
				<tr>
					<SortTh key="name" current={sort} {onsort}>Component</SortTh>
					<SortTh key="version" current={sort} {onsort}>Version</SortTh>
					<SortTh key="pkgtype" current={sort} {onsort}>Type</SortTh>
					<th>Licenses</th>
					<SortTh key="images" current={sort} {onsort} align="right">Images</SortTh>
				</tr>
			</thead>
			<tbody>
				{#each d.items as ComponentGroup[] as c (c.name + c.version + c.pkgType)}
					<tr>
						<td class="mono small name" title={c.purl}>{c.name}</td>
						<td class="mono small">{c.version}</td>
						<td class="small ink2">{c.pkgType || c.type}</td>
						<td class="small ink2 lic">{c.licenses?.join(', ') ?? ''}</td>
						<td class="r num">
							<a class="link" href="/sbom{qs({ q: `name:${q1("=" + c.name)} version:${q1("=" + c.version)}`, group: 'image' })}">{c.images.length}</a>
						</td>
					</tr>
				{/each}
			</tbody>
		</table>
	{/if}
</ListLayout>

<style>
	.small {
		font-size: 12px;
	}
	.img {
		max-width: 380px;
	}
	.wls {
		max-width: 280px;
	}
	.name {
		max-width: 360px;
		word-break: break-all;
	}
	.lic {
		max-width: 260px;
	}
</style>
