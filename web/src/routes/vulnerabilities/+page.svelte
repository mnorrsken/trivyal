<script lang="ts">
	import { api } from '#lib/api.ts';
	import { Fetcher } from '#lib/fetcher.svelte.ts';
	import { ListState } from '#lib/list.svelte.ts';
	import { live } from '#lib/live.svelte.ts';
	import { schemas } from '#lib/schema.svelte.ts';
	import { date, imageHref, qs, shortDigest, total } from '#lib/format.ts';
	import type { CVEGroup, Finding, ImageGroup, List, WorkloadGroup } from '#lib/types.ts';
	import Empty from '#lib/components/Empty.svelte';
	import ImageName from '#lib/components/ImageName.svelte';
	import ListLayout from '#lib/components/ListLayout.svelte';
	import SevBadge from '#lib/components/SevBadge.svelte';
	import SevBar from '#lib/components/SevBar.svelte';
	import SevCounts from '#lib/components/SevCounts.svelte';
	import SortTh from '#lib/components/SortTh.svelte';
	import WorkloadLink from '#lib/components/WorkloadLink.svelte';

	type Item = ImageGroup | WorkloadGroup | CVEGroup | Finding;

	const ls = new ListState({ group: 'image' });
	const f = new Fetcher<List<Item>>();

	$effect(() => {
		const p = ls.params;
		live.generation;
		f.run(() => api<List<Item>>('vulnerabilities', p));
	});

	const d = $derived(f.data);
	const sort = $derived(d?.sort ?? '');
	const onsort = (k: string) => ls.toggleSort(k, sort);
	const max = $derived(
		Math.max(1, ...((d?.items ?? []) as (ImageGroup | WorkloadGroup)[]).map((i) => (i.counts ? total(i.counts) : 0)))
	);
	const csvHref = $derived('/api/v1/vulnerabilities.csv' + qs({ q: ls.q, stale: ls.stale ? '1' : undefined }));

	const groups = [
		{ value: 'image', label: 'Images' },
		{ value: 'workload', label: 'Workloads' },
		{ value: 'cve', label: 'Vulnerabilities' },
		{ value: 'finding', label: 'All findings' }
	];
	const nouns: Record<string, string> = { image: 'images', workload: 'workloads', cve: 'vulnerabilities', finding: 'findings' };
	const facetLabels = {
		sev: 'Severity',
		fixable: 'Fixable',
		ns: 'Namespace',
		kind: 'Workload kind',
		registry: 'Registry',
		class: 'Package class'
	};
</script>

<svelte:head><title>Vulnerabilities · trivyal</title></svelte:head>

<ListLayout
	title="Vulnerabilities"
	subtitle="Findings are counted once per image, even when several workloads run it."
	{ls}
	{groups}
	schema={schemas.value.vulnerabilities}
	facets={d?.facets ?? {}}
	{facetLabels}
	total={d?.total ?? 0}
	rows={d?.rows}
	size={ls.size}
	error={f.error}
	loading={f.loading}
	noun={nouns[d?.group ?? ls.group] ?? 'results'}
	placeholder="sev:critical,high fixable:yes ns:demo openssl"
>
	{#snippet actions()}
		<a class="btn" href={csvHref} download>Export CSV</a>
	{/snippet}

	{#if d && d.items.length === 0}
		<Empty title="No vulnerabilities match" good={!ls.q}>
			{#if ls.q}Try removing a filter.{/if}
		</Empty>
	{:else if d?.group === 'image'}
		<table class="table">
			<thead>
				<tr>
					<SortTh key="image" current={sort} {onsort}>Image</SortTh>
					<SortTh key="severity" current={sort} {onsort}>Findings</SortTh>
					<SortTh key="fixable" current={sort} {onsort} align="right">Fixable</SortTh>
					<SortTh key="workloads" current={sort} {onsort}>Used by</SortTh>
					<th>OS</th>
				</tr>
			</thead>
			<tbody>
				{#each d.items as ImageGroup[] as g (g.key)}
					<tr>
						<td class="main">
							<ImageName ref={g.ref} key={g.key} />
							<div class="muted mono small">{shortDigest(g.digest)}</div>
						</td>
						<td class="sev">
							<SevCounts counts={g.counts} />
							<SevBar counts={g.counts} {max} height={5} />
						</td>
						<td class="r num">{g.fixable}</td>
						<td class="wls">
							{#each g.workloads.slice(0, 2) as w (w.kind + w.namespace + w.name)}
								<div><WorkloadLink {w} /></div>
							{/each}
							{#if g.workloads.length > 2}
								<a class="muted small" href={imageHref(g.key)}>+{g.workloads.length - 2} more</a>
							{/if}
						</td>
						<td class="ink2 small">
							{g.os.family ?? ''}
							{g.os.name ?? ''}
							{#if g.os.eosl}<span class="pill eosl" title="The OS release no longer gets security updates">EOL</span>{/if}
						</td>
					</tr>
				{/each}
			</tbody>
		</table>
	{:else if d?.group === 'workload'}
		<table class="table">
			<thead>
				<tr>
					<SortTh key="namespace" current={sort} {onsort}>Workload</SortTh>
					<SortTh key="severity" current={sort} {onsort}>Findings</SortTh>
					<SortTh key="fixable" current={sort} {onsort} align="right">Fixable</SortTh>
					<th>Images</th>
				</tr>
			</thead>
			<tbody>
				{#each d.items as WorkloadGroup[] as g (g.workload.kind + g.workload.namespace + g.workload.name)}
					<tr>
						<td class="main"><WorkloadLink w={g.workload} /></td>
						<td class="sev">
							<SevCounts counts={g.counts} />
							<SevBar counts={g.counts} {max} height={5} />
						</td>
						<td class="r num">{g.fixable}</td>
						<td class="imgs">
							{#each g.images as ref (ref)}
								<div><ImageName {ref} link={false} /></div>
							{/each}
						</td>
					</tr>
				{/each}
			</tbody>
		</table>
	{:else if d?.group === 'cve'}
		<table class="table">
			<thead>
				<tr>
					<SortTh key="severity" current={sort} {onsort}>Severity</SortTh>
					<SortTh key="id" current={sort} {onsort}>Vulnerability</SortTh>
					<SortTh key="score" current={sort} {onsort} align="right">Score</SortTh>
					<th>Packages</th>
					<SortTh key="images" current={sort} {onsort} align="right">Images</SortTh>
					<SortTh key="workloads" current={sort} {onsort} align="right">Workloads</SortTh>
					<SortTh key="published" current={sort} {onsort}>Published</SortTh>
				</tr>
			</thead>
			<tbody>
				{#each d.items as CVEGroup[] as g (g.id)}
					<tr>
						<td><SevBadge severity={g.severity} small /></td>
						<td class="main">
							<a class="link mono" href="/cve/{encodeURIComponent(g.id)}">{g.id}</a>
							{#if g.fixable}<span class="pill good">fix available</span>{/if}
							{#if g.title}<div class="ink2 small trunc title" title={g.title}>{g.title}</div>{/if}
						</td>
						<td class="r num">{g.score?.toFixed(1) ?? '—'}</td>
						<td class="mono small pkgs">{g.packages.join(', ')}</td>
						<td class="r num">{g.images}</td>
						<td class="r num">{g.workloads}</td>
						<td class="num small ink2">{date(g.published)}</td>
					</tr>
				{/each}
			</tbody>
		</table>
	{:else if d?.group === 'finding'}
		<table class="table">
			<thead>
				<tr>
					<SortTh key="severity" current={sort} {onsort}>Severity</SortTh>
					<SortTh key="id" current={sort} {onsort}>Vulnerability</SortTh>
					<SortTh key="package" current={sort} {onsort}>Package</SortTh>
					<th>Installed</th>
					<th>Fixed in</th>
					<SortTh key="image" current={sort} {onsort}>Image</SortTh>
					<SortTh key="score" current={sort} {onsort} align="right">Score</SortTh>
				</tr>
			</thead>
			<tbody>
				{#each d.items as Finding[] as x (x.imageKey + x.vuln.vulnerabilityID + x.vuln.resource + x.vuln.installedVersion + x.vuln.target)}
					<tr>
						<td><SevBadge severity={x.vuln.severity} small /></td>
						<td class="main">
							<a class="link mono" href="/cve/{encodeURIComponent(x.vuln.vulnerabilityID)}">{x.vuln.vulnerabilityID}</a>
							{#if x.vuln.title}<div class="ink2 small trunc title" title={x.vuln.title}>{x.vuln.title}</div>{/if}
						</td>
						<td class="mono small">{x.vuln.resource}</td>
						<td class="mono small">{x.vuln.installedVersion}</td>
						<td class="mono small">
							{#if x.vuln.fixedVersion}<span class="fixed">{x.vuln.fixedVersion}</span>{:else}<span class="muted">—</span>{/if}
						</td>
						<td class="imgcol">
							<ImageName ref={x.image} key={x.imageKey} />
							<div class="muted small">{x.workloads.length} workload{x.workloads.length === 1 ? '' : 's'}</div>
						</td>
						<td class="r num">{x.vuln.score?.toFixed(1) ?? '—'}</td>
					</tr>
				{/each}
			</tbody>
		</table>
	{/if}
</ListLayout>

<style>
	.main {
		min-width: 220px;
		max-width: 420px;
	}
	.sev {
		min-width: 250px;
	}
	.sev :global(.track) {
		margin-top: 6px;
	}
	.small {
		font-size: 12px;
	}
	.wls,
	.imgs {
		max-width: 300px;
	}
	.wls div,
	.imgs div {
		line-height: 22px;
	}
	.title {
		max-width: 420px;
		margin-top: 2px;
	}
	.pkgs {
		max-width: 220px;
	}
	.imgcol {
		max-width: 300px;
	}
	.fixed {
		color: var(--good-ink);
	}
	.eosl {
		color: var(--sev-critical);
		margin-left: 4px;
	}
	.pill.good {
		margin-left: 6px;
	}
</style>
