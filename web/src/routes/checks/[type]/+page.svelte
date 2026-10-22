<script lang="ts">
	import { page } from '$app/state';
	import { api } from '#lib/api.ts';
	import { Fetcher } from '#lib/fetcher.svelte.ts';
	import { ListState } from '#lib/list.svelte.ts';
	import { live } from '#lib/live.svelte.ts';
	import { schemas } from '#lib/schema.svelte.ts';
	import { qs, reportHref, total } from '#lib/format.ts';
	import { checkTypes } from '#lib/checks.ts';
	import type { CheckFinding, CheckGroup, List, ResourceGroup } from '#lib/types.ts';
	import Empty from '#lib/components/Empty.svelte';
	import ListLayout from '#lib/components/ListLayout.svelte';
	import SevBadge from '#lib/components/SevBadge.svelte';
	import SevBar from '#lib/components/SevBar.svelte';
	import SevCounts from '#lib/components/SevCounts.svelte';
	import SortTh from '#lib/components/SortTh.svelte';
	import WorkloadLink from '#lib/components/WorkloadLink.svelte';

	type Item = ResourceGroup | CheckGroup | CheckFinding;

	const type = $derived(page.params.type ?? 'config');
	const info = $derived(checkTypes[type] ?? checkTypes.config);
	const ls = new ListState({ group: 'resource' });
	const f = new Fetcher<List<Item>>();

	$effect(() => {
		const p = ls.params;
		const t = type;
		live.generation;
		f.run(() => api<List<Item>>('checks/' + t, p));
	});

	const d = $derived(f.data);
	const sort = $derived(d?.sort ?? '');
	const onsort = (k: string) => ls.toggleSort(k, sort);
	const max = $derived(Math.max(1, ...((d?.items ?? []) as ResourceGroup[]).map((i) => (i.counts ? total(i.counts) : 0))));
	const checkHref = (id: string) => `/checks/${type}/${encodeURIComponent(id)}`;

	const groups = [
		{ value: 'resource', label: 'Resources' },
		{ value: 'check', label: 'Checks' },
		{ value: 'finding', label: 'All findings' }
	];
	const nouns: Record<string, string> = { resource: 'resources', check: 'checks', finding: 'findings' };
	const facetLabels = {
		sev: 'Severity',
		kind: 'Kind',
		ns: 'Namespace',
		category: 'Category',
		status: 'Status',
		scope: 'Scope'
	};
</script>

<svelte:head><title>{info.title} · trivyal</title></svelte:head>

<ListLayout
	title={info.title}
	subtitle={info.subtitle}
	{ls}
	{groups}
	schema={schemas.value.checks}
	facets={d?.facets ?? {}}
	{facetLabels}
	total={d?.total ?? 0}
	rows={d?.rows}
	size={ls.size}
	error={f.error}
	loading={f.loading}
	noun={nouns[d?.group ?? ls.group] ?? 'results'}
	placeholder={info.placeholder}
	showStale={type === 'config'}
>
	{#if d && d.items.length === 0}
		<Empty title={ls.q ? 'Nothing matches' : info.empty} good={!ls.q}>
			{#if ls.q}Try removing a filter.{/if}
		</Empty>
	{:else if d?.group === 'resource'}
		<table class="table">
			<thead>
				<tr>
					<SortTh key="namespace" current={sort} {onsort}>Resource</SortTh>
					<SortTh key="severity" current={sort} {onsort}>Failed checks</SortTh>
					<th>Report</th>
				</tr>
			</thead>
			<tbody>
				{#each d.items as ResourceGroup[] as g (g.report.type + g.report.namespace + g.report.name)}
					<tr>
						<td class="main"><WorkloadLink w={g.resource} /></td>
						<td class="sev">
							<SevCounts counts={g.counts} showUnknown={false} />
							<SevBar counts={g.counts} {max} height={5} showUnknown={false} />
						</td>
						<td class="small"><a class="link" href={reportHref(g.report)}>details</a></td>
					</tr>
				{/each}
			</tbody>
		</table>
	{:else if d?.group === 'check'}
		<table class="table">
			<thead>
				<tr>
					<SortTh key="severity" current={sort} {onsort}>Severity</SortTh>
					<SortTh key="id" current={sort} {onsort}>Check</SortTh>
					<SortTh key="title" current={sort} {onsort}>Title</SortTh>
					<SortTh key="failed" current={sort} {onsort} align="right">Failing</SortTh>
				</tr>
			</thead>
			<tbody>
				{#each d.items as CheckGroup[] as g (g.id)}
					<tr>
						<td><SevBadge severity={g.severity} small /></td>
						<td class="mono small nowrap"><a class="link" href={checkHref(g.id)}>{g.id}</a></td>
						<td class="title">
							<a href={checkHref(g.id)}>{g.title}</a>
							{#if g.description}<div class="muted small trunc">{g.description}</div>{/if}
						</td>
						<td class="r num">
							<a class="link" href={qs({ q: `check:${g.id}` + (ls.q ? ' ' + ls.q : '') })}>{g.failed}</a>
						</td>
					</tr>
				{/each}
			</tbody>
		</table>
	{:else if d?.group === 'finding'}
		<table class="table">
			<thead>
				<tr>
					<SortTh key="severity" current={sort} {onsort}>Severity</SortTh>
					<SortTh key="id" current={sort} {onsort}>Check</SortTh>
					<SortTh key="resource" current={sort} {onsort}>Resource</SortTh>
					<th>Message</th>
				</tr>
			</thead>
			<tbody>
				{#each d.items as CheckFinding[] as x, i (x.report.name + x.check.checkID + i)}
					<tr>
						<td><SevBadge severity={x.check.severity} small /></td>
						<td class="title">
							<a class="link mono small" href={checkHref(x.check.checkID)}>{x.check.checkID}</a>
							<div class="small">{x.check.title}</div>
						</td>
						<td class="main"><WorkloadLink w={x.resource} /></td>
						<td class="small ink2 msg">{x.check.messages?.join(' ') ?? ''}</td>
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
		min-width: 230px;
	}
	.sev :global(.track) {
		margin-top: 6px;
	}
	.small {
		font-size: 12px;
	}
	.nowrap {
		white-space: nowrap;
	}
	.title {
		max-width: 480px;
	}
	.title a:hover {
		text-decoration: underline;
	}
	.msg {
		max-width: 420px;
	}
</style>
