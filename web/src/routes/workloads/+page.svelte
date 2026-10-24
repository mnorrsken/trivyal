<script lang="ts">
	import { api } from '#lib/api.ts';
	import { Fetcher } from '#lib/fetcher.svelte.ts';
	import { ListState } from '#lib/list.svelte.ts';
	import { live } from '#lib/live.svelte.ts';
	import { schemas } from '#lib/schema.svelte.ts';
	import { total } from '#lib/format.ts';
	import type { List, WorkloadRow } from '#lib/types.ts';
	import Empty from '#lib/components/Empty.svelte';
	import ImageName from '#lib/components/ImageName.svelte';
	import ListLayout from '#lib/components/ListLayout.svelte';
	import MarkMenu from '#lib/components/MarkMenu.svelte';
	import SevBar from '#lib/components/SevBar.svelte';
	import SevCounts from '#lib/components/SevCounts.svelte';
	import SortTh from '#lib/components/SortTh.svelte';
	import WorkloadLink from '#lib/components/WorkloadLink.svelte';

	const ls = new ListState();
	const f = new Fetcher<List<WorkloadRow>>();
	$effect(() => {
		const p = ls.params;
		live.generation;
		f.run(() => api<List<WorkloadRow>>('workloads', p));
	});
	const d = $derived(f.data);
	const sort = $derived(d?.sort ?? '');
	const onsort = (k: string) => ls.toggleSort(k, sort);
	const max = $derived(Math.max(1, ...(d?.items ?? []).map((w) => total(w.stats.vulns))));
	const facetLabels = { ns: 'Namespace', kind: 'Kind', sev: 'Has severity', fixable: 'Fixable', secrets: 'Secrets' };
</script>

<svelte:head><title>Workloads · trivyal</title></svelte:head>

<ListLayout
	title="Workloads"
	subtitle="Everything running in the cluster, with what trivy found in it."
	{ls}
	schema={schemas.value.workloads}
	facets={d?.facets ?? {}}
	{facetLabels}
	total={d?.total ?? 0}
	size={ls.size}
	error={f.error}
	loading={f.loading}
	noun="workloads"
	placeholder="ns:demo kind:Deployment sev:critical image:nginx"
	showStale={false}
>
	{#if d && d.items.length === 0}
		<Empty title="No workloads match" />
	{:else if d}
		<table class="table">
			<thead>
				<tr>
					<SortTh key="namespace" current={sort} {onsort}>Workload</SortTh>
					<th class="r">Ready</th>
					<SortTh key="severity" current={sort} {onsort}>Vulnerabilities</SortTh>
					<SortTh key="config" current={sort} {onsort}>Misconfigurations</SortTh>
					<th class="r">Secrets</th>
					<th>Images</th>
					<th></th>
				</tr>
			</thead>
			<tbody>
				{#each d.items as w (w.kind + w.namespace + w.name)}
					<tr>
						<td class="main"><WorkloadLink {w} /></td>
						<td class="r num small">
							{#if w.kind === 'CronJob'}<span class="muted mono">{w.schedule}</span>{:else}{w.ready}/{w.replicas ?? '–'}{/if}
						</td>
						<td class="sev">
							<SevCounts counts={w.stats.vulns} />
							<SevBar counts={w.stats.vulns} {max} height={5} />
						</td>
						<td><SevCounts counts={w.stats.config} showUnknown={false} /></td>
						<td class="r num">{w.stats.secrets || ''}</td>
						<td class="imgs">
							{#each (w.containers ?? []).filter((c) => !c.init) as c (c.name)}
								<div><ImageName ref={c.image} link={false} /></div>
							{/each}
						</td>
						<td class="r mark-col"><MarkMenu target={{ kind: 'workload', resource: { kind: w.kind, namespace: w.namespace, name: w.name } }} contains={w.flagged} row /></td>
					</tr>
				{/each}
			</tbody>
		</table>
	{/if}
</ListLayout>

<style>
	.main {
		min-width: 220px;
		max-width: 360px;
	}
	.sev {
		min-width: 250px;
	}
	.sev :global(.track) {
		margin-top: 6px;
	}
	.imgs {
		max-width: 300px;
	}
	.small {
		font-size: 12px;
	}
</style>
