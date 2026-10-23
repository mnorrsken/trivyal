<script lang="ts">
	import { api } from '#lib/api.ts';
	import { Fetcher } from '#lib/fetcher.svelte.ts';
	import { ListState } from '#lib/list.svelte.ts';
	import { live } from '#lib/live.svelte.ts';
	import { schemas } from '#lib/schema.svelte.ts';
	import { int } from '#lib/format.ts';
	import type { List, SecretFinding } from '#lib/types.ts';
	import Empty from '#lib/components/Empty.svelte';
	import HideButton from '#lib/components/HideButton.svelte';
	import ImageName from '#lib/components/ImageName.svelte';
	import ListLayout from '#lib/components/ListLayout.svelte';
	import SevBadge from '#lib/components/SevBadge.svelte';
	import SortTh from '#lib/components/SortTh.svelte';
	import WorkloadLink from '#lib/components/WorkloadLink.svelte';

	type SecretList = List<SecretFinding> & { scanned: number; clean: number };

	const ls = new ListState();
	const f = new Fetcher<SecretList>();
	$effect(() => {
		const p = ls.params;
		live.generation;
		f.run(() => api<SecretList>('secrets', p));
	});
	const d = $derived(f.data);
	const sort = $derived(d?.sort ?? '');
	const onsort = (k: string) => ls.toggleSort(k, sort);
	let shown = $state<Record<number, boolean>>({});

	const facetLabels = {
		sev: 'Severity',
		category: 'Category',
		rule: 'Rule',
		ns: 'Namespace',
		kind: 'Workload kind'
	};
</script>

<svelte:head><title>Exposed secrets · trivyal</title></svelte:head>

<ListLayout
	title="Exposed secrets"
	subtitle={d ? `${int(d.scanned)} containers scanned, ${int(d.clean)} clean.` : 'Keys, tokens and passwords found in container images.'}
	{ls}
	schema={schemas.value.secrets}
	facets={d?.facets ?? {}}
	{facetLabels}
	total={d?.total ?? 0}
	size={ls.size}
	error={f.error}
	loading={f.loading}
	noun="secrets"
	placeholder="sev:high category:AWS ns:demo"
>
	{#if d && d.items.length === 0}
		<Empty title={ls.q ? 'No secrets match' : 'No exposed secrets found'} good={!ls.q}>
			{#if ls.q}Try removing a filter.{:else}All {int(d.scanned)} scanned container images are clean.{/if}
		</Empty>
	{:else if d}
		<table class="table">
			<thead>
				<tr>
					<SortTh key="severity" current={sort} {onsort}>Severity</SortTh>
					<SortTh key="rule" current={sort} {onsort}>Secret</SortTh>
					<SortTh key="target" current={sort} {onsort}>File</SortTh>
					<SortTh key="workload" current={sort} {onsort}>Workload</SortTh>
					<th>Match</th>
					<th></th>
				</tr>
			</thead>
			<tbody>
				{#each d.items as s, i (s.report.name + s.secret.ruleID + s.secret.target + i)}
					<tr>
						<td><SevBadge severity={s.secret.severity} small /></td>
						<td class="rule">
							{s.secret.title}
							<div class="muted small mono">{s.secret.ruleID} · {s.secret.category}</div>
						</td>
						<td class="mono small file" title={s.secret.target}>{s.secret.target}</td>
						<td class="wl">
							<WorkloadLink w={s.workload} />
							<div class="small"><ImageName ref={s.image} key={s.imageKey} /></div>
						</td>
						<td class="match">
							{#if shown[i]}
								<code class="mono small">{s.secret.match}</code>
							{:else}
								<button class="btn small" onclick={() => (shown[i] = true)}>Show</button>
							{/if}
						</td>
						<td class="r">
							<HideButton target={{ kind: 'secret', image: s.imageName, rule: s.secret.ruleID, file: s.secret.target }} small />
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
	.rule {
		min-width: 200px;
	}
	.file {
		max-width: 320px;
		word-break: break-all;
	}
	.wl {
		max-width: 320px;
	}
	.match {
		max-width: 260px;
	}
	.match code {
		word-break: break-all;
		color: var(--ink-2);
	}
	.btn.small {
		height: 24px;
		font-size: 12px;
		padding: 0 8px;
	}
</style>
