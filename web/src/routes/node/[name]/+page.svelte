<script lang="ts">
	import { page } from '$app/state';
	import { api } from '#lib/api.ts';
	import { Fetcher } from '#lib/fetcher.svelte.ts';
	import { live } from '#lib/live.svelte.ts';
	import { ago, memory } from '#lib/format.ts';
	import type { CheckFinding, NodeInfo, PodInfo } from '#lib/types.ts';
	import CheckList from '#lib/components/CheckList.svelte';
	import Empty from '#lib/components/Empty.svelte';
	import PodTable from '#lib/components/PodTable.svelte';

	type Detail = NodeInfo & { infra: CheckFinding[]; podList: PodInfo[] };

	const name = $derived(page.params.name ?? '');
	const f = new Fetcher<Detail>();
	$effect(() => {
		const n = name;
		live.generation;
		f.run(() => api<Detail>('node/' + encodeURIComponent(n)));
	});
	const d = $derived(f.data);
</script>

<svelte:head><title>{name} · trivyal</title></svelte:head>

{#if f.error}
	<div class="card"><Empty title="Node not found">{f.error}</Empty></div>
{:else if d}
	<header>
		<p class="crumb muted"><a class="link" href="/nodes">Nodes</a> /</p>
		<h1>{d.name}</h1>
		<div class="facts">
			<span class="pill" class:good={d.ready}>{d.ready ? 'Ready' : 'Not ready'}</span>
			{#if d.unschedulable}<span class="pill">cordoned</span>{/if}
			{#each d.roles ?? [] as r (r)}<span class="pill accent">{r}</span>{/each}
			<span class="pill mono">{d.kubelet}</span>
			<span class="pill">{d.osImage}</span>
			<span class="pill mono">{d.kernel}</span>
			<span class="pill mono">{d.runtime}</span>
			<span class="pill">{d.cpu} CPU · {memory(d.memory)}</span>
			<span class="pill">created {ago(d.created)}</span>
		</div>
	</header>

	<section class="card sec">
		<h2 class="section-title pad">Infrastructure assessment</h2>
		<CheckList findings={d.infra} type="infra" empty="No node configuration findings" />
	</section>

	<section class="card sec">
		<h2 class="section-title pad">Pods ({d.podList.length})</h2>
		<PodTable pods={d.podList} showWorkload showNode={false} />
	</section>
{/if}

<style>
	.crumb {
		font-size: 13px;
		margin-bottom: 4px;
	}
	h1 {
		font-size: 20px;
		font-weight: 600;
	}
	.facts {
		display: flex;
		gap: 6px;
		flex-wrap: wrap;
		margin: 10px 0 16px;
	}
	.sec {
		margin-bottom: 16px;
		overflow-x: auto;
	}
	.pad {
		padding: 16px 16px 4px;
	}
</style>
