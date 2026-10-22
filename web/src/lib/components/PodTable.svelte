<script lang="ts">
	import { ago, podHref } from '../format';
	import type { PodInfo } from '../types';
	import Empty from './Empty.svelte';
	import WorkloadLink from './WorkloadLink.svelte';

	let { pods, showWorkload = false, showNode = true }: { pods: PodInfo[]; showWorkload?: boolean; showNode?: boolean } = $props();
	const restarts = (p: PodInfo) => (p.containers ?? []).reduce((n, c) => n + c.restarts, 0);
	const ready = (p: PodInfo) => {
		const cs = (p.containers ?? []).filter((c) => !c.init);
		return `${cs.filter((c) => c.ready).length}/${cs.length}`;
	};
</script>

{#if pods.length === 0}
	<Empty title="No pods" />
{:else}
	<table class="table">
		<thead>
			<tr>
				<th>Pod</th>
				{#if showWorkload}<th>Workload</th>{/if}
				<th>Status</th>
				<th class="r">Ready</th>
				<th class="r">Restarts</th>
				{#if showNode}<th>Node</th>{/if}
				<th>Started</th>
			</tr>
		</thead>
		<tbody>
			{#each pods as p (p.namespace + p.name)}
				<tr>
					<td class="name"><a class="link" href={podHref(p.namespace, p.name)}>{p.name}</a></td>
					{#if showWorkload}<td class="wl"><WorkloadLink w={p.workload} /></td>{/if}
					<td><span class="pill" class:good={p.phase === 'Running' || p.phase === 'Succeeded'}>{p.phase}</span></td>
					<td class="r num">{ready(p)}</td>
					<td class="r num">{restarts(p)}</td>
					{#if showNode}<td>{#if p.node}<a class="link" href="/node/{encodeURIComponent(p.node)}">{p.node}</a>{/if}</td>{/if}
					<td class="small ink2">{ago(p.started)}</td>
				</tr>
			{/each}
		</tbody>
	</table>
{/if}

<style>
	.name {
		max-width: 360px;
		word-break: break-all;
	}
	.wl {
		max-width: 300px;
	}
	.small {
		font-size: 12px;
	}
</style>
