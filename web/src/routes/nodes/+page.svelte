<script lang="ts">
	import { api } from '#lib/api.ts';
	import { Fetcher } from '#lib/fetcher.svelte.ts';
	import { live } from '#lib/live.svelte.ts';
	import { ago, memory } from '#lib/format.ts';
	import type { NodeInfo } from '#lib/types.ts';
	import Empty from '#lib/components/Empty.svelte';

	const f = new Fetcher<NodeInfo[]>();
	$effect(() => {
		live.generation;
		f.run(() => api<NodeInfo[]>('nodes'));
	});
</script>

<svelte:head><title>Nodes · trivyal</title></svelte:head>

<h1>Nodes</h1>
<p class="muted sub">Node configuration is checked by trivy's infrastructure assessment.</p>

{#if f.error}
	<div class="card"><Empty title="Could not load nodes">{f.error}</Empty></div>
{:else if f.data}
	<section class="card wrap">
		<table class="table">
			<thead>
				<tr><th>Node</th><th>Status</th><th>Roles</th><th>Kubelet</th><th>OS</th><th>Runtime</th><th class="r">CPU</th><th class="r">Memory</th><th class="r">Pods</th><th>Age</th></tr>
			</thead>
			<tbody>
				{#each f.data as n (n.name)}
					<tr>
						<td><a class="link" href="/node/{encodeURIComponent(n.name)}">{n.name}</a></td>
						<td>
							<span class="pill" class:good={n.ready}>{n.ready ? 'Ready' : 'Not ready'}</span>
							{#if n.unschedulable}<span class="pill">cordoned</span>{/if}
						</td>
						<td class="small">{n.roles?.join(', ') ?? ''}</td>
						<td class="mono small">{n.kubelet}</td>
						<td class="small ink2">{n.osImage} · {n.arch}</td>
						<td class="mono small ink2">{n.runtime}</td>
						<td class="r num">{n.cpu}</td>
						<td class="r num small">{memory(n.memory)}</td>
						<td class="r num">{n.pods}</td>
						<td class="small ink2">{ago(n.created)}</td>
					</tr>
				{/each}
			</tbody>
		</table>
	</section>
{/if}

<style>
	h1 {
		font-size: 22px;
		font-weight: 600;
	}
	.sub {
		font-size: 13px;
		margin: 2px 0 16px;
	}
	.wrap {
		overflow-x: auto;
	}
	.small {
		font-size: 12px;
	}
</style>
