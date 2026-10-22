<script lang="ts">
	import { workloadHref } from '../format';
	import type { Workload } from '../types';

	let { w, showNs = true }: { w: Workload; showNs?: boolean } = $props();
</script>

<a class="wl" href={workloadHref(w)} title="{w.kind} {w.namespace ? w.namespace + '/' : ''}{w.name}">
	<span class="kind">{w.kind || '—'}</span>
	<span class="trunc">
		{#if showNs && w.namespace}<span class="muted">{w.namespace}/</span>{/if}{w.name}
	</span>
	{#if w.stale}<span class="pill" title="ReplicaSet scaled to zero (old revision)">old</span>{/if}
</a>

<style>
	.wl {
		display: inline-flex;
		align-items: center;
		gap: 8px;
		max-width: 100%;
		min-width: 0;
	}
	.wl:hover .trunc {
		text-decoration: underline;
		color: var(--accent-ink);
	}
	.kind {
		font-size: 10.5px;
		font-weight: 600;
		letter-spacing: 0.02em;
		color: var(--muted);
		border: 1px solid var(--hairline);
		border-radius: 4px;
		padding: 0 5px;
		line-height: 17px;
		flex: none;
	}
</style>
