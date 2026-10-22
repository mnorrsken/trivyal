<script lang="ts">
	// Facet sidebar: click a value to include it, the minus button to exclude
	// it. Counts ignore the facet's own filter so alternatives stay visible.
	import { excluded, has, toggle } from '../filter';
	import { sevLabel } from '../format';
	import type { FacetValue } from '../types';

	let {
		q,
		facets,
		labels,
		onchange
	}: {
		q: string;
		facets: Record<string, FacetValue[]>;
		labels: Record<string, string>;
		onchange: (q: string) => void;
	} = $props();

	let expanded = $state<Record<string, boolean>>({});
	const order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];

	function values(field: string): FacetValue[] {
		const v = facets[field] ?? [];
		if (field === 'sev') return [...v].sort((a, b) => order.indexOf(a.value) - order.indexOf(b.value));
		return v;
	}

	function display(field: string, v: string) {
		if (field === 'sev') return sevLabel(v);
		return v;
	}
</script>

<div class="facets">
	{#each Object.keys(labels) as field (field)}
		{@const vals = values(field)}
		{#if vals.length}
			{@const limit = expanded[field] ? vals.length : 8}
			<section>
				<h3>{labels[field]}</h3>
				<ul>
					{#each vals.slice(0, limit) as v (v.value)}
						{@const on = has(q, field, v.value)}
						{@const off = excluded(q, field, v.value)}
						<li class:on class:off>
							<button class="val" onclick={() => onchange(toggle(q, field, v.value))} title={v.value}>
								<span class="box" aria-hidden="true">{on ? '✓' : ''}</span>
								{#if field === 'sev'}<span class="dot {v.value.toLowerCase()}"></span>{/if}
								<span class="name">{display(field, v.value)}</span>
								<span class="n num">{v.count}</span>
							</button>
							<button
								class="neg"
								title={off ? 'Stop excluding' : 'Exclude'}
								onclick={() => onchange(toggle(q, field, v.value, true))}>−</button
							>
						</li>
					{/each}
				</ul>
				{#if vals.length > 8}
					<button class="more" onclick={() => (expanded[field] = !expanded[field])}>
						{expanded[field] ? 'Show less' : `Show all ${vals.length}`}
					</button>
				{/if}
			</section>
		{/if}
	{/each}
</div>

<style>
	.facets {
		display: flex;
		flex-direction: column;
		gap: 18px;
	}
	h3 {
		font-size: 11px;
		font-weight: 600;
		letter-spacing: 0.04em;
		text-transform: uppercase;
		color: var(--muted);
		margin-bottom: 4px;
	}
	li {
		display: flex;
		align-items: center;
		border-radius: 6px;
	}
	li:hover {
		background: var(--surface-2);
	}
	.val {
		flex: 1;
		min-width: 0;
		display: flex;
		align-items: center;
		gap: 7px;
		padding: 4px 6px;
		font-size: 13px;
		text-align: left;
	}
	.box {
		width: 14px;
		height: 14px;
		border-radius: 4px;
		border: 1px solid var(--axis);
		font-size: 10px;
		line-height: 12px;
		text-align: center;
		color: #fff;
		flex: none;
	}
	.on .box {
		background: var(--accent);
		border-color: var(--accent);
	}
	.off .name {
		text-decoration: line-through;
		color: var(--muted);
	}
	.name {
		flex: 1;
		min-width: 0;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}
	.n {
		color: var(--muted);
		font-size: 12px;
	}
	.neg {
		width: 22px;
		height: 22px;
		margin-right: 2px;
		border-radius: 5px;
		color: var(--muted);
		visibility: hidden;
	}
	li:hover .neg,
	.off .neg {
		visibility: visible;
	}
	.neg:hover {
		background: var(--surface);
		color: var(--ink);
	}
	.dot {
		width: 8px;
		height: 8px;
		border-radius: 999px;
		background: var(--sev-unknown);
		flex: none;
	}
	.dot.critical {
		background: var(--sev-critical);
	}
	.dot.high {
		background: var(--sev-high);
	}
	.dot.medium {
		background: var(--sev-medium);
	}
	.dot.low {
		background: var(--sev-low);
	}
	.more {
		font-size: 12px;
		color: var(--accent-ink);
		padding: 2px 6px;
	}
</style>
