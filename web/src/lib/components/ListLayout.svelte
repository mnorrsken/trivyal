<script lang="ts">
	// Shared frame for list pages: title, grouping tabs, filter bar, facet
	// sidebar, results and pager. The URL holds all state (ListState).
	import type { Snippet } from 'svelte';
	import type { ListState } from '../list.svelte';
	import type { FacetValue, SchemaField } from '../types';
	import { int } from '../format';
	import Facets from './Facets.svelte';
	import FilterBar from './FilterBar.svelte';
	import Pager from './Pager.svelte';
	import Tabs from './Tabs.svelte';

	let {
		title,
		subtitle,
		ls,
		groups,
		schema,
		facets,
		facetLabels,
		total,
		rows,
		size,
		error,
		loading,
		noun,
		placeholder,
		showStale = true,
		actions,
		children
	}: {
		title: string;
		subtitle?: string;
		ls: ListState;
		groups?: { value: string; label: string }[];
		schema: SchemaField[];
		facets: Record<string, FacetValue[]>;
		facetLabels: Record<string, string>;
		total: number;
		rows?: number;
		size: number;
		error: string | null;
		loading: boolean;
		noun: string;
		placeholder?: string;
		showStale?: boolean;
		actions?: Snippet;
		children: Snippet;
	} = $props();

	let showFacets = $state(false);
</script>

<div class="head">
	<div>
		<h1>{title}</h1>
		{#if subtitle}<p class="muted sub">{subtitle}</p>{/if}
	</div>
	<div class="tools">
		{@render actions?.()}
		{#if groups}
			<Tabs tabs={groups} value={ls.group} onchange={(v) => ls.update({ group: v })} />
		{/if}
	</div>
</div>

<div class="filter">
	<FilterBar
		q={ls.q}
		{schema}
		{facets}
		{error}
		{placeholder}
		onchange={(q, replace) => ls.setQ(q, replace)}
	/>
</div>

<div class="body">
	<aside class:open={showFacets}>
		<Facets q={ls.q} {facets} labels={facetLabels} onchange={(q) => ls.setQ(q)} />
		{#if showStale}
			<label class="stale">
				<input type="checkbox" checked={ls.stale} onchange={(e) => ls.update({ stale: e.currentTarget.checked ? '1' : '' })} />
				Include old ReplicaSets
			</label>
		{/if}
	</aside>
	<section class="results" class:loading>
		<div class="meta">
			<button class="btn facet-toggle" onclick={() => (showFacets = !showFacets)}>Filters</button>
			<span class="muted num">
				{int(total)}
				{noun}{#if rows !== undefined && rows !== total}&nbsp;· {int(rows)} matching rows{/if}
			</span>
		</div>
		<div class="card tablewrap">
			{@render children()}
		</div>
		<Pager page={ls.page} {size} {total} onpage={(p) => ls.update({ page: p })} />
	</section>
</div>

<style>
	.head {
		display: flex;
		align-items: flex-end;
		justify-content: space-between;
		gap: 16px;
		flex-wrap: wrap;
		margin-bottom: 16px;
	}
	h1 {
		font-size: 22px;
		font-weight: 600;
		letter-spacing: -0.01em;
	}
	.sub {
		font-size: 13px;
		margin-top: 2px;
	}
	.tools {
		display: flex;
		gap: 8px;
		align-items: center;
		flex-wrap: wrap;
	}
	.filter {
		margin-bottom: 16px;
	}
	.body {
		display: grid;
		grid-template-columns: 220px minmax(0, 1fr);
		gap: 24px;
		align-items: start;
	}
	aside {
		position: sticky;
		top: 16px;
		max-height: calc(100vh - 32px);
		overflow-y: auto;
		padding-right: 4px;
	}
	.stale {
		display: flex;
		gap: 8px;
		align-items: center;
		margin-top: 18px;
		font-size: 13px;
		color: var(--ink-2);
	}
	.meta {
		display: flex;
		align-items: center;
		gap: 12px;
		font-size: 13px;
		margin-bottom: 8px;
		min-height: 24px;
	}
	.facet-toggle {
		display: none;
	}
	.tablewrap {
		overflow-x: auto;
	}
	.results {
		transition: opacity 0.15s;
	}
	.results.loading {
		opacity: 0.6;
	}
	@media (max-width: 860px) {
		.body {
			grid-template-columns: minmax(0, 1fr);
		}
		aside {
			display: none;
			position: static;
			max-height: none;
		}
		aside.open {
			display: block;
		}
		.facet-toggle {
			display: inline-flex;
			height: 28px;
		}
	}
</style>
