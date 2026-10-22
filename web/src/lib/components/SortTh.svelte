<script lang="ts">
	// Sortable column header. current is the sort the server applied.
	import type { Snippet } from 'svelte';

	let {
		key,
		current,
		onsort,
		align = 'left',
		children
	}: {
		key: string;
		current: string;
		onsort: (key: string) => void;
		align?: 'left' | 'right';
		children: Snippet;
	} = $props();
	const dir = $derived(current === key ? 'asc' : current === '-' + key ? 'desc' : '');
</script>

<th style:text-align={align} aria-sort={dir === 'asc' ? 'ascending' : dir === 'desc' ? 'descending' : 'none'}>
	<button onclick={() => onsort(key)} class:on={!!dir}>
		{@render children()}<span class="arrow" aria-hidden="true">{dir === 'asc' ? '↓' : dir === 'desc' ? '↑' : '↕'}</span>
	</button>
</th>

<style>
	button {
		display: inline-flex;
		align-items: center;
		gap: 4px;
		font: inherit;
		color: inherit;
	}
	.arrow {
		opacity: 0.35;
		font-size: 11px;
	}
	.on .arrow {
		opacity: 1;
	}
	button:hover .arrow {
		opacity: 0.8;
	}
</style>
