<script lang="ts">
	import type { Snippet } from 'svelte';

	let {
		label,
		value,
		href,
		note,
		children
	}: { label: string; value: string; href?: string; note?: string; children?: Snippet } = $props();
</script>

<svelte:element this={href ? 'a' : 'div'} {href} class="tile card" class:clickable={!!href}>
	<span class="label">{label}</span>
	<span class="value">{value}</span>
	{#if note}<span class="note">{note}</span>{/if}
	{#if children}<div class="extra">{@render children()}</div>{/if}
</svelte:element>

<style>
	.tile {
		display: flex;
		flex-direction: column;
		gap: 2px;
		padding: 14px 16px;
		min-width: 0;
	}
	.clickable:hover {
		border-color: var(--accent);
	}
	.label {
		font-size: 12.5px;
		color: var(--ink-2);
	}
	.value {
		font-size: 28px;
		font-weight: 600;
		letter-spacing: -0.02em;
		line-height: 1.2;
	}
	.note {
		font-size: 12px;
		color: var(--muted);
	}
	.extra {
		margin-top: 8px;
	}
</style>
