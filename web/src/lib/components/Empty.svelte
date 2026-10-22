<script lang="ts">
	import type { Snippet } from 'svelte';

	let { title, children, good = false }: { title: string; children?: Snippet; good?: boolean } = $props();
</script>

<div class="empty">
	{#if good}
		<svg viewBox="0 0 24 24" aria-hidden="true"
			><circle cx="12" cy="12" r="10" fill="none" stroke="var(--good)" stroke-width="1.8" /><path
				d="M7.5 12.5l3 3 6-6.5"
				fill="none"
				stroke="var(--good)"
				stroke-width="1.8"
				stroke-linecap="round"
				stroke-linejoin="round"
			/></svg
		>
	{/if}
	<p class="t">{title}</p>
	{#if children}<div class="d">{@render children()}</div>{/if}
</div>

<style>
	.empty {
		padding: 48px 24px;
		text-align: center;
	}
	svg {
		width: 32px;
		height: 32px;
		margin: 0 auto 10px;
	}
	.t {
		font-weight: 500;
	}
	.d {
		margin-top: 6px;
		font-size: 13px;
		color: var(--muted);
	}
</style>
