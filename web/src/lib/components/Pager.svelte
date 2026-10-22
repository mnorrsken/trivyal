<script lang="ts">
	import { int } from '../format';

	let {
		page,
		size,
		total,
		onpage
	}: { page: number; size: number; total: number; onpage: (p: number) => void } = $props();
	const pages = $derived(Math.max(1, Math.ceil(total / size)));
	const from = $derived(total === 0 ? 0 : (page - 1) * size + 1);
	const to = $derived(Math.min(page * size, total));
</script>

{#if total > size}
	<nav class="pager" aria-label="Pages">
		<span class="info num">{int(from)}–{int(to)} of {int(total)}</span>
		<button disabled={page <= 1} onclick={() => onpage(1)} title="First">«</button>
		<button disabled={page <= 1} onclick={() => onpage(page - 1)}>Previous</button>
		<span class="num">{page} / {pages}</span>
		<button disabled={page >= pages} onclick={() => onpage(page + 1)}>Next</button>
		<button disabled={page >= pages} onclick={() => onpage(pages)} title="Last">»</button>
	</nav>
{/if}

<style>
	.pager {
		display: flex;
		align-items: center;
		justify-content: flex-end;
		gap: 8px;
		padding: 12px 0 0;
		font-size: 13px;
		color: var(--ink-2);
	}
	.info {
		margin-right: auto;
		color: var(--muted);
	}
	button {
		height: 30px;
		padding: 0 10px;
		border-radius: 6px;
		border: 1px solid var(--hairline);
		background: var(--surface);
	}
	button:hover:not(:disabled) {
		background: var(--surface-2);
	}
	button:disabled {
		opacity: 0.4;
	}
</style>
