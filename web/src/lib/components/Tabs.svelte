<script lang="ts">
	let {
		tabs,
		value,
		onchange
	}: { tabs: { value: string; label: string }[]; value: string; onchange: (v: string) => void } = $props();
</script>

<div class="tabs" role="tablist">
	{#each tabs as t (t.value)}
		<button role="tab" aria-selected={t.value === value} class:on={t.value === value} onclick={() => onchange(t.value)}
			>{t.label}</button
		>
	{/each}
</div>

<style>
	.tabs {
		display: inline-flex;
		gap: 2px;
		padding: 3px;
		border-radius: 8px;
		background: var(--surface-2);
		flex-wrap: wrap;
	}
	button {
		height: 30px;
		padding: 0 12px;
		border-radius: 6px;
		font-size: 13px;
		color: var(--ink-2);
	}
	button:hover {
		color: var(--ink);
	}
	.on {
		background: var(--surface);
		color: var(--ink);
		font-weight: 500;
		box-shadow: 0 1px 2px rgba(0, 0, 0, 0.08);
	}
</style>
