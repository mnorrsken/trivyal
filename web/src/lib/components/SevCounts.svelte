<script lang="ts">
	// Severity counts as numbers with a colored dot. Zero counts are dimmed
	// rather than hidden so columns line up. href(sev) makes each a link.
	import type { Counts } from '../types';

	let {
		counts,
		href,
		showUnknown = true
	}: { counts: Counts; href?: (sev: string) => string; showUnknown?: boolean } = $props();

	const items = $derived([
		{ k: 'critical', sev: 'CRITICAL', n: counts.criticalCount, t: 'C' },
		{ k: 'high', sev: 'HIGH', n: counts.highCount, t: 'H' },
		{ k: 'medium', sev: 'MEDIUM', n: counts.mediumCount, t: 'M' },
		{ k: 'low', sev: 'LOW', n: counts.lowCount, t: 'L' },
		...(showUnknown ? [{ k: 'unknown', sev: 'UNKNOWN', n: counts.unknownCount ?? 0, t: '?' }] : [])
	]);
</script>

<span class="counts num">
	{#each items as it (it.k)}
		{#if href && it.n > 0}
			<a class="c {it.k}" href={href(it.sev)} title="{it.n} {it.sev.toLowerCase()}"
				><span class="dot"></span>{it.n}</a
			>
		{:else}
			<span class="c {it.k}" class:zero={it.n === 0} title="{it.n} {it.sev.toLowerCase()}"
				><span class="dot"></span>{it.n}</span
			>
		{/if}
	{/each}
</span>

<style>
	.counts {
		display: inline-flex;
		gap: 10px;
		font-size: 13px;
	}
	.c {
		display: inline-flex;
		align-items: center;
		gap: 5px;
		min-width: 34px;
		color: var(--ink);
	}
	a.c:hover {
		text-decoration: underline;
	}
	.zero {
		color: var(--muted);
		opacity: 0.55;
	}
	.dot {
		width: 7px;
		height: 7px;
		border-radius: 999px;
		background: var(--sev-unknown);
		flex: none;
	}
	.critical .dot {
		background: var(--sev-critical);
	}
	.high .dot {
		background: var(--sev-high);
	}
	.medium .dot {
		background: var(--sev-medium);
	}
	.low .dot {
		background: var(--sev-low);
	}
	.zero .dot {
		background: var(--axis);
	}
</style>
