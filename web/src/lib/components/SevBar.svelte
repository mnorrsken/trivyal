<script lang="ts">
	// Stacked severity bar. Width is relative to max so rows compare; the
	// numbers are always shown next to it (SevCounts), the bar adds shape.
	import { total } from '../format';
	import type { Counts } from '../types';

	let {
		counts,
		max = 0,
		height = 8,
		showUnknown = true
	}: { counts: Counts; max?: number; height?: number; showUnknown?: boolean } = $props();

	const parts = $derived(
		[
			{ k: 'critical', n: counts.criticalCount, label: 'Critical' },
			{ k: 'high', n: counts.highCount, label: 'High' },
			{ k: 'medium', n: counts.mediumCount, label: 'Medium' },
			{ k: 'low', n: counts.lowCount, label: 'Low' },
			{ k: 'unknown', n: showUnknown ? (counts.unknownCount ?? 0) : 0, label: 'Unknown' }
		].filter((p) => p.n > 0)
	);
	const sum = $derived(showUnknown ? total(counts) : total(counts) - (counts.unknownCount ?? 0));
	const width = $derived(max > 0 ? Math.max(sum > 0 ? 2 : 0, (sum / max) * 100) : 100);
	const label = $derived(parts.map((p) => `${p.n} ${p.label.toLowerCase()}`).join(', ') || 'none');
</script>

<div class="track" style:height="{height}px" role="img" aria-label={label}>
	<div class="bar" style:width="{width}%">
		{#each parts as p (p.k)}
			<span class="seg {p.k}" style:flex-grow={p.n} title="{p.n} {p.label}"></span>
		{/each}
	</div>
</div>

<style>
	.track {
		width: 100%;
		min-width: 60px;
	}
	.bar {
		display: flex;
		gap: 2px;
		height: 100%;
	}
	.seg {
		flex-basis: 0;
		min-width: 3px;
		height: 100%;
		background: var(--sev-unknown);
	}
	.seg:first-child {
		border-radius: 4px 0 0 4px;
	}
	.seg:last-child {
		border-radius: 0 4px 4px 0;
	}
	.seg:only-child {
		border-radius: 4px;
	}
	.critical {
		background: var(--sev-critical);
	}
	.high {
		background: var(--sev-high);
	}
	.medium {
		background: var(--sev-medium);
	}
	.low {
		background: var(--sev-low);
	}
</style>
