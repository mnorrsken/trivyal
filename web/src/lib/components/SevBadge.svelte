<script lang="ts">
	import { sevLabel } from '../format';

	let { severity, small = false }: { severity: string; small?: boolean } = $props();
	const cls = $derived(severity?.toLowerCase() ?? 'unknown');
</script>

<span class="sev {cls}" class:small>
	<span class="dot" aria-hidden="true"></span>{sevLabel(severity || 'UNKNOWN')}
</span>

<style>
	.sev {
		display: inline-flex;
		align-items: center;
		gap: 6px;
		font-size: 12px;
		font-weight: 500;
		line-height: 20px;
		padding: 0 8px 0 7px;
		border-radius: 999px;
		background: var(--surface-2);
		color: var(--ink-2);
		white-space: nowrap;
	}
	.small {
		font-size: 11px;
		line-height: 18px;
		padding: 0 6px 0 5px;
	}
	.dot {
		width: 8px;
		height: 8px;
		border-radius: 999px;
		background: var(--sev-unknown);
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
	.critical {
		color: var(--ink);
		font-weight: 600;
	}
</style>
