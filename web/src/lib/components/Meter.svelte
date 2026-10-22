<script lang="ts">
	// Pass ratio meter: filled part in the accent hue on a lighter track of
	// the same hue; the percentage is always printed beside it.
	let { pass, fail }: { pass: number; fail: number } = $props();
	const pct = $derived(pass + fail > 0 ? Math.round((pass / (pass + fail)) * 100) : 0);
</script>

<div class="meter" role="meter" aria-valuenow={pct} aria-valuemin={0} aria-valuemax={100} aria-label="{pct}% passing">
	<div class="fill" style:width="{pct}%"></div>
</div>

<style>
	.meter {
		height: 6px;
		border-radius: 4px;
		background: var(--accent-wash);
		overflow: hidden;
	}
	.fill {
		height: 100%;
		border-radius: 4px;
		background: var(--accent);
	}
</style>
