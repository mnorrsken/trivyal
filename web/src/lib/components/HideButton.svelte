<script lang="ts">
	// "Hide" button that opens a small form for an optional note. What is
	// hidden now stays hidden; findings that turn up later show again.
	import { hide } from '../hidden';
	import type { HideTarget } from '../types';

	let { target, label = 'Hide', small = false }: { target: HideTarget; label?: string; small?: boolean } = $props();

	let open = $state(false);
	let note = $state('');
	let busy = $state(false);
	let error = $state<string | null>(null);

	async function save() {
		busy = true;
		error = null;
		try {
			await hide(target, note.trim());
			open = false;
			note = '';
		} catch (e) {
			error = e instanceof Error ? e.message : String(e);
		} finally {
			busy = false;
		}
	}

	function onkey(e: KeyboardEvent) {
		if (e.key === 'Enter') save();
		if (e.key === 'Escape') open = false;
	}
</script>

<!-- Clicks stay here: some rows expand on click. -->
<!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_static_element_interactions -->
<span class="hide" onclick={(e) => e.stopPropagation()}>
	{#if open}
		<!-- svelte-ignore a11y_autofocus -->
		<input class="note" class:small placeholder="Note (optional)" bind:value={note} onkeydown={onkey} disabled={busy} autofocus />
		<button class="btn" class:small onclick={save} disabled={busy}>{label}</button>
		<button class="btn" class:small onclick={() => (open = false)} disabled={busy} aria-label="Cancel">Cancel</button>
		{#if error}<span class="err small">{error}</span>{/if}
	{:else}
		<button class="btn" class:small onclick={() => (open = true)} title="Hide what is found now; anything new shows again">{label}</button>
	{/if}
</span>

<style>
	.hide {
		display: inline-flex;
		gap: 6px;
		align-items: center;
		flex-wrap: wrap;
	}
	.note {
		height: 32px;
		width: 220px;
		padding: 0 10px;
		border-radius: 7px;
		border: 1px solid var(--hairline);
		background: var(--page);
		color: var(--ink);
		font-size: 13px;
	}
	.note.small {
		height: 24px;
		width: 160px;
		font-size: 12px;
	}
	.btn.small {
		height: 24px;
		font-size: 12px;
		padding: 0 8px;
	}
	.err {
		color: var(--sev-critical);
	}
	.small {
		font-size: 12px;
	}
</style>
