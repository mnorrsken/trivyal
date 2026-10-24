<script lang="ts">
	// A pill that shows whether target is flagged or hidden, and opens a menu
	// to flag, hide or clear it with a note. In table rows the pill of an
	// unmarked target shows on hover only. contains marks a group that has
	// flagged findings without being flagged itself.
	import { marks } from '../marks.svelte';
	import type { MarkState, MarkTarget } from '../types';

	let {
		target,
		contains = false,
		label = 'Mark',
		row = false
	}: { target: MarkTarget; contains?: boolean; label?: string; row?: boolean } = $props();

	const id = $props.id();
	const mark = $derived(marks.get(target));
	let btn = $state<HTMLButtonElement>();
	let pop = $state<HTMLDivElement>();
	let note = $state('');
	let busy = $state(false);
	let error = $state<string | null>(null);

	function close() {
		pop?.hidePopover();
	}

	// The menu lives in the top layer: place it under the pill and close it
	// when the page scrolls away from it.
	function ontoggle(e: ToggleEvent) {
		if (e.newState !== 'open' || !btn || !pop) {
			removeEventListener('scroll', close, true);
			return;
		}
		note = mark?.note ?? '';
		error = null;
		const r = btn.getBoundingClientRect();
		const w = pop.offsetWidth;
		pop.style.left = Math.max(8, Math.min(r.right - w, innerWidth - w - 8)) + 'px';
		const below = r.bottom + 4;
		pop.style.top = (below + pop.offsetHeight > innerHeight - 8 ? Math.max(8, r.top - pop.offsetHeight - 4) : below) + 'px';
		addEventListener('scroll', close, { capture: true, once: true });
	}

	async function run(fn: () => Promise<unknown>) {
		busy = true;
		error = null;
		try {
			await fn();
			close();
		} catch (e) {
			error = e instanceof Error ? e.message : String(e);
		} finally {
			busy = false;
		}
	}
	const set = (state: MarkState) => run(() => marks.set(target, state, note.trim()));
	const title = $derived(
		mark?.state === 'flagged'
			? 'Flagged' + (mark.note ? ': ' + mark.note : '')
			: mark?.state === 'hidden'
				? 'Hidden' + (mark.note ? ': ' + mark.note : '')
				: contains
					? 'Has flagged findings'
					: 'Flag or hide'
	);
</script>

<!-- Clicks stay here: some rows expand on click. -->
<!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_static_element_interactions -->
<span class="wrap" onclick={(e) => e.stopPropagation()}>
	<button
		bind:this={btn}
		class="pill mark st-{mark?.state ?? (contains ? 'contains' : 'none')}"
		class:row
		popovertarget="mark-{id}"
		{title}
		aria-label={title}
	>
		{#if mark?.state === 'flagged'}⚑ Flagged{:else if mark?.state === 'hidden'}Hidden{:else if contains}⚑{:else}{label}{/if}
	</button>
	<div bind:this={pop} id="mark-{id}" popover="auto" class="card menu" {ontoggle}>
		<input class="note" placeholder="Note (optional)" bind:value={note} disabled={busy} />
		<div class="actions">
			<button class="btn" class:on={mark?.state === 'flagged'} disabled={busy} onclick={() => set('flagged')}>⚑ Flag</button>
			<button class="btn" class:on={mark?.state === 'hidden'} disabled={busy} onclick={() => set('hidden')}>
				{mark?.state === 'hidden' ? 'Hide again' : 'Hide'}
			</button>
			{#if mark}
				<button class="btn" disabled={busy} onclick={() => run(() => marks.clear(mark.id))}>Clear</button>
			{/if}
		</div>
		{#if error}<p class="err">{error}</p>{/if}
		<p class="help muted">
			Flagged items come first in lists. Hiding hides the findings found now; new ones show again.{#if mark?.state === 'hidden'}
				Hide again to hide new ones too.{/if}
		</p>
	</div>
</span>

<style>
	.wrap {
		display: inline-flex;
	}
	.mark {
		cursor: pointer;
		white-space: nowrap;
		border: 1px solid transparent;
	}
	/* st- prefix: plain "hidden" is a Tailwind utility (display: none). */
	.mark.st-none {
		border-color: var(--hairline);
		background: transparent;
		color: var(--muted);
	}
	.mark.st-flagged,
	.mark.st-contains {
		background: var(--accent-wash);
		color: var(--accent-ink);
		font-weight: 550;
	}
	.mark.st-hidden {
		border-color: var(--hairline);
	}
	.mark:hover {
		border-color: var(--axis);
	}
	@media (hover: hover) {
		.mark.row.st-none {
			opacity: 0;
		}
		:global(tr:hover) .mark.row.st-none,
		.mark.row.st-none:focus-visible,
		.wrap:has(:global(:popover-open)) .mark.row.st-none {
			opacity: 1;
		}
	}
	.menu {
		position: fixed;
		inset: auto;
		margin: 0;
		width: 280px;
		padding: 10px;
		box-shadow: 0 6px 24px rgba(0, 0, 0, 0.18);
		color: var(--ink);
		font-size: 13px;
		text-align: left;
	}
	.note {
		width: 100%;
		height: 30px;
		padding: 0 8px;
		border-radius: 6px;
		border: 1px solid var(--hairline);
		background: var(--page);
		color: var(--ink);
		font-size: 13px;
	}
	.actions {
		display: flex;
		gap: 6px;
		margin-top: 8px;
	}
	.actions .btn {
		height: 28px;
		font-size: 12.5px;
		padding: 0 10px;
	}
	.btn.on {
		background: var(--accent-wash);
		border-color: var(--accent);
		color: var(--accent-ink);
	}
	.help {
		margin-top: 8px;
		font-size: 12px;
		white-space: normal;
	}
	.err {
		margin-top: 6px;
		color: var(--sev-critical);
		font-size: 12px;
	}
</style>
