<script lang="ts">
	// Detail page controls: "Show hidden" (?hidden=1), a Hide button for the
	// page's subject, or what is hidden about it with Unhide.
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { ago, int } from '../format';
	import { hide, unhide } from '../hidden';
	import type { HideTarget, MarkInfo } from '../types';
	import HideButton from './HideButton.svelte';

	let { target, mark, noun }: { target?: HideTarget; mark?: MarkInfo; noun: string } = $props();

	const showHidden = $derived(page.url.searchParams.get('hidden') === '1');
	let busy = $state(false);
	let error = $state<string | null>(null);

	function toggle(on: boolean) {
		const u = new URL(page.url.href);
		if (on) u.searchParams.set('hidden', '1');
		else u.searchParams.delete('hidden');
		goto(u, { replace: true, reset: false });
	}

	async function run(fn: () => Promise<unknown>) {
		busy = true;
		error = null;
		try {
			await fn();
		} catch (e) {
			error = e instanceof Error ? e.message : String(e);
		} finally {
			busy = false;
		}
	}
	const plural = (n: number, w: string) => `${int(n)} ${w}${n === 1 ? '' : 's'}`;
</script>

<div class="bar">
	{#if target && !mark}<HideButton {target} label="Hide {noun}" />{/if}
	<label class="show">
		<input type="checkbox" checked={showHidden} onchange={(e) => toggle(e.currentTarget.checked)} />
		Show hidden
	</label>
</div>
{#if mark}
	<div class="card banner">
		<div class="text">
			<strong>This {noun} is hidden</strong>
			<span class="ink2">
				since {ago(mark.updated)}: {plural(mark.hiding, 'finding')} hidden{#if mark.new},
					<span class="new">{plural(mark.new, 'new finding')} shown again</span>{/if}.
			</span>
			{#if mark.note}<div class="note">“{mark.note}”</div>{/if}
			{#if error}<div class="err">{error}</div>{/if}
		</div>
		<div class="actions">
			{#if mark.new}
				<button class="btn" disabled={busy} onclick={() => run(() => hide(mark.target))}>Hide new findings too</button>
			{/if}
			<button class="btn" disabled={busy} onclick={() => run(() => unhide(mark.id))}>Unhide</button>
		</div>
	</div>
{/if}

<style>
	.bar {
		display: flex;
		gap: 12px;
		align-items: center;
		flex-wrap: wrap;
	}
	.show {
		display: flex;
		gap: 6px;
		align-items: center;
		font-size: 13px;
		color: var(--ink-2);
	}
	.banner {
		display: flex;
		justify-content: space-between;
		align-items: center;
		gap: 12px;
		flex-wrap: wrap;
		padding: 12px 16px;
		margin-top: 12px;
		background: var(--accent-wash);
		font-size: 13px;
	}
	.note {
		margin-top: 4px;
		color: var(--ink-2);
	}
	.new {
		color: var(--accent-ink);
		font-weight: 550;
	}
	.actions {
		display: flex;
		gap: 8px;
	}
	.err {
		color: var(--sev-critical);
		margin-top: 4px;
	}
</style>
