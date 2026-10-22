<script lang="ts">
	// Global search (Ctrl/Cmd-K): jumps to namespaces, workloads, images,
	// vulnerabilities, checks and packages.
	import { goto } from '$app/navigation';
	import { api } from '../api';
	import { imageHref, qs } from '../format';
	import type { SearchHit } from '../types';

	let open = $state(false);
	let text = $state('');
	let hits = $state<SearchHit[]>([]);
	let active = $state(0);
	let input = $state<HTMLInputElement>();
	let timer: ReturnType<typeof setTimeout> | undefined;
	let seq = 0;

	const kindLabel: Record<string, string> = {
		namespace: 'Namespace',
		workload: 'Workload',
		image: 'Image',
		cve: 'Vulnerability',
		check: 'Check',
		package: 'Package',
		node: 'Node',
		pod: 'Pod'
	};

	export function show() {
		open = true;
		queueMicrotask(() => input?.select());
	}

	function href(h: SearchHit): string {
		switch (h.kind) {
			case 'namespace':
				return '/namespace/' + encodeURIComponent(h.key);
			case 'workload': {
				const [ns, kind, name] = h.key.split('/');
				return `/workload/${encodeURIComponent(ns || '_')}/${encodeURIComponent(kind)}/${encodeURIComponent(name)}`;
			}
			case 'image':
				return imageHref(h.key);
			case 'cve':
				return '/cve/' + encodeURIComponent(h.key);
			case 'check': {
				const [type, id] = h.key.split('/');
				return `/checks/${type}/${encodeURIComponent(id)}`;
			}
			case 'package':
				return '/sbom' + qs({ q: `name:${/[\s,]/.test(h.key) ? `"${h.key}"` : h.key}` });
			case 'node':
				return '/node/' + encodeURIComponent(h.key);
			case 'pod': {
				const [ns, name] = h.key.split('/');
				return `/pod/${encodeURIComponent(ns)}/${encodeURIComponent(name)}`;
			}
		}
	}

	function oninput() {
		clearTimeout(timer);
		timer = setTimeout(async () => {
			const s = ++seq;
			const q = text.trim();
			if (q.length < 2) {
				hits = [];
				return;
			}
			try {
				const r = await api<SearchHit[]>('search', { q });
				if (s === seq) {
					hits = r;
					active = 0;
				}
			} catch {
				/* keep old hits */
			}
		}, 150);
	}

	function pick(h: SearchHit) {
		open = false;
		goto(href(h));
	}

	function onkeydown(e: KeyboardEvent) {
		if (e.key === 'ArrowDown') {
			e.preventDefault();
			active = Math.min(active + 1, hits.length - 1);
		} else if (e.key === 'ArrowUp') {
			e.preventDefault();
			active = Math.max(active - 1, 0);
		} else if (e.key === 'Enter' && hits[active]) {
			e.preventDefault();
			pick(hits[active]);
		} else if (e.key === 'Escape') {
			open = false;
		}
	}

	function onwindowkey(e: KeyboardEvent) {
		if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
			e.preventDefault();
			show();
		} else if (e.key === '/' && !open && !(e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement)) {
			e.preventDefault();
			show();
		}
	}
</script>

<svelte:window onkeydown={onwindowkey} />

<button class="trigger" onclick={show}>
	<svg viewBox="0 0 20 20" aria-hidden="true"
		><circle cx="8.5" cy="8.5" r="5.5" fill="none" stroke="currentColor" stroke-width="1.8" /><path
			d="M13 13l4 4"
			stroke="currentColor"
			stroke-width="1.8"
			stroke-linecap="round"
		/></svg
	>
	<span>Search</span>
	<kbd>⌘K</kbd>
</button>

{#if open}
	<!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_static_element_interactions -->
	<div class="backdrop" onclick={() => (open = false)}>
		<!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_static_element_interactions -->
		<div class="panel card" onclick={(e) => e.stopPropagation()} role="dialog" aria-label="Search" tabindex="-1">
			<input
				bind:this={input}
				bind:value={text}
				{oninput}
				{onkeydown}
				placeholder="Namespaces, workloads, pods, nodes, images, CVEs, checks, packages…"
				spellcheck="false"
				autocomplete="off"
			/>
			{#if hits.length}
				<ul>
					{#each hits as h, i (h.kind + h.key)}
						{#if i === 0 || hits[i - 1].kind !== h.kind}
							<li class="group">{kindLabel[h.kind]}</li>
						{/if}
						<li>
							<a href={href(h)} class:active={i === active} onmouseenter={() => (active = i)} onclick={() => (open = false)}>
								<span class="label trunc">{h.label}</span>
								{#if h.sub}<span class="sub trunc">{h.sub}</span>{/if}
							</a>
						</li>
					{/each}
				</ul>
			{:else if text.trim().length >= 2}
				<p class="none">No matches</p>
			{/if}
		</div>
	</div>
{/if}

<style>
	.trigger {
		display: flex;
		align-items: center;
		gap: 8px;
		width: 100%;
		height: 34px;
		padding: 0 10px;
		border-radius: 7px;
		border: 1px solid var(--hairline);
		background: var(--surface);
		color: var(--muted);
		font-size: 13px;
	}
	.trigger:hover {
		color: var(--ink);
	}
	.trigger svg {
		width: 14px;
		height: 14px;
	}
	.trigger span {
		flex: 1;
		text-align: left;
	}
	kbd {
		font-family: var(--font-sans);
		font-size: 11px;
		border: 1px solid var(--hairline);
		border-radius: 4px;
		padding: 0 4px;
	}
	.backdrop {
		position: fixed;
		inset: 0;
		z-index: 50;
		background: rgba(0, 0, 0, 0.35);
		display: flex;
		justify-content: center;
		align-items: flex-start;
		padding: 12vh 16px 0;
	}
	.panel {
		width: min(640px, 100%);
		overflow: hidden;
		box-shadow: 0 16px 48px rgba(0, 0, 0, 0.25);
	}
	input {
		width: 100%;
		height: 52px;
		padding: 0 18px;
		border: 0;
		border-bottom: 1px solid var(--hairline);
		background: transparent;
		color: var(--ink);
		font-size: 15px;
		outline: none;
	}
	ul {
		max-height: 60vh;
		overflow-y: auto;
		padding: 6px;
	}
	.group {
		font-size: 11px;
		font-weight: 600;
		letter-spacing: 0.04em;
		text-transform: uppercase;
		color: var(--muted);
		padding: 10px 10px 4px;
	}
	a {
		display: flex;
		align-items: baseline;
		gap: 12px;
		padding: 7px 10px;
		border-radius: 6px;
		font-size: 13.5px;
	}
	a.active {
		background: var(--accent-wash);
	}
	.label {
		font-weight: 500;
		min-width: 0;
	}
	.sub {
		color: var(--muted);
		font-size: 12px;
		margin-left: auto;
		max-width: 50%;
	}
	.none {
		padding: 18px;
		color: var(--muted);
		font-size: 13px;
	}
</style>
