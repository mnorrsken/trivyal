<script lang="ts">
	// Search box for the filter language with autocomplete for field names
	// and facet values, removable chips, and a field reference.
	import { parse, remove } from '../filter';
	import type { FacetValue, SchemaField } from '../types';

	let {
		q,
		schema = [],
		facets = {},
		error = null,
		placeholder = 'Filter…',
		onchange
	}: {
		q: string;
		schema?: SchemaField[];
		facets?: Record<string, FacetValue[]>;
		error?: string | null;
		placeholder?: string;
		onchange: (q: string, replace: boolean) => void;
	} = $props();

	let text = $state('');
	let input: HTMLInputElement;
	let timer: ReturnType<typeof setTimeout> | undefined;
	let showHelp = $state(false);
	let active = $state(-1);
	let focused = $state(false);
	let caret = $state(0);

	// Follow external changes (facet clicks, back button) unless typing.
	$effect(() => {
		const ext = q;
		if (document.activeElement !== input || !timer) text = ext;
	});

	const tokens = $derived(parse(q));

	function apply(replace: boolean) {
		clearTimeout(timer);
		timer = undefined;
		const v = text.trim().replace(/\s+/g, ' ');
		if (v !== q) onchange(v, replace);
	}

	function oninput() {
		caret = input.selectionStart ?? text.length;
		active = -1;
		clearTimeout(timer);
		timer = setTimeout(() => apply(true), 450);
	}

	// The word under the caret drives suggestions.
	const current = $derived.by(() => {
		const before = text.slice(0, caret);
		const m = /(^|\s)(-?)([^\s]*)$/.exec(before);
		return { start: before.length - (m?.[3].length ?? 0), word: m?.[3] ?? '', neg: m?.[2] ?? '' };
	});

	interface Suggestion {
		label: string;
		insert: string;
		hint?: string;
	}

	const suggestions = $derived.by((): Suggestion[] => {
		if (!focused) return [];
		const w = current.word.toLowerCase();
		const colon = w.indexOf(':');
		if (colon < 0) {
			if (!w) return [];
			return schema
				.filter((f) => f.name.startsWith(w) || f.aliases?.some((a) => a.startsWith(w)))
				.slice(0, 8)
				.map((f) => ({ label: f.name + ':', insert: f.name + ':', hint: f.help }));
		}
		const field = w.slice(0, colon);
		const f = schema.find((s) => s.name === field || s.aliases?.includes(field));
		const vals = f ? (facets[f.name] ?? []) : [];
		const parts = w.slice(colon + 1).split(',');
		const last = parts[parts.length - 1];
		const prefix = w.slice(0, w.length - last.length);
		if (vals.some((v) => v.value.toLowerCase() === last)) return [];
		return vals
			.filter((v) => v.value.toLowerCase().includes(last) && !parts.slice(0, -1).includes(v.value.toLowerCase()))
			.slice(0, 10)
			.map((v) => ({
				label: v.value,
				insert: prefix + (/[\s,]/.test(v.value) ? `"${v.value}"` : v.value),
				hint: String(v.count)
			}));
	});

	function accept(s: Suggestion) {
		const { start } = current;
		const end = start + current.word.length;
		const after = text.slice(end);
		const sep = s.insert.endsWith(':') ? '' : ' ';
		text = text.slice(0, start) + s.insert + sep + after.replace(/^\s+/, '');
		caret = start + s.insert.length + sep.length;
		active = -1;
		queueMicrotask(() => {
			input.focus();
			input.setSelectionRange(caret, caret);
		});
		if (sep) apply(false);
	}

	function onkeydown(e: KeyboardEvent) {
		if (suggestions.length && (e.key === 'ArrowDown' || e.key === 'ArrowUp')) {
			e.preventDefault();
			const n = suggestions.length;
			active = (active + (e.key === 'ArrowDown' ? 1 : n - 1)) % n;
			return;
		}
		if ((e.key === 'Enter' || e.key === 'Tab') && active >= 0 && suggestions[active]) {
			e.preventDefault();
			accept(suggestions[active]);
			return;
		}
		if (e.key === 'Enter') {
			e.preventDefault();
			apply(false);
		}
		if (e.key === 'Escape') {
			if (active >= 0) active = -1;
			else input.blur();
		}
	}

	function insertField(name: string) {
		text = (text.trim() ? text.trim() + ' ' : '') + name + ':';
		caret = text.length;
		showHelp = false;
		queueMicrotask(() => {
			input.focus();
			input.setSelectionRange(caret, caret);
		});
	}
</script>

<div class="wrap">
	<div class="box" class:err={!!error}>
		<svg class="icon" viewBox="0 0 20 20" aria-hidden="true"
			><circle cx="8.5" cy="8.5" r="5.5" fill="none" stroke="currentColor" stroke-width="1.8" /><path
				d="M13 13l4 4"
				stroke="currentColor"
				stroke-width="1.8"
				stroke-linecap="round"
			/></svg
		>
		<input
			bind:this={input}
			bind:value={text}
			{oninput}
			{onkeydown}
			onclick={() => (caret = input.selectionStart ?? text.length)}
			onfocus={() => (focused = true)}
			onblur={() => setTimeout(() => (focused = false), 150)}
			{placeholder}
			spellcheck="false"
			autocomplete="off"
			aria-label="Filter"
			role="combobox"
			aria-expanded={suggestions.length > 0}
			aria-controls="filter-suggestions"
		/>
		{#if text}
			<button
				class="clear"
				title="Clear filter"
				onclick={() => {
					text = '';
					apply(false);
				}}>×</button
			>
		{/if}
		<button class="help" class:on={showHelp} title="Filter fields" onclick={() => (showHelp = !showHelp)}
			>?</button
		>
	</div>

	{#if suggestions.length}
		<ul class="sugg" id="filter-suggestions" role="listbox">
			{#each suggestions as s, i (s.insert)}
				<li role="option" aria-selected={i === active}>
					<button class:active={i === active} onmousedown={(e) => e.preventDefault()} onclick={() => accept(s)}>
						<span class="mono">{s.label}</span>
						{#if s.hint}<span class="hint">{s.hint}</span>{/if}
					</button>
				</li>
			{/each}
		</ul>
	{/if}

	{#if showHelp}
		<div class="helpbox card">
			<p class="intro">
				<span class="mono">field:value</span> filters, <span class="mono">a,b</span> means either,
				<span class="mono">-field:value</span> excludes, <span class="mono">*</span> is a wildcard,
				<span class="mono">=value</span> matches exactly,
				<span class="mono">&gt;=7</span> compares. Other words search everywhere.
			</p>
			<div class="fields">
				{#each schema as f (f.name)}
					<button onclick={() => insertField(f.name)}>
						<span class="mono">{f.name}</span><span class="hint">{f.help}</span>
					</button>
				{/each}
			</div>
		</div>
	{/if}

	{#if error}
		<p class="error">{error}</p>
	{:else if tokens.length}
		<div class="chips">
			{#each tokens as t, i (i + t.raw)}
				<span class="chip" class:neg={t.negate}>
					{#if t.field}<span class="f">{t.negate ? 'not ' : ''}{t.field}</span>{/if}
					<span class="v">{t.field ? t.values.join(' or ') : t.values[0]}</span>
					<button title="Remove" onclick={() => onchange(remove(q, i), false)}>×</button>
				</span>
			{/each}
			{#if tokens.length > 1}
				<button class="clearall" onclick={() => onchange('', false)}>Clear all</button>
			{/if}
		</div>
	{/if}
</div>

<style>
	.wrap {
		position: relative;
	}
	.box {
		display: flex;
		align-items: center;
		gap: 8px;
		height: 40px;
		padding: 0 6px 0 12px;
		background: var(--surface);
		border: 1px solid var(--ring);
		border-radius: 8px;
	}
	.box:focus-within {
		border-color: var(--accent);
		box-shadow: 0 0 0 3px var(--accent-wash);
	}
	.box.err {
		border-color: var(--sev-critical);
	}
	.icon {
		width: 16px;
		height: 16px;
		color: var(--muted);
		flex: none;
	}
	input {
		flex: 1;
		min-width: 0;
		height: 100%;
		background: transparent;
		border: 0;
		outline: none;
		font: 14px var(--font-mono);
		color: var(--ink);
	}
	input::placeholder {
		font-family: var(--font-sans);
		color: var(--muted);
	}
	.clear,
	.help {
		width: 28px;
		height: 28px;
		border-radius: 6px;
		color: var(--muted);
		font-size: 16px;
		flex: none;
	}
	.help {
		font-size: 13px;
		font-weight: 600;
		border: 1px solid var(--hairline);
	}
	.clear:hover,
	.help:hover,
	.help.on {
		background: var(--surface-2);
		color: var(--ink);
	}
	.sugg {
		position: absolute;
		z-index: 30;
		top: 44px;
		left: 0;
		min-width: 280px;
		max-width: 100%;
		background: var(--surface);
		border: 1px solid var(--ring);
		border-radius: 8px;
		box-shadow: 0 8px 24px rgba(0, 0, 0, 0.12);
		padding: 4px;
	}
	.sugg button {
		display: flex;
		justify-content: space-between;
		gap: 16px;
		width: 100%;
		padding: 6px 8px;
		border-radius: 5px;
		text-align: left;
		font-size: 13px;
	}
	.sugg button:hover,
	.sugg button.active {
		background: var(--accent-wash);
	}
	.hint {
		color: var(--muted);
		font-size: 12px;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}
	.mono {
		font-family: var(--font-mono);
		font-size: 13px;
	}
	.helpbox {
		position: absolute;
		z-index: 30;
		top: 44px;
		right: 0;
		width: min(560px, 100%);
		padding: 12px;
		box-shadow: 0 8px 24px rgba(0, 0, 0, 0.12);
	}
	.intro {
		font-size: 13px;
		color: var(--ink-2);
		margin-bottom: 8px;
		line-height: 1.6;
	}
	.fields {
		display: grid;
		grid-template-columns: minmax(0, 1fr);
		gap: 2px;
	}
	.fields button {
		display: grid;
		grid-template-columns: 90px 1fr;
		gap: 12px;
		text-align: left;
		padding: 4px 6px;
		border-radius: 5px;
	}
	.fields button:hover {
		background: var(--surface-2);
	}
	.error {
		margin-top: 6px;
		font-size: 13px;
		color: var(--sev-critical);
	}
	.chips {
		display: flex;
		flex-wrap: wrap;
		gap: 6px;
		margin-top: 8px;
	}
	.chip {
		display: inline-flex;
		align-items: center;
		gap: 5px;
		height: 26px;
		padding: 0 4px 0 10px;
		border-radius: 999px;
		background: var(--accent-wash);
		font-size: 12px;
	}
	.chip.neg {
		background: var(--surface-2);
		text-decoration-color: var(--muted);
	}
	.chip .f {
		color: var(--muted);
	}
	.chip .v {
		font-weight: 500;
		max-width: 320px;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}
	.chip button {
		width: 20px;
		height: 20px;
		border-radius: 999px;
		color: var(--muted);
	}
	.chip button:hover {
		background: var(--surface);
		color: var(--ink);
	}
	.clearall {
		font-size: 12px;
		color: var(--muted);
		padding: 0 6px;
	}
	.clearall:hover {
		color: var(--ink);
		text-decoration: underline;
	}
</style>
