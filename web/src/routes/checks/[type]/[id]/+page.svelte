<script lang="ts">
	import { page } from '$app/state';
	import { api } from '#lib/api.ts';
	import { Fetcher } from '#lib/fetcher.svelte.ts';
	import { live } from '#lib/live.svelte.ts';
	import { checkTypes } from '#lib/checks.ts';
	import { reportHref } from '#lib/format.ts';
	import type { Check, CheckFinding } from '#lib/types.ts';
	import Empty from '#lib/components/Empty.svelte';
	import HiddenNote from '#lib/components/HiddenNote.svelte';
	import MarkMenu from '#lib/components/MarkMenu.svelte';
	import SevBadge from '#lib/components/SevBadge.svelte';
	import WorkloadLink from '#lib/components/WorkloadLink.svelte';

	interface CheckDetail {
		check: Check;
		resources: CheckFinding[];
		hiddenFindings: number;
	}

	const type = $derived(page.params.type ?? 'config');
	const id = $derived(page.params.id ?? '');
	const f = new Fetcher<CheckDetail>();
	$effect(() => {
		const path = `checks/${type}/${encodeURIComponent(id)}`;
		live.generation;
		f.run(() => api<CheckDetail>(path));
	});
	const d = $derived(f.data);
	let text = $state('');
	const rows = $derived(
		(d?.resources ?? []).filter((r) => {
			const t = text.trim().toLowerCase();
			return !t || `${r.resource.kind} ${r.resource.namespace ?? ''} ${r.resource.name}`.toLowerCase().includes(t);
		})
	);
	const failing = $derived((d?.resources ?? []).filter((r) => !r.check.success).length);
</script>

<svelte:head><title>{id} · trivyal</title></svelte:head>

{#if f.error}
	<div class="card"><Empty title="Check not found">{f.error}</Empty></div>
{:else if d}
	<header>
		<p class="crumb muted">
			<a class="link" href="/checks/{type}?group=check">{checkTypes[type]?.title ?? type}</a> /
		</p>
		<h1><span class="mono">{d.check.checkID}</span> <SevBadge severity={d.check.severity} /></h1>
		<p class="title">{d.check.title}</p>
		<div class="ctl">
			<MarkMenu target={{ kind: 'check', type, id: d.check.checkID }} label="Flag or hide" />
			<HiddenNote count={d.hiddenFindings} />
		</div>
	</header>

	<section class="card pad info">
		{#if d.check.description}<p class="prose-sm">{d.check.description}</p>{/if}
		{#if d.check.remediation}
			<h2 class="section-title fix">How to fix</h2>
			<p class="prose-sm">{d.check.remediation}</p>
		{/if}
		{#if d.check.category}<p class="muted small cat">{d.check.category}</p>{/if}
	</section>

	<section class="card list">
		<div class="bar">
			<h2 class="section-title">{failing} failing resource{failing === 1 ? '' : 's'}</h2>
			<input placeholder="Filter resources" bind:value={text} />
		</div>
		<table class="table">
			<thead><tr><th>Resource</th><th>Status</th><th>Message</th><th></th><th></th></tr></thead>
			<tbody>
				{#each rows as r, i (r.report.name + i)}
					<tr>
						<td class="main"><WorkloadLink w={r.resource} /></td>
						<td>
							{#if r.check.success}<span class="pill good">pass</span>{:else}<span class="pill">fail</span>{/if}
						</td>
						<td class="small ink2">{r.check.messages?.join(' ') ?? ''}</td>
						<td class="small"><a class="link" href={reportHref(r.report)}>report</a></td>
						<td class="r mark-col">
							{#if !r.check.success}
								<MarkMenu target={{ kind: 'resource-check', type, id: r.check.checkID, resource: r.resource }} contains={r.flagged} row />
							{/if}
						</td>
					</tr>
				{/each}
			</tbody>
		</table>
	</section>
{/if}

<style>
	.crumb {
		font-size: 13px;
		margin-bottom: 4px;
	}
	h1 {
		display: flex;
		align-items: center;
		gap: 10px;
		font-size: 20px;
		font-weight: 600;
	}
	.title {
		margin-top: 4px;
		color: var(--ink-2);
	}
	.ctl {
		margin-top: 12px;
	}
	.pad {
		padding: 16px;
	}
	.info {
		margin: 16px 0;
		max-width: 900px;
	}
	.fix {
		margin-top: 14px;
		margin-bottom: 4px;
	}
	.cat {
		margin-top: 12px;
	}
	.small {
		font-size: 12px;
	}
	.list {
		overflow-x: auto;
	}
	.bar {
		display: flex;
		justify-content: space-between;
		align-items: center;
		gap: 12px;
		padding: 12px 12px 4px 16px;
	}
	.bar h2 {
		margin: 0;
	}
	input {
		height: 32px;
		width: 240px;
		padding: 0 10px;
		border-radius: 7px;
		border: 1px solid var(--hairline);
		background: var(--page);
		color: var(--ink);
		font-size: 13px;
	}
	.main {
		min-width: 240px;
	}
</style>
