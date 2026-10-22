<script lang="ts">
	import { page } from '$app/state';
	import { api } from '#lib/api.ts';
	import { Fetcher } from '#lib/fetcher.svelte.ts';
	import { live } from '#lib/live.svelte.ts';
	import { reportHref } from '#lib/format.ts';
	import type { CheckFinding, Control } from '#lib/types.ts';
	import Empty from '#lib/components/Empty.svelte';
	import SevBadge from '#lib/components/SevBadge.svelte';
	import WorkloadLink from '#lib/components/WorkloadLink.svelte';

	interface ControlDetail {
		report: string;
		title: string;
		control: Control;
		failing: (CheckFinding & { type: string })[];
		checks: Record<string, { title: string; severity: string; type: string }>;
	}

	const name = $derived(page.params.name ?? '');
	const control = $derived(page.params.control ?? '');
	const f = new Fetcher<ControlDetail>();
	$effect(() => {
		const p = `compliance/${encodeURIComponent(name)}/${encodeURIComponent(control)}`;
		live.generation;
		f.run(() => api<ControlDetail>(p));
	});
	const d = $derived(f.data);
	const c = $derived(d?.control);
</script>

<svelte:head><title>{control} · trivyal</title></svelte:head>

{#if f.error}
	<div class="card"><Empty title="Control not found">{f.error}</Empty></div>
{:else if d && c}
	<header>
		<p class="crumb muted">
			<a class="link" href="/compliance">Compliance</a> /
			<a class="link" href="/compliance/{encodeURIComponent(name)}">{d.title}</a> /
		</p>
		<h1><span class="mono">{c.id}</span> <SevBadge severity={c.severity} /></h1>
		<p class="title">{c.name}</p>
	</header>

	<section class="card pad info">
		{#if c.description}<p class="prose-sm">{c.description}</p>{/if}
		{#if c.manual}
			<p class="prose-sm manual">This control has no automated check. Review it by hand.</p>
		{:else}
			<h2 class="section-title checks">Checks</h2>
			<ul>
				{#each c.checks ?? [] as id (id)}
					{@const ch = d.checks[id.toUpperCase()]}
					<li>
						{#if ch}
							<a class="link mono small" href="/checks/{ch.type}/{encodeURIComponent(id)}">{id}</a>
							<span class="small">{ch.title}</span>
						{:else}
							<span class="mono small">{id}</span>
							<span class="muted small">no results in the current reports</span>
						{/if}
					</li>
				{/each}
			</ul>
		{/if}
	</section>

	{#if !c.manual}
		<section class="card list">
			<h2 class="section-title head">
				{d.failing.length} failing resource{d.failing.length === 1 ? '' : 's'}
				{#if c.totalFail !== undefined && c.totalFail !== d.failing.length}
					<span class="muted small">(the compliance report counted {c.totalFail} at its last run)</span>
				{/if}
			</h2>
			{#if d.failing.length === 0}
				<Empty title="Nothing fails this control right now" good />
			{:else}
				<table class="table">
					<thead><tr><th>Resource</th><th>Check</th><th>Message</th></tr></thead>
					<tbody>
						{#each d.failing as x, i (x.report.name + x.check.checkID + i)}
							<tr>
								<td class="main"><WorkloadLink w={x.resource} /></td>
								<td class="small">
									<a class="link mono" href={reportHref(x.report)}>{x.check.checkID}</a>
									<div>{x.check.title}</div>
								</td>
								<td class="small ink2">{x.check.messages?.join(' ') ?? ''}</td>
							</tr>
						{/each}
					</tbody>
				</table>
			{/if}
		</section>
	{/if}
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
	.pad {
		padding: 16px;
	}
	.info {
		margin: 16px 0;
		max-width: 900px;
	}
	.checks {
		margin: 14px 0 6px;
	}
	ul {
		display: flex;
		flex-direction: column;
		gap: 4px;
	}
	li {
		display: flex;
		gap: 10px;
		align-items: baseline;
	}
	.manual {
		margin-top: 10px;
	}
	.small {
		font-size: 12px;
	}
	.list {
		overflow-x: auto;
	}
	.head {
		padding: 16px 16px 0;
	}
	.main {
		min-width: 240px;
	}
</style>
