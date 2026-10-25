<script lang="ts">
	// One raw report: shows whatever the report kind holds, with links to
	// the richer pages (image, check).
	import { page } from '$app/state';
	import { api } from '#lib/api.ts';
	import { Fetcher } from '#lib/fetcher.svelte.ts';
	import { live } from '#lib/live.svelte.ts';
	import { ago, imageHref } from '#lib/format.ts';
	import type { Check, Counts, Resource, Secret, Vulnerability } from '#lib/types.ts';
	import Empty from '#lib/components/Empty.svelte';
	import SevBadge from '#lib/components/SevBadge.svelte';
	import SevCounts from '#lib/components/SevCounts.svelte';
	import VulnTable from '#lib/components/VulnTable.svelte';

	interface Report {
		kind: string;
		namespace?: string;
		name: string;
		resource: Resource;
		container?: string;
		updated: string;
		scanner: { name: string; version: string };
		summary?: Counts & { componentsCount?: number };
		checks?: Check[] | null;
		vulnerabilities?: Vulnerability[] | null;
		secrets?: Secret[] | null;
		artifact?: { repository: string; tag?: string; digest?: string };
		registry?: { server: string };
	}

	const path = $derived(page.params.path ?? '');
	const f = new Fetcher<{ report: Report }>();
	$effect(() => {
		const p = path;
		live.generation;
		f.run(() => api<{ report: Report }>('report/' + p));
	});
	const r = $derived(f.data?.report);
	const checkType = $derived(
		r?.kind.includes('ConfigAudit') ? 'config' : r?.kind.includes('Rbac') ? 'rbac' : r?.kind.includes('Infra') ? 'infra' : ''
	);
	const failed = $derived((r?.checks ?? []).filter((c) => !c.success));
	const passed = $derived((r?.checks ?? []).filter((c) => c.success));
	let open = $state<number | null>(null);
</script>

<svelte:head><title>{r?.name ?? 'Report'} · trivyal</title></svelte:head>

{#if f.error}
	<div class="card"><Empty title="Report not found">{f.error}</Empty></div>
{:else if r}
	<header>
		<p class="crumb muted">{r.kind}</p>
		<h1>{r.resource.kind} <span class="muted">{r.resource.namespace ? r.resource.namespace + '/' : ''}</span>{r.resource.name}</h1>
		<div class="facts">
			{#if r.container}<span class="pill">container {r.container}</span>{/if}
			<span class="pill">{r.scanner.name} {r.scanner.version}</span>
			<span class="pill">updated {ago(r.updated)}</span>
			<span class="pill mono">{r.name}</span>
		</div>
	</header>

	{#if r.summary && r.summary.criticalCount !== undefined}
		<div class="sum"><SevCounts counts={r.summary} showUnknown={!!r.vulnerabilities} /></div>
	{/if}

	{#if r.artifact?.digest}
		<p class="small">Image: <a class="link mono" href={imageHref(r.artifact.digest)}>{r.artifact.repository}:{r.artifact.tag}</a></p>
	{/if}

	{#if r.checks}
		<section class="card list">
			{#if failed.length === 0}
				<Empty title="All checks pass" good />
			{:else}
				<table class="table">
					<thead><tr><th>Severity</th><th>Check</th><th>Message</th></tr></thead>
					<tbody>
						{#each failed as c, i (c.checkID + i)}
							<tr class="row" onclick={() => (open = open === i ? null : i)}>
								<td><SevBadge severity={c.severity} small /></td>
								<td class="title">
									<a class="link mono small" href="/checks/{checkType}/{encodeURIComponent(c.checkID)}" onclick={(e) => e.stopPropagation()}
										>{c.checkID}</a
									>
									<div>{c.title}</div>
								</td>
								<td class="small ink2">{c.messages?.join(' ') ?? ''}</td>
							</tr>
							{#if open === i}
								<tr class="detail">
									<td colspan="3">
										<p class="prose-sm">{c.description}</p>
										{#if c.remediation}<p class="prose-sm fix"><strong>Fix:</strong> {c.remediation}</p>{/if}
									</td>
								</tr>
							{/if}
						{/each}
					</tbody>
				</table>
			{/if}
			{#if passed.length}
				<p class="muted small passed">{passed.length} checks pass.</p>
			{/if}
		</section>
	{:else if r.vulnerabilities}
		<section class="card list"><VulnTable vulns={r.vulnerabilities} /></section>
	{:else if r.secrets}
		<section class="card list">
			{#if r.secrets.length === 0}
				<Empty title="No secrets found" good />
			{:else}
				<table class="table">
					<thead><tr><th>Severity</th><th>Rule</th><th>File</th><th>Match</th></tr></thead>
					<tbody>
						{#each r.secrets as s, i (s.ruleID + s.target + i)}
							<tr>
								<td><SevBadge severity={s.severity} small /></td>
								<td>{s.title}<div class="muted small mono">{s.ruleID}</div></td>
								<td class="mono small">{s.target}</td>
								<td class="mono small muted">{s.match}</td>
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
		font-size: 20px;
		font-weight: 600;
	}
	.facts {
		display: flex;
		gap: 6px;
		flex-wrap: wrap;
		margin: 10px 0 14px;
	}
	.sum {
		margin-bottom: 12px;
	}
	.small {
		font-size: 12px;
	}
	.list {
		overflow-x: auto;
		margin-top: 12px;
	}
	.row {
		cursor: pointer;
	}
	.title {
		max-width: 420px;
	}
	.detail td {
		background: var(--surface-2);
	}
	.fix {
		margin-top: 6px;
	}
	.passed {
		padding: 10px 12px;
	}
</style>
