<script lang="ts">
	import { page } from '$app/state';
	import { api } from '#lib/api.ts';
	import { Fetcher } from '#lib/fetcher.svelte.ts';
	import { live } from '#lib/live.svelte.ts';
	import { ago, sevLabel, severities } from '#lib/format.ts';
	import type { ComplianceReport, Control } from '#lib/types.ts';
	import Empty from '#lib/components/Empty.svelte';
	import Meter from '#lib/components/Meter.svelte';
	import SevBadge from '#lib/components/SevBadge.svelte';
	import Tabs from '#lib/components/Tabs.svelte';

	const name = $derived(page.params.name ?? '');
	const f = new Fetcher<ComplianceReport>();
	$effect(() => {
		const n = name;
		live.generation;
		f.run(() => api<ComplianceReport>('compliance/' + encodeURIComponent(n)));
	});
	const d = $derived(f.data);

	let status = $state('fail');
	let sev = $state('');
	let text = $state('');

	function ctlState(c: Control): 'fail' | 'pass' | 'manual' {
		if (c.manual) return 'manual';
		return (c.totalFail ?? 0) > 0 ? 'fail' : 'pass';
	}
	const counts = $derived({
		fail: (d?.controls ?? []).filter((c) => ctlState(c) === 'fail').length,
		pass: (d?.controls ?? []).filter((c) => ctlState(c) === 'pass').length,
		manual: (d?.controls ?? []).filter((c) => ctlState(c) === 'manual').length
	});
	const rows = $derived(
		(d?.controls ?? []).filter((c) => {
			const t = text.trim().toLowerCase();
			return (
				(status === 'all' || ctlState(c) === status) &&
				(!sev || c.severity === sev) &&
				(!t || `${c.id} ${c.name} ${c.description ?? ''}`.toLowerCase().includes(t))
			);
		})
	);
</script>

<svelte:head><title>{d?.title ?? name} · trivyal</title></svelte:head>

{#if f.error}
	<div class="card"><Empty title="Compliance report not found">{f.error}</Empty></div>
{:else if d}
	<header>
		<p class="crumb muted"><a class="link" href="/compliance">Compliance</a> /</p>
		<h1>{d.title}</h1>
		{#if d.description}<p class="prose-sm desc">{d.description}</p>{/if}
		<div class="facts">
			<span class="pill">{d.passCount} pass · {d.failCount} fail</span>
			<span class="pill">updated {ago(d.updated)}</span>
			{#if d.cron}<span class="pill" title="Cron schedule">runs <span class="mono">{d.cron}</span></span>{/if}
			{#if d.reportType}<span class="pill">{d.reportType} report</span>{/if}
		</div>
		<div class="meter"><Meter pass={d.passCount} fail={d.failCount} /></div>
	</header>

	<div class="bar">
		<Tabs
			tabs={[
				{ value: 'fail', label: `Failing (${counts.fail})` },
				{ value: 'pass', label: `Passing (${counts.pass})` },
				{ value: 'manual', label: `Manual (${counts.manual})` },
				{ value: 'all', label: 'All' }
			]}
			value={status}
			onchange={(v) => (status = v)}
		/>
		<select bind:value={sev}>
			<option value="">All severities</option>
			{#each severities.slice(0, 4) as s (s)}<option value={s}>{sevLabel(s)}</option>{/each}
		</select>
		<input placeholder="Filter controls" bind:value={text} />
	</div>

	<section class="card list">
		{#if rows.length === 0}
			<Empty title="No controls match" good={status === 'fail' && !text && !sev} />
		{:else}
			<table class="table">
				<thead><tr><th>Control</th><th>Name</th><th>Severity</th><th class="r">Failing</th></tr></thead>
				<tbody>
					{#each rows as c (c.id)}
						<tr>
							<td class="mono small id">
								<a class="link" href="/compliance/{encodeURIComponent(name)}/{encodeURIComponent(c.id)}">{c.id}</a>
							</td>
							<td class="nm">
								<a href="/compliance/{encodeURIComponent(name)}/{encodeURIComponent(c.id)}">{c.name}</a>
								{#if c.manual}<span class="pill">manual</span>{/if}
							</td>
							<td><SevBadge severity={c.severity} small /></td>
							<td class="r num">{c.manual ? '—' : (c.totalFail ?? 0)}</td>
						</tr>
					{/each}
				</tbody>
			</table>
		{/if}
	</section>
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
	.desc {
		margin-top: 4px;
		max-width: 900px;
	}
	.facts {
		display: flex;
		gap: 6px;
		flex-wrap: wrap;
		margin-top: 10px;
	}
	.meter {
		max-width: 480px;
		margin: 12px 0 18px;
	}
	.bar {
		display: flex;
		gap: 10px;
		flex-wrap: wrap;
		align-items: center;
		margin-bottom: 12px;
	}
	select,
	input {
		height: 34px;
		padding: 0 10px;
		border-radius: 7px;
		border: 1px solid var(--hairline);
		background: var(--surface);
		color: var(--ink);
		font-size: 13px;
	}
	input {
		flex: 1 1 200px;
		max-width: 320px;
	}
	.list {
		overflow-x: auto;
	}
	.small {
		font-size: 12px;
	}
	.id {
		white-space: nowrap;
	}
	.nm a:hover {
		text-decoration: underline;
	}
	.nm .pill {
		margin-left: 6px;
	}
</style>
