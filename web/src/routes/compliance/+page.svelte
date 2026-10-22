<script lang="ts">
	import { api } from '#lib/api.ts';
	import { Fetcher } from '#lib/fetcher.svelte.ts';
	import { live } from '#lib/live.svelte.ts';
	import { ago } from '#lib/format.ts';
	import type { ComplianceSummary } from '#lib/types.ts';
	import Empty from '#lib/components/Empty.svelte';
	import Meter from '#lib/components/Meter.svelte';

	const f = new Fetcher<ComplianceSummary[] | null>();
	$effect(() => {
		live.generation;
		f.run(() => api<ComplianceSummary[] | null>('compliance'));
	});
</script>

<svelte:head><title>Compliance · trivyal</title></svelte:head>

<h1>Compliance</h1>
<p class="muted sub">Benchmarks run by trivy-operator on a schedule (ClusterComplianceReports).</p>

{#if f.error}
	<div class="card"><Empty title="Could not load compliance reports">{f.error}</Empty></div>
{:else if f.data && f.data.length === 0}
	<div class="card">
		<Empty title="No compliance reports">Enable <code>compliance</code> in the trivy-operator Helm values to run CIS, NSA and PSS benchmarks.</Empty>
	</div>
{:else if f.data}
	<div class="grid">
		{#each f.data as c (c.name)}
			{@const pct = c.pass + c.fail ? Math.round((c.pass / (c.pass + c.fail)) * 100) : 0}
			<a class="card item" href="/compliance/{encodeURIComponent(c.name)}">
				<span class="name">{c.title || c.name}</span>
				<span class="pct">{pct}%</span>
				<Meter pass={c.pass} fail={c.fail} />
				<span class="muted small num">{c.pass} controls pass · {c.fail} fail</span>
				<span class="muted small">{c.name} · updated {ago(c.updated)}</span>
			</a>
		{/each}
	</div>
{/if}

<style>
	h1 {
		font-size: 22px;
		font-weight: 600;
	}
	.sub {
		font-size: 13px;
		margin: 2px 0 16px;
	}
	.grid {
		display: grid;
		grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
		gap: 12px;
	}
	.item {
		display: flex;
		flex-direction: column;
		gap: 6px;
		padding: 16px;
	}
	.item:hover {
		border-color: var(--accent);
	}
	.name {
		font-weight: 550;
	}
	.pct {
		font-size: 28px;
		font-weight: 600;
	}
	.small {
		font-size: 12px;
	}
	code {
		font-family: var(--font-mono);
	}
</style>
