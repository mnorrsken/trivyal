<script lang="ts">
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { api } from '#lib/api.ts';
	import { Fetcher } from '#lib/fetcher.svelte.ts';
	import { live } from '#lib/live.svelte.ts';
	import { ago, int, qs, reportHref } from '#lib/format.ts';
	import type { Counts, ImageUse, MarkInfo, SBOMInfo, SecretFinding, Vulnerability, OS } from '#lib/types.ts';
	import Empty from '#lib/components/Empty.svelte';
	import HideButton from '#lib/components/HideButton.svelte';
	import HideControls from '#lib/components/HideControls.svelte';
	import ImageName from '#lib/components/ImageName.svelte';
	import SevBadge from '#lib/components/SevBadge.svelte';
	import SevCounts from '#lib/components/SevCounts.svelte';
	import Tabs from '#lib/components/Tabs.svelte';
	import VulnTable from '#lib/components/VulnTable.svelte';
	import WorkloadLink from '#lib/components/WorkloadLink.svelte';
	import Components from '#lib/components/Components.svelte';

	interface ImageDetail {
		key: string;
		ref: string;
		name?: string;
		registry?: string;
		repository?: string;
		tag?: string;
		digest?: string;
		os?: OS;
		summary?: Counts;
		fixable?: number;
		updated: string;
		uses: ImageUse[];
		vulnerabilities: Vulnerability[] | null;
		secrets: SecretFinding[] | null;
		secretScanned: boolean;
		sbom?: SBOMInfo;
		hidden?: MarkInfo;
	}

	const key = $derived(page.url.searchParams.get('key') ?? '');
	const tab = $derived(page.url.searchParams.get('tab') ?? 'vulns');
	const hidden = $derived(page.url.searchParams.get('hidden') ?? undefined);
	const f = new Fetcher<ImageDetail>();
	$effect(() => {
		const p = { key, hidden };
		live.generation;
		f.run(() => api<ImageDetail>('image', p));
	});
	const d = $derived(f.data);
	const live_uses = $derived((d?.uses ?? []).filter((u) => !u.workload.stale));
	const old_uses = $derived((d?.uses ?? []).filter((u) => u.workload.stale));

	function setTab(t: string) {
		const u = new URL(page.url.href);
		if (t === 'vulns') u.searchParams.delete('tab');
		else u.searchParams.set('tab', t);
		goto(u, { replace: true, reset: false });
	}
</script>

<svelte:head><title>{d?.ref ?? 'Image'} · trivyal</title></svelte:head>

{#if f.error}
	<div class="card"><Empty title="Image not found">{f.error}</Empty></div>
{:else if d}
	<header class="head">
		<p class="crumb muted"><a class="link" href="/vulnerabilities">Images</a> /</p>
		<h1><ImageName ref={d.ref} link={false} /></h1>
		<div class="meta">
			{#if d.digest}<span class="mono muted small" title={d.digest}>{d.digest}</span>{/if}
		</div>
		<div class="facts">
			{#if d.os?.family}
				<span class="pill">{d.os.family} {d.os.name}</span>
				{#if d.os.eosl}<span class="pill eol" title="This OS release no longer gets security updates">End of life OS</span>{/if}
			{/if}
			<span class="pill">{live_uses.length} workload{live_uses.length === 1 ? '' : 's'}</span>
			<span class="pill">scanned {ago(d.updated)}</span>
		</div>
		<div class="ctl">
			<HideControls target={d.name ? { kind: 'image', image: d.name } : undefined} mark={d.hidden} noun="image" />
		</div>
	</header>

	<div class="tiles">
		{#if d.summary}
			<div class="card tile">
				<span class="label">Vulnerabilities</span>
				<SevCounts counts={d.summary} />
				<span class="muted small">{int(d.fixable ?? 0)} fixable</span>
			</div>
		{/if}
		<div class="card tile">
			<span class="label">Exposed secrets</span>
			<span class="big">{d.secrets?.length ?? 0}</span>
			<span class="muted small">{d.secretScanned ? 'scanned' : 'not scanned'}</span>
		</div>
		{#if d.sbom}
			<div class="card tile">
				<span class="label">Components</span>
				<span class="big">{int(d.sbom.components)}</span>
				<a class="link small" href="/api/v1/sbom/download{qs({ key: d.key })}" download>Download CycloneDX</a>
			</div>
		{/if}
	</div>

	<Tabs
		tabs={[
			{ value: 'vulns', label: `Vulnerabilities (${d.vulnerabilities?.length ?? 0})` },
			{ value: 'uses', label: `Used by (${live_uses.length})` },
			{ value: 'secrets', label: `Secrets (${d.secrets?.length ?? 0})` },
			...(d.sbom ? [{ value: 'sbom', label: `SBOM (${d.sbom.components})` }] : [])
		]}
		value={tab}
		onchange={setTab}
	/>

	<section class="card body">
		{#if tab === 'vulns'}
			{#if d.vulnerabilities}
				<VulnTable vulns={d.vulnerabilities} imageName={d.name} />
			{:else}
				<Empty title="No vulnerability report for this image" />
			{/if}
		{:else if tab === 'uses'}
			<table class="table">
				<thead><tr><th>Workload</th><th>Container</th><th>Report</th></tr></thead>
				<tbody>
					{#each [...live_uses, ...old_uses] as u (u.report.type + u.report.namespace + u.report.name)}
						<tr>
							<td><WorkloadLink w={u.workload} /></td>
							<td class="mono small">{u.container ?? ''}</td>
							<td class="small"><a class="link" href={reportHref(u.report)}>{u.report.name}</a></td>
						</tr>
					{/each}
				</tbody>
			</table>
		{:else if tab === 'secrets'}
			{#if d.secrets?.length}
				<table class="table">
					<thead><tr><th>Severity</th><th>Rule</th><th>File</th><th>Match</th><th></th></tr></thead>
					<tbody>
						{#each d.secrets as s (s.secret.ruleID + s.secret.target + s.secret.match)}
							<tr>
								<td><SevBadge severity={s.secret.severity} small /></td>
								<td>{s.secret.title}<div class="muted small mono">{s.secret.ruleID}</div></td>
								<td class="mono small">{s.secret.target}</td>
								<td class="mono small muted trunc match">{s.secret.match}</td>
								<td class="r">
									<HideButton target={{ kind: 'secret', image: s.imageName, rule: s.secret.ruleID, file: s.secret.target }} small />
								</td>
							</tr>
						{/each}
					</tbody>
				</table>
			{:else}
				<Empty title={d.secretScanned ? 'No secrets found in this image' : 'No secret scan for this image'} good={d.secretScanned} />
			{/if}
		{:else if tab === 'sbom' && d.sbom}
			<Components imageKey={d.key} />
		{/if}
	</section>
{/if}

<style>
	.head {
		margin-bottom: 16px;
	}
	.crumb {
		font-size: 13px;
		margin-bottom: 4px;
	}
	h1 {
		font-size: 18px;
		font-weight: 600;
	}
	h1 :global(.img) {
		font-size: 17px;
	}
	.meta {
		margin-top: 4px;
	}
	.small {
		font-size: 12px;
	}
	.facts {
		display: flex;
		gap: 6px;
		flex-wrap: wrap;
		margin-top: 10px;
	}
	.eol {
		color: var(--sev-critical);
	}
	.ctl {
		margin-top: 12px;
	}
	.tiles {
		display: grid;
		grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
		gap: 12px;
		margin-bottom: 16px;
	}
	.tile {
		display: flex;
		flex-direction: column;
		gap: 6px;
		padding: 14px 16px;
	}
	.label {
		font-size: 12.5px;
		color: var(--ink-2);
	}
	.big {
		font-size: 24px;
		font-weight: 600;
	}
	.body {
		margin-top: 12px;
		overflow: hidden;
	}
	.match {
		max-width: 260px;
	}
</style>
