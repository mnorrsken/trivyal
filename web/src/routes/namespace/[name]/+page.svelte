<script lang="ts">
	import { page } from '$app/state';
	import { api } from '#lib/api.ts';
	import { Fetcher } from '#lib/fetcher.svelte.ts';
	import { live } from '#lib/live.svelte.ts';
	import { ago, qs, total } from '#lib/format.ts';
	import type { CheckFinding, NamespaceRow, WorkloadRow } from '#lib/types.ts';
	import CheckList from '#lib/components/CheckList.svelte';
	import Empty from '#lib/components/Empty.svelte';
	import HiddenNote from '#lib/components/HiddenNote.svelte';
	import MarkMenu from '#lib/components/MarkMenu.svelte';
	import SevBar from '#lib/components/SevBar.svelte';
	import SevCounts from '#lib/components/SevCounts.svelte';
	import WorkloadLink from '#lib/components/WorkloadLink.svelte';

	type Detail = NamespaceRow & {
		workloadList: WorkloadRow[];
		configFindings: CheckFinding[];
		rbacFindings: CheckFinding[];
		hiddenFindings: number;
	};

	const name = $derived(page.params.name ?? '');
	const f = new Fetcher<Detail>();
	$effect(() => {
		const n = name;
		live.generation;
		f.run(() => api<Detail>('namespace/' + encodeURIComponent(n)));
	});
	const d = $derived(f.data);
	const max = $derived(Math.max(1, ...(d?.workloadList ?? []).map((w) => total(w.stats.vulns))));
	const pssLabels = $derived(Object.entries(d?.labels ?? {}).filter(([k]) => k.startsWith('pod-security.kubernetes.io/')));
	const nsq = $derived(qs({ q: 'ns:' + name }));
</script>

<svelte:head><title>{name} · trivyal</title></svelte:head>

{#if f.error}
	<div class="card"><Empty title="Namespace not found">{f.error}</Empty></div>
{:else if d}
	<header>
		<p class="crumb muted"><a class="link" href="/namespaces">Namespaces</a> /</p>
		<h1>{d.name}</h1>
		<div class="facts">
			<span class="pill">{d.phase}</span>
			<span class="pill">created {ago(d.created)}</span>
			{#each pssLabels as [k, v] (k)}<span class="pill accent">{k.replace('pod-security.kubernetes.io/', 'PSS ')}: {v}</span>{/each}
			{#if pssLabels.length === 0}<span class="pill">no Pod Security Standard enforced</span>{/if}
		</div>
		<nav class="jump">
			<a class="btn" href="/vulnerabilities{nsq}">Vulnerabilities</a>
			<a class="btn" href="/checks/config{nsq}">Config audit</a>
			<a class="btn" href="/secrets{nsq}">Secrets</a>
			<a class="btn" href="/checks/rbac{nsq}">RBAC</a>
		</nav>
		<div class="ctl">
			<MarkMenu target={{ kind: 'namespace', namespace: d.name }} label="Flag or hide" />
			<HiddenNote count={d.hiddenFindings} />
		</div>
	</header>

	<div class="tiles">
		<div class="card tile"><span class="label">Workloads</span><span class="big">{d.workloads}</span></div>
		<div class="card tile"><span class="label">Vulnerabilities</span><SevCounts counts={d.vulns} /></div>
		<div class="card tile"><span class="label">Misconfigurations</span><SevCounts counts={d.config} showUnknown={false} /></div>
		<div class="card tile"><span class="label">Exposed secrets</span><span class="big">{d.secrets}</span></div>
	</div>

	<section class="card sec">
		<h2 class="section-title pad">Workloads</h2>
		{#if d.workloadList.length === 0}
			<Empty title="No workloads" />
		{:else}
			<table class="table">
				<thead><tr><th>Workload</th><th class="r">Ready</th><th>Vulnerabilities</th><th>Misconfigurations</th><th class="r">Secrets</th><th></th></tr></thead>
				<tbody>
					{#each d.workloadList as w (w.kind + w.name)}
						<tr>
							<td class="main"><WorkloadLink {w} showNs={false} /></td>
							<td class="r num small">
								{#if w.kind === 'CronJob'}<span class="mono muted">{w.schedule}</span>{:else}{w.ready}/{w.replicas ?? '–'}{/if}
							</td>
							<td class="sev"><SevCounts counts={w.stats.vulns} /><SevBar counts={w.stats.vulns} {max} height={5} /></td>
							<td><SevCounts counts={w.stats.config} showUnknown={false} /></td>
							<td class="r num">{w.stats.secrets || ''}</td>
							<td class="r mark-col">
								<MarkMenu target={{ kind: 'workload', resource: { kind: w.kind, namespace: w.namespace, name: w.name } }} contains={w.flagged} row />
							</td>
						</tr>
					{/each}
				</tbody>
			</table>
		{/if}
	</section>

	<section class="card sec">
		<h2 class="section-title pad">Other resources (services, ingresses, volumes…)</h2>
		<CheckList findings={d.configFindings} showResource empty="No misconfigured resources" />
	</section>

	<section class="card sec">
		<h2 class="section-title pad">RBAC</h2>
		<CheckList findings={d.rbacFindings} type="rbac" showResource empty="No risky roles" />
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
	.facts {
		display: flex;
		gap: 6px;
		flex-wrap: wrap;
		margin: 10px 0;
	}
	.jump {
		display: flex;
		gap: 6px;
		flex-wrap: wrap;
		margin-bottom: 16px;
	}
	.ctl {
		margin-bottom: 16px;
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
		gap: 8px;
		padding: 14px 16px;
	}
	.label {
		font-size: 12.5px;
		color: var(--ink-2);
	}
	.big {
		font-size: 22px;
		font-weight: 600;
	}
	.sec {
		margin-bottom: 16px;
		overflow-x: auto;
	}
	.pad {
		padding: 16px 16px 4px;
	}
	.main {
		min-width: 220px;
	}
	.sev {
		min-width: 250px;
	}
	.sev :global(.track) {
		margin-top: 6px;
	}
	.small {
		font-size: 12px;
	}
</style>
