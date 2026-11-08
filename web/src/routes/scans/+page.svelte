<script lang="ts">
	import { api } from '#lib/api.ts';
	import { Fetcher } from '#lib/fetcher.svelte.ts';
	import { ListState } from '#lib/list.svelte.ts';
	import { live } from '#lib/live.svelte.ts';
	import { schemas } from '#lib/schema.svelte.ts';
	import { ago, int, reportHref } from '#lib/format.ts';
	import type { List, Scan } from '#lib/types.ts';
	import Empty from '#lib/components/Empty.svelte';
	import ImageName from '#lib/components/ImageName.svelte';
	import ListLayout from '#lib/components/ListLayout.svelte';
	import SevCounts from '#lib/components/SevCounts.svelte';
	import SortTh from '#lib/components/SortTh.svelte';
	import WorkloadLink from '#lib/components/WorkloadLink.svelte';

	type ScanList = List<Scan> & { running: number };

	const ls = new ListState();
	const f = new Fetcher<ScanList>();
	$effect(() => {
		const p = ls.params;
		live.generation;
		// This list follows the cluster; refreshes do not dim it.
		live.cluster;
		f.run(() => api<ScanList>('scans', p), JSON.stringify(p));
	});
	const d = $derived(f.data);
	const sort = $derived(d?.sort ?? '');
	const onsort = (k: string) => ls.toggleSort(k, sort);

	// Running times tick without a refetch.
	let now = $state(Date.now());
	$effect(() => {
		const t = setInterval(() => (now = Date.now()), 5000);
		return () => clearInterval(t);
	});

	const facetLabels = { state: 'State', type: 'Type', age: 'Scanned within', ns: 'Namespace', kind: 'Workload kind' };
	const typeLabels: Record<string, string> = {
		vulnerability: 'Vulnerabilities',
		secret: 'Exposed secrets',
		sbom: 'SBOM',
		config: 'Config audit',
		rbac: 'RBAC',
		infra: 'Infrastructure',
		compliance: 'Compliance'
	};
	const stateLabels = { running: 'Running', failed: 'Failed', done: 'Done' };

	function typeLabel(s: Scan): string {
		// One image scan job writes the vulnerability, secret and SBOM reports.
		if (s.job && s.type === 'vulnerability') return 'Image scan';
		if (s.job && s.type === 'infra') return 'Node collector';
		return typeLabels[s.type] ?? s.type;
	}

	function elapsed(from: string, to: number): string {
		const s = Math.max(0, Math.round((to - new Date(from).getTime()) / 1000));
		if (s < 60) return `${s}s`;
		if (s < 3600) return `${Math.floor(s / 60)}m ${s % 60}s`;
		return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`;
	}

	function when(s: Scan, n: number): string {
		if (s.state === 'running') return `for ${elapsed(s.time, n)}`;
		return ago(s.finished ?? s.time);
	}

	// The scanned object when it is not the workload itself (a ReplicaSet of a Deployment).
	function scanned(s: Scan): string {
		const r = s.resource;
		const w = s.workload;
		if (r.kind === w.kind && r.name === w.name && r.namespace === w.namespace) return '';
		return `${r.kind} ${r.name}`;
	}
</script>

<svelte:head><title>Scans · trivyal</title></svelte:head>

<ListLayout
	title="Scans"
	subtitle={d?.running
		? `${int(d.running)} scan${d.running === 1 ? '' : 's'} running now.`
		: 'Scan jobs trivy-operator runs now, and the last scan of every report.'}
	{ls}
	schema={schemas.value.scans}
	facets={d?.facets ?? {}}
	{facetLabels}
	total={d?.total ?? 0}
	size={ls.size}
	error={f.error}
	loading={f.loading}
	noun="scans"
	placeholder="state:running type:vulnerability age:1h ns:demo"
	markable={false}
>
	{#if d && d.items.length === 0}
		<Empty title={ls.q ? 'No scans match' : 'No scans yet'}>
			{#if ls.q}Try removing a filter.{:else}Scans show up here when trivy-operator starts a scan job or writes a report.{/if}
		</Empty>
	{:else if d}
		<table class="table">
			<thead>
				<tr>
					<th>State</th>
					<SortTh key="time" current={sort} {onsort}>When</SortTh>
					<SortTh key="type" current={sort} {onsort}>Type</SortTh>
					<SortTh key="workload" current={sort} {onsort}>Scanned</SortTh>
					<th>Images</th>
					<th>Result</th>
				</tr>
			</thead>
			<tbody>
				{#each d.items as s, i (s.job ? 'job/' + s.job.namespace + '/' + s.job.name : s.report ? reportHref(s.report) : i)}
					<tr>
						<td>
							<span class="state st-{s.state}"><span class="dot"></span>{stateLabels[s.state]}</span>
						</td>
						<td class="small num nowrap" title={s.finished ?? s.time}>
							{#if s.report}
								<a class="link" href={reportHref(s.report)}>{when(s, now)}</a>
							{:else}
								<span class="ink2">{when(s, now)}</span>
							{/if}
						</td>
						<td class="type">
							{typeLabel(s)}
							{#if s.scanner}<div class="muted small">{s.scanner}</div>{/if}
						</td>
						<td class="wl">
							{#if s.type === 'compliance'}
								<a class="link" href="/compliance/{encodeURIComponent(s.resource.name)}">{s.resource.name}</a>
							{:else}
								<WorkloadLink w={s.workload} />
							{/if}
							{#if scanned(s)}<div class="muted small trunc">{scanned(s)}</div>{/if}
						</td>
						<td class="imgs">
							{#each s.images ?? [] as img (img.container + img.image)}
								<div class="small"><ImageName ref={img.image} key={img.key} /></div>
							{/each}
						</td>
						<td class="result">
							{#if s.state === 'failed'}
								<span class="small ink2">{s.message}</span>
							{:else if s.summary}
								<SevCounts counts={s.summary} showUnknown={s.type === 'vulnerability'} />
							{:else if s.components !== undefined}
								<span class="small num">{int(s.components)} components</span>
							{:else if s.fail !== undefined}
								<span class="small num">{int(s.pass ?? 0)} pass · {int(s.fail)} fail</span>
							{/if}
						</td>
					</tr>
				{/each}
			</tbody>
		</table>
	{/if}
</ListLayout>

<style>
	.small {
		font-size: 12px;
	}
	.nowrap {
		white-space: nowrap;
	}
	.type {
		white-space: nowrap;
	}
	.wl {
		min-width: 200px;
		max-width: 340px;
	}
	.imgs {
		max-width: 320px;
	}
	.result {
		min-width: 200px;
		max-width: 360px;
	}
	.state {
		display: inline-flex;
		align-items: center;
		gap: 6px;
		font-size: 12.5px;
		white-space: nowrap;
	}
	.dot {
		width: 7px;
		height: 7px;
		border-radius: 999px;
		background: var(--axis);
		flex: none;
	}
	.st-running {
		color: var(--accent-ink);
	}
	.st-running .dot {
		background: var(--accent);
		animation: pulse 1.4s ease-in-out infinite;
	}
	.st-failed {
		color: var(--sev-critical);
		font-weight: 550;
	}
	.st-failed .dot {
		background: var(--sev-critical);
	}
	.st-done {
		color: var(--ink-2);
	}
	@keyframes pulse {
		50% {
			opacity: 0.3;
		}
	}
	@media (prefers-reduced-motion: reduce) {
		.st-running .dot {
			animation: none;
		}
	}
</style>
