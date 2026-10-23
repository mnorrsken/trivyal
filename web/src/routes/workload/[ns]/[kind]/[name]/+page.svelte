<script lang="ts">
	import { page } from '$app/state';
	import { api } from '#lib/api.ts';
	import { Fetcher } from '#lib/fetcher.svelte.ts';
	import { live } from '#lib/live.svelte.ts';
	import { ago, imageHref, reportHref } from '#lib/format.ts';
	import type {
		CheckFinding,
		Container,
		MarkInfo,
		PodInfo,
		Resource,
		SecretFinding,
		WorkloadImage,
		WorkloadInfo,
		Counts
	} from '#lib/types.ts';
	import CheckList from '#lib/components/CheckList.svelte';
	import Empty from '#lib/components/Empty.svelte';
	import HideButton from '#lib/components/HideButton.svelte';
	import HideControls from '#lib/components/HideControls.svelte';
	import ImageName from '#lib/components/ImageName.svelte';
	import PodTable from '#lib/components/PodTable.svelte';
	import SevBadge from '#lib/components/SevBadge.svelte';
	import SevCounts from '#lib/components/SevCounts.svelte';

	interface Detail {
		workload?: WorkloadInfo;
		resource: Resource;
		pods: PodInfo[];
		reports: {
			images: WorkloadImage[];
			config: CheckFinding[];
			secrets: SecretFinding[];
			reports: { type: string; namespace?: string; name: string }[];
		};
		hidden?: MarkInfo;
	}

	const ns = $derived(page.params.ns ?? '_');
	const kind = $derived(page.params.kind ?? '');
	const name = $derived(page.params.name ?? '');
	const hidden = $derived(page.url.searchParams.get('hidden') ?? undefined);
	const f = new Fetcher<Detail>();
	$effect(() => {
		const p = `workload/${encodeURIComponent(ns)}/${encodeURIComponent(kind)}/${encodeURIComponent(name)}`;
		const params = { hidden };
		live.generation;
		f.run(() => api<Detail>(p, params));
	});
	const d = $derived(f.data);
	const w = $derived(d?.workload);

	const vulnTotal = $derived.by(() => {
		const c: Counts = { criticalCount: 0, highCount: 0, mediumCount: 0, lowCount: 0, unknownCount: 0 };
		const seen = new Set<string>();
		for (const i of d?.reports.images ?? []) {
			if (seen.has(i.key)) continue;
			seen.add(i.key);
			c.criticalCount += i.counts.criticalCount;
			c.highCount += i.counts.highCount;
			c.mediumCount += i.counts.mediumCount;
			c.lowCount += i.counts.lowCount;
			c.unknownCount = (c.unknownCount ?? 0) + (i.counts.unknownCount ?? 0);
		}
		return c;
	});
	const configCounts = $derived.by(() => {
		const c: Counts = { criticalCount: 0, highCount: 0, mediumCount: 0, lowCount: 0 };
		for (const x of d?.reports.config ?? []) {
			const k = (x.check.severity.toLowerCase() + 'Count') as keyof Counts;
			if (k in c) (c[k] as number)++;
		}
		return c;
	});
	const imageFor = (c: Container) => d?.reports.images.find((i) => i.container === c.name);

	function flags(c: Container): { t: string; bad: boolean }[] {
		const out: { t: string; bad: boolean }[] = [];
		if (c.privileged) out.push({ t: 'privileged', bad: true });
		if (c.runAsNonRoot !== true && !(c.runAsUser && c.runAsUser > 0)) out.push({ t: 'may run as root', bad: true });
		if (c.readOnlyRootFilesystem !== true) out.push({ t: 'writable root fs', bad: false });
		if (c.allowPrivilegeEscalation !== false) out.push({ t: 'privilege escalation allowed', bad: false });
		return out;
	}
</script>

<svelte:head><title>{name} · trivyal</title></svelte:head>

{#if f.error}
	<div class="card"><Empty title="Workload not found">{f.error}</Empty></div>
{:else if d}
	<header>
		<p class="crumb muted">
			<a class="link" href="/workloads">Workloads</a> /
			{#if d.resource.namespace}<a class="link" href="/namespace/{encodeURIComponent(d.resource.namespace)}">{d.resource.namespace}</a> /{/if}
		</p>
		<h1><span class="kind">{d.resource.kind}</span> {d.resource.name}</h1>
		<div class="facts">
			{#if w}
				{#if w.kind === 'CronJob'}
					<span class="pill">schedule <span class="mono">{w.schedule}</span></span>
					{#if w.suspended}<span class="pill">suspended</span>{/if}
					{#if w.lastSchedule}<span class="pill">last run {ago(w.lastSchedule)}</span>{/if}
				{:else}
					<span class="pill" class:good={w.ready === w.replicas}>{w.ready}/{w.replicas ?? 0} ready</span>
				{/if}
				<span class="pill">created {ago(w.created)}</span>
				{#if w.serviceAccount}<span class="pill">service account {w.serviceAccount}</span>{/if}
				{#if w.owner}<span class="pill">owned by {w.owner.kind} {w.owner.name}</span>{/if}
				{#if w.hostNetwork}<span class="pill bad">host network</span>{/if}
				{#if w.hostPID}<span class="pill bad">host PID</span>{/if}
			{:else}
				<span class="pill">not found in the cluster; showing reports only</span>
			{/if}
		</div>
		<div class="ctl">
			<HideControls target={{ kind: 'workload', resource: d.resource }} mark={d.hidden} noun="workload" />
		</div>
	</header>

	<div class="tiles">
		<div class="card tile">
			<span class="label">Vulnerabilities</span>
			<SevCounts counts={vulnTotal} />
		</div>
		<div class="card tile">
			<span class="label">Misconfigurations</span>
			<SevCounts counts={configCounts} showUnknown={false} />
		</div>
		<div class="card tile">
			<span class="label">Exposed secrets</span>
			<span class="big">{d.reports.secrets.length}</span>
		</div>
	</div>

	{#if w?.containers?.length}
		<section class="card sec">
			<h2 class="section-title pad">Containers</h2>
			<table class="table">
				<thead><tr><th>Container</th><th>Image</th><th>Vulnerabilities</th><th>Security</th><th>Resources</th></tr></thead>
				<tbody>
					{#each w.containers as c (c.name + c.init)}
						{@const img = imageFor(c)}
						<tr>
							<td class="mono small">{c.name}{#if c.init}<span class="pill init">init</span>{/if}</td>
							<td class="img">
								{#if img}<ImageName ref={img.ref} key={img.key} />{:else}<ImageName ref={c.image} link={false} />{/if}
							</td>
							<td>
								{#if img}<a href={imageHref(img.key)}><SevCounts counts={img.counts} /></a>{:else}<span class="muted small">no report</span>{/if}
							</td>
							<td class="flags">
								{#each flags(c) as fl (fl.t)}<span class="pill" class:bad={fl.bad}>{fl.t}</span>{/each}
							</td>
							<td class="small ink2 num">
								{#if c.cpuRequest || c.memoryRequest}req {c.cpuRequest ?? '–'} / {c.memoryRequest ?? '–'}<br />{/if}
								{#if c.cpuLimit || c.memoryLimit}limit {c.cpuLimit ?? '–'} / {c.memoryLimit ?? '–'}{/if}
								{#if !c.cpuRequest && !c.memoryRequest && !c.cpuLimit && !c.memoryLimit}<span class="muted">none set</span>{/if}
							</td>
						</tr>
					{/each}
				</tbody>
			</table>
		</section>
	{:else if d.reports.images.length}
		<section class="card sec">
			<h2 class="section-title pad">Images</h2>
			<table class="table">
				<tbody>
					{#each d.reports.images as img (img.container + img.key)}
						<tr>
							<td class="mono small">{img.container}</td>
							<td class="img"><ImageName ref={img.ref} key={img.key} /></td>
							<td><SevCounts counts={img.counts} /></td>
						</tr>
					{/each}
				</tbody>
			</table>
		</section>
	{/if}

	<section class="card sec">
		<h2 class="section-title pad">Misconfigurations</h2>
		<CheckList findings={d.reports.config} />
	</section>

	{#if d.reports.secrets.length}
		<section class="card sec">
			<h2 class="section-title pad">Exposed secrets</h2>
			<table class="table">
				<thead><tr><th>Severity</th><th>Secret</th><th>File</th><th>Container</th><th></th></tr></thead>
				<tbody>
					{#each d.reports.secrets as s, i (s.secret.ruleID + s.secret.target + i)}
						<tr>
							<td><SevBadge severity={s.secret.severity} small /></td>
							<td>{s.secret.title}<div class="muted small mono">{s.secret.ruleID}</div></td>
							<td class="mono small">{s.secret.target}</td>
							<td class="mono small">{s.container}</td>
							<td class="r">
								<HideButton target={{ kind: 'secret', image: s.imageName, rule: s.secret.ruleID, file: s.secret.target }} small />
							</td>
						</tr>
					{/each}
				</tbody>
			</table>
		</section>
	{/if}

	{#if d.pods.length}
		<section class="card sec">
			<h2 class="section-title pad">Pods</h2>
			<PodTable pods={d.pods} />
		</section>
	{/if}

	{#if d.reports.reports.length}
		<section class="card sec pad">
			<h2 class="section-title">Reports</h2>
			<ul class="reps">
				{#each d.reports.reports as r (r.type + r.name)}
					<li><a class="link mono small" href={reportHref(r)}>{r.type}/{r.name}</a></li>
				{/each}
			</ul>
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
		word-break: break-all;
	}
	.kind {
		font-size: 12px;
		font-weight: 600;
		color: var(--muted);
		border: 1px solid var(--hairline);
		border-radius: 5px;
		padding: 1px 6px;
	}
	.facts {
		display: flex;
		gap: 6px;
		flex-wrap: wrap;
		margin: 10px 0 12px;
	}
	.ctl {
		margin-bottom: 16px;
	}
	.pill.bad {
		color: var(--sev-critical);
	}
	.tiles {
		display: grid;
		grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
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
	section.pad {
		padding: 16px;
	}
	.small {
		font-size: 12px;
	}
	.img {
		max-width: 340px;
	}
	.flags {
		display: flex;
		flex-wrap: wrap;
		gap: 4px;
		max-width: 300px;
	}
	.init {
		margin-left: 6px;
	}
	.reps {
		display: flex;
		flex-direction: column;
		gap: 4px;
	}
</style>
