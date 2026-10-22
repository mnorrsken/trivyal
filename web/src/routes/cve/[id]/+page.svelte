<script lang="ts">
	import { page } from '$app/state';
	import { api } from '#lib/api.ts';
	import { Fetcher } from '#lib/fetcher.svelte.ts';
	import { live } from '#lib/live.svelte.ts';
	import { date } from '#lib/format.ts';
	import type { Finding, Vulnerability } from '#lib/types.ts';
	import Empty from '#lib/components/Empty.svelte';
	import ImageName from '#lib/components/ImageName.svelte';
	import SevBadge from '#lib/components/SevBadge.svelte';
	import WorkloadLink from '#lib/components/WorkloadLink.svelte';

	interface CVEDetail {
		id: string;
		vuln: Vulnerability;
		affected: Finding[];
	}

	const id = $derived(page.params.id ?? '');
	const f = new Fetcher<CVEDetail>();
	$effect(() => {
		const i = id;
		live.generation;
		f.run(() => api<CVEDetail>('cve/' + encodeURIComponent(i)));
	});
	const d = $derived(f.data);
	const v = $derived(d?.vuln);
	const workloads = $derived(new Set(d?.affected.flatMap((a) => a.workloads.map((w) => w.kind + w.namespace + w.name))).size);
	const images = $derived(new Set(d?.affected.map((a) => a.imageKey)).size);
</script>

<svelte:head><title>{id} · trivyal</title></svelte:head>

{#if f.error}
	<div class="card"><Empty title="Vulnerability not found">{f.error}. It may have been fixed in every image.</Empty></div>
{:else if d && v}
	<header>
		<p class="crumb muted"><a class="link" href="/vulnerabilities?group=cve">Vulnerabilities</a> /</p>
		<h1><span class="mono">{d.id}</span> <SevBadge severity={v.severity} /></h1>
		{#if v.title}<p class="title">{v.title}</p>{/if}
	</header>

	<div class="grid">
		<section class="card pad">
			{#if v.description}<p class="prose-sm">{v.description}</p>{/if}
			<dl>
				{#if v.score !== undefined}<dt>CVSS score</dt><dd class="num">{v.score.toFixed(1)}</dd>{/if}
				{#if v.publishedDate}<dt>Published</dt><dd>{date(v.publishedDate)}</dd>{/if}
				{#if v.lastModifiedDate}<dt>Last modified</dt><dd>{date(v.lastModifiedDate)}</dd>{/if}
				<dt>Reach</dt><dd>{images} image{images === 1 ? '' : 's'} · {workloads} workload{workloads === 1 ? '' : 's'}</dd>
			</dl>
		</section>
		<section class="card pad">
			<h2 class="section-title">Links</h2>
			<ul class="links">
				{#if v.primaryLink}<li><a class="link" href={v.primaryLink} target="_blank" rel="noreferrer">{v.primaryLink}</a></li>{/if}
				{#each (v.links ?? []).filter((l) => l !== v.primaryLink).slice(0, 12) as l (l)}
					<li><a class="link" href={l} target="_blank" rel="noreferrer">{l}</a></li>
				{/each}
			</ul>
		</section>
	</div>

	<section class="card affected">
		<h2 class="section-title pad-h">Affected images</h2>
		<table class="table">
			<thead><tr><th>Image</th><th>Package</th><th>Installed</th><th>Fixed in</th><th>Workloads</th></tr></thead>
			<tbody>
				{#each d.affected as a (a.imageKey + a.vuln.resource + a.vuln.installedVersion + a.vuln.target)}
					<tr>
						<td class="img"><ImageName ref={a.image} key={a.imageKey} /></td>
						<td class="mono small">{a.vuln.resource}</td>
						<td class="mono small">{a.vuln.installedVersion}</td>
						<td class="mono small">
							{#if a.vuln.fixedVersion}<span class="fixed">{a.vuln.fixedVersion}</span>{:else}<span class="muted">no fix yet</span>{/if}
						</td>
						<td>
							{#each a.workloads as w (w.kind + w.namespace + w.name)}
								<div><WorkloadLink {w} /></div>
							{/each}
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
	.grid {
		display: grid;
		grid-template-columns: minmax(0, 1.6fr) minmax(0, 1fr);
		gap: 16px;
		margin: 16px 0;
	}
	.pad {
		padding: 16px;
	}
	.pad-h {
		padding: 16px 16px 0;
	}
	dl {
		display: grid;
		grid-template-columns: 120px 1fr;
		gap: 6px 12px;
		margin-top: 12px;
		font-size: 13px;
	}
	dt {
		color: var(--muted);
	}
	.links {
		display: flex;
		flex-direction: column;
		gap: 4px;
		font-size: 12.5px;
		word-break: break-all;
	}
	.affected {
		overflow-x: auto;
	}
	.img {
		max-width: 360px;
	}
	.small {
		font-size: 12px;
	}
	.fixed {
		color: var(--good-ink);
	}
	@media (max-width: 900px) {
		.grid {
			grid-template-columns: minmax(0, 1fr);
		}
	}
</style>
