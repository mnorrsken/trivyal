<script lang="ts">
	import { api } from '#lib/api.ts';
	import { Fetcher } from '#lib/fetcher.svelte.ts';
	import { live } from '#lib/live.svelte.ts';
	import { ago, compact, int, qs, total } from '#lib/format.ts';
	import type { Counts, Summary } from '#lib/types.ts';
	import Empty from '#lib/components/Empty.svelte';
	import ImageName from '#lib/components/ImageName.svelte';
	import Meter from '#lib/components/Meter.svelte';
	import SevBar from '#lib/components/SevBar.svelte';
	import SevCounts from '#lib/components/SevCounts.svelte';
	import StatTile from '#lib/components/StatTile.svelte';

	const f = new Fetcher<Summary>();
	$effect(() => {
		live.generation;
		f.run(() => api<Summary>('summary'));
	});
	const s = $derived(f.data);

	const vulnHref = (q: string) => '/vulnerabilities' + qs({ q });
	const checkHref = (type: string, q: string) => `/checks/${type}` + qs({ q });
	const known = (c: Counts) => total(c) - (c.unknownCount ?? 0);
	const maxNS = $derived(Math.max(1, ...(s?.namespaces ?? []).map((n) => total(n.vulns))));
	const maxImg = $derived(Math.max(1, ...(s?.topImages ?? []).map((i) => total(i.counts))));
</script>

<div class="head">
	<h1>Overview</h1>
	{#if s?.newest}
		<p class="muted fresh">
			Latest scan {ago(s.newest)} · oldest report {ago(s.oldest)}
		</p>
	{/if}
</div>

{#if f.error && !s}
	<div class="card"><Empty title="Could not load the summary">{f.error}</Empty></div>
{:else if s && !s.synced}
	<div class="card"><Empty title="Loading reports from the cluster…">This takes a few seconds after start.</Empty></div>
{:else if s && !s.installed}
	<div class="card">
		<Empty title="trivy-operator is not installed">
			No <code>aquasecurity.github.io</code> report CRDs were found. Install trivy-operator; this page picks up its reports
			automatically.
		</Empty>
	</div>
{:else if s}
	<section class="tiles">
		<StatTile
			label="Vulnerabilities"
			value={compact(total(s.vulns.counts))}
			note="in {int(s.vulns.images)} images · {int(s.vulns.workloads)} workloads"
			href="/vulnerabilities?group=finding"
		>
			<SevCounts counts={s.vulns.counts} href={(sev) => vulnHref('sev:' + sev.toLowerCase()) + '&group=finding'} />
		</StatTile>
		<StatTile
			label="Fixable vulnerabilities"
			value={compact(s.vulns.fixable)}
			note="a fixed version exists"
			href={vulnHref('fixable:yes') + '&group=finding'}
		/>
		<StatTile
			label="Misconfigurations"
			value={compact(known(s.config.counts))}
			note="{int(s.config.failing)} of {int(s.config.resources)} resources failing"
			href="/checks/config?group=check"
		>
			<SevCounts counts={s.config.counts} showUnknown={false} href={(sev) => checkHref('config', 'sev:' + sev.toLowerCase())} />
		</StatTile>
		<StatTile
			label="Exposed secrets"
			value={compact(total(s.secrets.counts))}
			note="{int(s.secrets.affected)} of {int(s.secrets.scanned)} containers affected"
			href="/secrets"
		/>
		<StatTile
			label="RBAC findings"
			value={compact(known(s.rbac.counts))}
			note="{int(s.rbac.failing)} of {int(s.rbac.resources)} roles failing"
			href="/checks/rbac?group=check"
		>
			<SevCounts counts={s.rbac.counts} showUnknown={false} href={(sev) => checkHref('rbac', 'sev:' + sev.toLowerCase())} />
		</StatTile>
	</section>

	<div class="grid">
		<section class="card pad">
			<div class="row-head">
				<h2 class="section-title">Most vulnerable images</h2>
				<a class="link small" href="/vulnerabilities">All images →</a>
			</div>
			{#if s.topImages.length}
				<div class="scroll">
				<table class="table">
					<thead>
						<tr><th>Image</th><th>Findings</th><th class="r">Fixable</th><th class="r">Workloads</th></tr>
					</thead>
					<tbody>
						{#each s.topImages as img (img.key)}
							<tr>
								<td class="imgcell"><ImageName ref={img.ref} key={img.key} /></td>
								<td class="sevcell">
									<SevCounts counts={img.counts} />
									<SevBar counts={img.counts} max={maxImg} height={6} />
								</td>
								<td class="r num">{int(img.fixable)}</td>
								<td class="r num">{img.workloads.length}</td>
							</tr>
						{/each}
					</tbody>
				</table>
				</div>
			{:else}
				<Empty title="No vulnerability reports yet" />
			{/if}
		</section>

		<section class="card pad">
			<div class="row-head">
				<h2 class="section-title">Compliance</h2>
				<a class="link small" href="/compliance">Details →</a>
			</div>
			{#if s.compliance?.length}
				<ul class="comp">
					{#each s.compliance as c (c.name)}
						{@const pct = c.pass + c.fail ? Math.round((c.pass / (c.pass + c.fail)) * 100) : 0}
						<li>
							<a href="/compliance/{encodeURIComponent(c.name)}">
								<span class="ctitle">{c.title || c.name}</span>
								<span class="pct num">{pct}%</span>
							</a>
							<Meter pass={c.pass} fail={c.fail} />
							<span class="muted small num">{c.pass} pass · {c.fail} fail · {ago(c.updated)}</span>
						</li>
					{/each}
				</ul>
			{:else}
				<Empty title="No compliance reports">Enable compliance scanning in trivy-operator to see CIS, NSA and PSS results.</Empty>
			{/if}
		</section>
	</div>

	<section class="card pad ns">
		<div class="row-head">
			<h2 class="section-title">Namespaces</h2>
		</div>
		{#if s.namespaces?.length}
			<div class="scroll">
				<table class="table">
					<thead>
						<tr>
							<th>Namespace</th>
							<th>Vulnerabilities</th>
							<th>Misconfigurations</th>
							<th class="r">Secrets</th>
							<th class="r">Workloads</th>
						</tr>
					</thead>
					<tbody>
						{#each s.namespaces as n (n.namespace)}
							<tr>
								<td><a class="link" href="/namespace/{encodeURIComponent(n.namespace)}">{n.namespace}</a></td>
								<td class="sevcell">
									<SevCounts counts={n.vulns} href={(sev) => vulnHref(`ns:${n.namespace} sev:${sev.toLowerCase()}`)} />
									<SevBar counts={n.vulns} max={maxNS} height={6} />
								</td>
								<td>
									<SevCounts
										counts={n.config}
										showUnknown={false}
										href={(sev) => checkHref('config', `ns:${n.namespace} sev:${sev.toLowerCase()}`)}
									/>
								</td>
								<td class="r num">
									{#if n.secrets}<a class="link" href="/secrets{qs({ q: 'ns:' + n.namespace })}">{n.secrets}</a>{:else}<span
											class="muted">0</span
										>{/if}
								</td>
								<td class="r num">{n.workloads}</td>
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
		{/if}
	</section>

	<p class="foot muted">
		{#each Object.entries(s.reports).filter(([, n]) => n > 0) as [k, n], i (k)}{i ? ' · ' : ''}{n} {k}{/each}
		{#if s.staleWorkloads}<br />{s.staleWorkloads} old ReplicaSet revisions are hidden from all counts.{/if}
		{#if s.scanners.length}<br />Scanners: {s.scanners.join(', ')}{/if}
	</p>
{/if}

<style>
	.head {
		display: flex;
		align-items: baseline;
		justify-content: space-between;
		gap: 12px;
		flex-wrap: wrap;
		margin-bottom: 16px;
	}
	h1 {
		font-size: 22px;
		font-weight: 600;
		letter-spacing: -0.01em;
	}
	.fresh {
		font-size: 13px;
	}
	.tiles {
		display: grid;
		grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
		gap: 12px;
		margin-bottom: 16px;
	}
	.grid {
		display: grid;
		grid-template-columns: minmax(0, 1.7fr) minmax(0, 1fr);
		gap: 16px;
		margin-bottom: 16px;
	}
	.pad {
		padding: 16px;
	}
	.row-head {
		display: flex;
		justify-content: space-between;
		align-items: baseline;
	}
	.small {
		font-size: 12.5px;
	}
	.imgcell {
		max-width: 340px;
	}
	.sevcell {
		min-width: 230px;
	}
	.sevcell :global(.track) {
		margin-top: 6px;
	}
	.comp {
		display: flex;
		flex-direction: column;
		gap: 16px;
	}
	.comp li {
		display: flex;
		flex-direction: column;
		gap: 6px;
	}
	.comp a {
		display: flex;
		justify-content: space-between;
		gap: 12px;
		font-size: 13.5px;
	}
	.comp a:hover .ctitle {
		text-decoration: underline;
	}
	.pct {
		font-weight: 600;
	}
	.scroll {
		overflow-x: auto;
	}
	.foot {
		font-size: 12px;
		line-height: 1.7;
		margin-top: 16px;
	}
	code {
		font-family: var(--font-mono);
		font-size: 12px;
	}
	@media (max-width: 1100px) {
		.grid {
			grid-template-columns: minmax(0, 1fr);
		}
	}
</style>
