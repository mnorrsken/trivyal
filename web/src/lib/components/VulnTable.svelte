<script lang="ts">
	// Vulnerabilities of one image, filtered in the browser (lists are small).
	import { date, sevLabel, severities } from '../format';
	import type { Vulnerability } from '../types';
	import Empty from './Empty.svelte';
	import SevBadge from './SevBadge.svelte';

	let { vulns }: { vulns: Vulnerability[] } = $props();

	let text = $state('');
	let sev = $state<string[]>([]);
	let fixable = $state(false);
	let limit = $state(100);
	let open = $state<string | null>(null);

	const counts = $derived(
		Object.fromEntries(severities.map((s) => [s, vulns.filter((v) => v.severity === s).length]))
	);
	const rows = $derived.by(() => {
		const t = text.trim().toLowerCase();
		return vulns.filter(
			(v) =>
				(!sev.length || sev.includes(v.severity)) &&
				(!fixable || !!v.fixedVersion) &&
				(!t ||
					v.vulnerabilityID.toLowerCase().includes(t) ||
					v.resource.toLowerCase().includes(t) ||
					(v.title ?? '').toLowerCase().includes(t))
		);
	});

	function toggleSev(s: string) {
		sev = sev.includes(s) ? sev.filter((x) => x !== s) : [...sev, s];
		limit = 100;
	}
	const key = (v: Vulnerability) => v.vulnerabilityID + v.resource + v.installedVersion + (v.target ?? '');
</script>

<div class="bar">
	<input class="search" placeholder="Filter by CVE, package or title" bind:value={text} oninput={() => (limit = 100)} />
	<div class="sevs">
		{#each severities as s (s)}
			{#if counts[s]}
				<button class="chip {s.toLowerCase()}" class:on={sev.includes(s)} onclick={() => toggleSev(s)}>
					<span class="dot"></span>{sevLabel(s)} <span class="num muted">{counts[s]}</span>
				</button>
			{/if}
		{/each}
		<label class="fix"><input type="checkbox" bind:checked={fixable} /> Fixable only</label>
	</div>
</div>

{#if rows.length === 0}
	<Empty title={vulns.length ? 'No vulnerabilities match' : 'No vulnerabilities found'} good={!vulns.length} />
{:else}
	<div class="wrap">
		<table class="table">
			<thead>
				<tr>
					<th>Severity</th>
					<th>Vulnerability</th>
					<th>Package</th>
					<th>Installed</th>
					<th>Fixed in</th>
					<th class="r">Score</th>
					<th>Published</th>
				</tr>
			</thead>
			<tbody>
				{#each rows.slice(0, limit) as v (key(v))}
					<tr class="row" onclick={() => (open = open === key(v) ? null : key(v))}>
						<td><SevBadge severity={v.severity} small /></td>
						<td class="main">
							<a class="link mono" href="/cve/{encodeURIComponent(v.vulnerabilityID)}" onclick={(e) => e.stopPropagation()}
								>{v.vulnerabilityID}</a
							>
							{#if v.title}<div class="ink2 small trunc t" title={v.title}>{v.title}</div>{/if}
						</td>
						<td class="mono small">{v.resource}</td>
						<td class="mono small">{v.installedVersion}</td>
						<td class="mono small">
							{#if v.fixedVersion}<span class="fixed">{v.fixedVersion}</span>{:else}<span class="muted">—</span>{/if}
						</td>
						<td class="r num">{v.score?.toFixed(1) ?? '—'}</td>
						<td class="small ink2 num">{date(v.publishedDate)}</td>
					</tr>
					{#if open === key(v)}
						<tr class="detail">
							<td colspan="7">
								{#if v.description}<p class="prose-sm">{v.description}</p>{/if}
								<dl>
									{#if v.target}<dt>Target</dt><dd class="mono">{v.target}</dd>{/if}
									{#if v.packagePath}<dt>Path</dt><dd class="mono">{v.packagePath}</dd>{/if}
									{#if v.packagePURL}<dt>PURL</dt><dd class="mono">{v.packagePURL}</dd>{/if}
									{#if v.class}<dt>Class</dt><dd>{v.class}</dd>{/if}
									{#if v.primaryLink}<dt>Link</dt><dd>
											<a class="link" href={v.primaryLink} target="_blank" rel="noreferrer">{v.primaryLink}</a>
										</dd>{/if}
								</dl>
							</td>
						</tr>
					{/if}
				{/each}
			</tbody>
		</table>
	</div>
	{#if rows.length > limit}
		<button class="btn more" onclick={() => (limit += 200)}>Show more ({rows.length - limit} left)</button>
	{/if}
{/if}

<style>
	.bar {
		display: flex;
		gap: 12px;
		flex-wrap: wrap;
		align-items: center;
		padding: 12px;
		border-bottom: 1px solid var(--hairline);
	}
	.search {
		flex: 1 1 240px;
		height: 34px;
		padding: 0 10px;
		border-radius: 7px;
		border: 1px solid var(--hairline);
		background: var(--page);
		color: var(--ink);
		font-size: 13px;
	}
	.sevs {
		display: flex;
		gap: 6px;
		flex-wrap: wrap;
		align-items: center;
	}
	.chip {
		display: inline-flex;
		align-items: center;
		gap: 6px;
		height: 28px;
		padding: 0 10px;
		border-radius: 999px;
		border: 1px solid var(--hairline);
		font-size: 12.5px;
	}
	.chip.on {
		background: var(--accent-wash);
		border-color: var(--accent);
	}
	.dot {
		width: 8px;
		height: 8px;
		border-radius: 999px;
		background: var(--sev-unknown);
	}
	.critical .dot {
		background: var(--sev-critical);
	}
	.high .dot {
		background: var(--sev-high);
	}
	.medium .dot {
		background: var(--sev-medium);
	}
	.low .dot {
		background: var(--sev-low);
	}
	.fix {
		display: flex;
		gap: 6px;
		align-items: center;
		font-size: 13px;
		margin-left: 6px;
	}
	.wrap {
		overflow-x: auto;
	}
	.row {
		cursor: pointer;
	}
	.main {
		min-width: 200px;
		max-width: 420px;
	}
	.t {
		margin-top: 2px;
	}
	.small {
		font-size: 12px;
	}
	.fixed {
		color: var(--good-ink);
	}
	.detail td {
		background: var(--surface-2);
	}
	dl {
		display: grid;
		grid-template-columns: 80px 1fr;
		gap: 4px 12px;
		margin-top: 8px;
		font-size: 12.5px;
	}
	dt {
		color: var(--muted);
	}
	dd {
		word-break: break-all;
	}
	.more {
		margin: 12px;
	}
</style>
