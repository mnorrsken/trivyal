<script lang="ts">
	import { page } from '$app/state';
	import { api } from '#lib/api.ts';
	import { Fetcher } from '#lib/fetcher.svelte.ts';
	import { live } from '#lib/live.svelte.ts';
	import { ago, imageHref, shortDigest } from '#lib/format.ts';
	import type { PodInfo } from '#lib/types.ts';
	import Empty from '#lib/components/Empty.svelte';
	import ImageName from '#lib/components/ImageName.svelte';
	import WorkloadLink from '#lib/components/WorkloadLink.svelte';

	type Detail = PodInfo & { images: Record<string, string> };

	const ns = $derived(page.params.ns ?? '');
	const name = $derived(page.params.name ?? '');
	const f = new Fetcher<Detail>();
	$effect(() => {
		const p = `pod/${encodeURIComponent(ns)}/${encodeURIComponent(name)}`;
		live.generation;
		f.run(() => api<Detail>(p));
	});
	const d = $derived(f.data);
</script>

<svelte:head><title>{name} · trivyal</title></svelte:head>

{#if f.error}
	<div class="card"><Empty title="Pod not found">{f.error}. It may have been replaced; look at its workload.</Empty></div>
{:else if d}
	<header>
		<p class="crumb muted">
			<a class="link" href="/namespace/{encodeURIComponent(d.namespace)}">{d.namespace}</a> / pods /
		</p>
		<h1><span class="kind">Pod</span> {d.name}</h1>
		<div class="facts">
			<span class="pill" class:good={d.phase === 'Running'}>{d.phase}</span>
			{#if d.node}<a class="pill" href="/node/{encodeURIComponent(d.node)}">node {d.node}</a>{/if}
			{#if d.ip}<span class="pill mono">{d.ip}</span>{/if}
			{#if d.started}<span class="pill">started {ago(d.started)}</span>{/if}
		</div>
		<p class="owner">Part of <WorkloadLink w={d.workload} /></p>
	</header>

	<section class="card sec">
		<table class="table">
			<thead><tr><th>Container</th><th>Image</th><th>Digest</th><th>State</th><th class="r">Restarts</th></tr></thead>
			<tbody>
				{#each d.containers ?? [] as c (c.name + c.init)}
					{@const key = d.images[c.name]}
					<tr>
						<td class="mono small">{c.name}{#if c.init}<span class="pill init">init</span>{/if}</td>
						<td class="img"><ImageName ref={c.image} {key} link={!!key} /></td>
						<td class="mono small muted" title={c.digest}>{shortDigest(c.digest)}</td>
						<td><span class="pill" class:good={c.ready}>{c.state}</span></td>
						<td class="r num">{c.restarts}</td>
					</tr>
				{/each}
			</tbody>
		</table>
		{#if Object.keys(d.images).length}
			<p class="note muted">Click an image for its vulnerabilities, secrets and SBOM.</p>
		{:else}
			<p class="note muted">No trivy reports match this pod's images yet.</p>
		{/if}
	</section>

	{#if d.labels && Object.keys(d.labels).length}
		<section class="card sec pad">
			<h2 class="section-title">Labels</h2>
			<div class="labels">
				{#each Object.entries(d.labels) as [k, v] (k)}<span class="pill mono">{k}={v}</span>{/each}
			</div>
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
		margin: 10px 0;
	}
	.owner {
		font-size: 13px;
		margin-bottom: 16px;
		display: flex;
		gap: 8px;
		align-items: center;
	}
	.sec {
		margin-bottom: 16px;
		overflow-x: auto;
	}
	.pad {
		padding: 16px;
	}
	.small {
		font-size: 12px;
	}
	.img {
		max-width: 380px;
	}
	.init {
		margin-left: 6px;
	}
	.note {
		font-size: 12px;
		padding: 10px 12px;
	}
	.labels {
		display: flex;
		flex-wrap: wrap;
		gap: 6px;
	}
</style>
