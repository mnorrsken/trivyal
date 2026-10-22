<script lang="ts">
	import { api } from '#lib/api.ts';
	import { Fetcher } from '#lib/fetcher.svelte.ts';
	import { live } from '#lib/live.svelte.ts';
	import { total } from '#lib/format.ts';
	import type { NamespaceRow } from '#lib/types.ts';
	import Empty from '#lib/components/Empty.svelte';
	import SevBar from '#lib/components/SevBar.svelte';
	import SevCounts from '#lib/components/SevCounts.svelte';

	const f = new Fetcher<NamespaceRow[]>();
	$effect(() => {
		live.generation;
		f.run(() => api<NamespaceRow[]>('namespaces'));
	});
	let text = $state('');
	const rows = $derived((f.data ?? []).filter((n) => n.name.includes(text.trim().toLowerCase())));
	const max = $derived(Math.max(1, ...rows.map((n) => total(n.vulns))));
	const pss = (n: NamespaceRow) => n.labels?.['pod-security.kubernetes.io/enforce'];
</script>

<svelte:head><title>Namespaces · trivyal</title></svelte:head>

<div class="head">
	<div>
		<h1>Namespaces</h1>
		<p class="muted sub">A vulnerability counts once per image, even when several workloads in the namespace run it.</p>
	</div>
	<input placeholder="Filter namespaces" bind:value={text} />
</div>

{#if f.error}
	<div class="card"><Empty title="Could not load namespaces">{f.error}</Empty></div>
{:else if f.data}
	<section class="card wrap">
		<table class="table">
			<thead>
				<tr>
					<th>Namespace</th>
					<th class="r">Workloads</th>
					<th>Vulnerabilities</th>
					<th>Misconfigurations</th>
					<th class="r">Secrets</th>
					<th>Pod security</th>
				</tr>
			</thead>
			<tbody>
				{#each rows as n (n.name)}
					<tr>
						<td><a class="link" href="/namespace/{encodeURIComponent(n.name)}">{n.name}</a></td>
						<td class="r num">{n.workloads}</td>
						<td class="sev">
							<SevCounts counts={n.vulns} />
							<SevBar counts={n.vulns} {max} height={5} />
						</td>
						<td><SevCounts counts={n.config} showUnknown={false} /></td>
						<td class="r num">{n.secrets || ''}</td>
						<td class="small">
							{#if pss(n)}<span class="pill accent">{pss(n)}</span>{:else}<span class="muted">not enforced</span>{/if}
						</td>
					</tr>
				{/each}
			</tbody>
		</table>
	</section>
{/if}

<style>
	.head {
		display: flex;
		justify-content: space-between;
		align-items: flex-end;
		gap: 12px;
		flex-wrap: wrap;
		margin-bottom: 16px;
	}
	h1 {
		font-size: 22px;
		font-weight: 600;
	}
	.sub {
		font-size: 13px;
		margin-top: 2px;
	}
	input {
		height: 34px;
		width: 260px;
		padding: 0 10px;
		border-radius: 7px;
		border: 1px solid var(--hairline);
		background: var(--surface);
		color: var(--ink);
		font-size: 13px;
	}
	.wrap {
		overflow-x: auto;
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
