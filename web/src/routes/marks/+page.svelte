<script lang="ts">
	import { api } from '#lib/api.ts';
	import { Fetcher } from '#lib/fetcher.svelte.ts';
	import { live } from '#lib/live.svelte.ts';
	import { ago, date, int, qs, workloadHref } from '#lib/format.ts';
	import type { MarkInfo, MarkTarget, Resource } from '#lib/types.ts';
	import Empty from '#lib/components/Empty.svelte';
	import MarkMenu from '#lib/components/MarkMenu.svelte';

	const f = new Fetcher<MarkInfo[]>();
	$effect(() => {
		live.generation;
		f.run(() => api<MarkInfo[]>('marks', { counts: 1 }));
	});
	// Flagged first; the server sends the most recently changed first.
	const rows = $derived([...(f.data ?? [])].sort((a, b) => Number(b.state === 'flagged') - Number(a.state === 'flagged')));

	const kinds: Record<MarkTarget['kind'], string> = {
		image: 'Image',
		'image-cve': 'Vulnerability in an image',
		cve: 'Vulnerability',
		secret: 'Secret',
		check: 'Check',
		'resource-check': 'Check on a resource',
		workload: 'Workload',
		namespace: 'Namespace'
	};
	const res = (r?: Resource) => (r ? [r.namespace, r.kind, r.name].filter(Boolean).join('/') : '');
	const checkHref = (t: MarkTarget) => `/checks/${t.type}/${encodeURIComponent(t.id ?? '')}`;

	// What the target is, and where its findings are listed.
	function describe(t: MarkTarget): { label: string; sub?: string; href: string } {
		switch (t.kind) {
			case 'image':
				return { label: t.image ?? '', href: '/vulnerabilities' + qs({ q: `image:${t.image}` }) };
			case 'image-cve':
				return { label: t.id ?? '', sub: 'in ' + t.image, href: `/cve/${encodeURIComponent(t.id ?? '')}` };
			case 'cve':
				return { label: t.id ?? '', href: `/cve/${encodeURIComponent(t.id ?? '')}` };
			case 'secret':
				return { label: t.rule ?? '', sub: `${t.file} in ${t.image}`, href: '/secrets' + qs({ q: `rule:${t.rule} image:${t.image}` }) };
			case 'check':
				return { label: t.id ?? '', sub: t.type, href: checkHref(t) };
			case 'resource-check':
				return { label: t.id ?? '', sub: 'on ' + res(t.resource), href: checkHref(t) };
			case 'workload':
				return { label: res(t.resource), href: t.resource ? workloadHref(t.resource) : '/workloads' };
			case 'namespace':
				return { label: t.namespace ?? '', href: `/namespace/${encodeURIComponent(t.namespace ?? '')}` };
		}
	}
</script>

<svelte:head><title>Flagged & hidden · trivyal</title></svelte:head>

<div class="head">
	<h1>Flagged & hidden</h1>
	<p class="muted sub">
		Flagged items come first in lists, with everything found in them now and later. Hiding hides the findings found now; findings
		that turn up later, for example in a new image build, show again.
	</p>
</div>

{#if f.error}
	<div class="card"><Empty title="Could not load flagged and hidden items">{f.error}</Empty></div>
{:else if f.data && f.data.length === 0}
	<div class="card">
		<Empty title="Nothing is flagged or hidden">Use the Mark pills on images, vulnerabilities, workloads, namespaces, secrets and checks.</Empty>
	</div>
{:else if f.data}
	<section class="card wrap">
		<table class="table">
			<thead>
				<tr>
					<th>State</th>
					<th>Kind</th>
					<th>Target</th>
					<th>Note</th>
					<th class="r">Findings</th>
					<th>Since</th>
				</tr>
			</thead>
			<tbody>
				{#each rows as m (m.id)}
					{@const d = describe(m.target)}
					<tr>
						<td><MarkMenu target={m.target} /></td>
						<td class="small ink2">{kinds[m.target.kind] ?? m.target.kind}</td>
						<td class="main">
							<a class="link mono small" href={d.href}>{d.label}</a>
							{#if d.sub}<div class="muted small mono trunc">{d.sub}</div>{/if}
						</td>
						<td class="small note">{m.note}</td>
						<td class="r num small">
							{#if m.counts && m.state === 'hidden'}
								{int(m.counts.now - m.counts.new)} hidden
								{#if m.counts.new}<div class="new">{int(m.counts.new)} new, shown</div>{/if}
							{:else if m.counts}
								{int(m.counts.now)}
							{/if}
						</td>
						<td class="small ink2 num" title={date(m.updated)}>{ago(m.updated)}</td>
					</tr>
				{/each}
			</tbody>
		</table>
	</section>
{/if}

<style>
	.head {
		margin-bottom: 16px;
	}
	h1 {
		font-size: 22px;
		font-weight: 600;
	}
	.sub {
		font-size: 13px;
		margin-top: 2px;
		max-width: 760px;
	}
	.wrap {
		overflow-x: auto;
	}
	.main {
		min-width: 220px;
		max-width: 460px;
	}
	.note {
		max-width: 320px;
		color: var(--ink-2);
	}
	.small {
		font-size: 12px;
	}
	.new {
		color: var(--accent-ink);
		font-weight: 550;
	}
</style>
