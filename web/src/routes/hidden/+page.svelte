<script lang="ts">
	import { api } from '#lib/api.ts';
	import { Fetcher } from '#lib/fetcher.svelte.ts';
	import { live } from '#lib/live.svelte.ts';
	import { ago, date, int, qs, workloadHref } from '#lib/format.ts';
	import { hide, unhide } from '#lib/hidden.ts';
	import type { HideTarget, MarkInfo, Resource } from '#lib/types.ts';
	import Empty from '#lib/components/Empty.svelte';

	const f = new Fetcher<MarkInfo[]>();
	$effect(() => {
		live.generation;
		f.run(() => api<MarkInfo[]>('hidden'));
	});
	let busy = $state<number | null>(null);
	let error = $state<string | null>(null);

	async function run(id: number, fn: () => Promise<unknown>) {
		busy = id;
		error = null;
		try {
			await fn();
		} catch (e) {
			error = e instanceof Error ? e.message : String(e);
		} finally {
			busy = null;
		}
	}

	const kinds: Record<HideTarget['kind'], string> = {
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
	const checkHref = (t: HideTarget) => `/checks/${t.type}/${encodeURIComponent(t.id ?? '')}`;

	// What the target is, and where its findings are listed (with hidden ones).
	function describe(t: HideTarget): { label: string; sub?: string; href: string } {
		switch (t.kind) {
			case 'image':
				return { label: t.image ?? '', href: '/vulnerabilities' + qs({ q: `image:${t.image}`, hidden: '1' }) };
			case 'image-cve':
				return { label: t.id ?? '', sub: 'in ' + t.image, href: `/cve/${encodeURIComponent(t.id ?? '')}?hidden=1` };
			case 'cve':
				return { label: t.id ?? '', href: `/cve/${encodeURIComponent(t.id ?? '')}` };
			case 'secret':
				return {
					label: t.rule ?? '',
					sub: `${t.file} in ${t.image}`,
					href: '/secrets' + qs({ q: `rule:${t.rule} image:${t.image}`, hidden: '1' })
				};
			case 'check':
				return { label: t.id ?? '', sub: t.type, href: checkHref(t) };
			case 'resource-check':
				return { label: t.id ?? '', sub: 'on ' + res(t.resource), href: checkHref(t) + '?hidden=1' };
			case 'workload':
				return { label: res(t.resource), href: t.resource ? workloadHref(t.resource) : '/workloads' };
			case 'namespace':
				return { label: t.namespace ?? '', href: `/namespace/${encodeURIComponent(t.namespace ?? '')}` };
		}
	}
</script>

<svelte:head><title>Hidden · trivyal</title></svelte:head>

<div class="head">
	<h1>Hidden</h1>
	<p class="muted sub">
		Hiding something hides the findings it has now. Findings that turn up later, for example in a new image build, show again.
	</p>
</div>

{#if f.error}
	<div class="card"><Empty title="Could not load hidden items">{f.error}</Empty></div>
{:else if f.data && f.data.length === 0}
	<div class="card">
		<Empty title="Nothing is hidden">Use the Hide buttons on images, vulnerabilities, workloads, namespaces, secrets and checks.</Empty>
	</div>
{:else if f.data}
	{#if error}<p class="err">{error}</p>{/if}
	<section class="card wrap">
		<table class="table">
			<thead>
				<tr>
					<th>Kind</th>
					<th>Hidden</th>
					<th>Note</th>
					<th class="r">Findings</th>
					<th>Since</th>
					<th></th>
				</tr>
			</thead>
			<tbody>
				{#each f.data as m (m.id)}
					{@const d = describe(m.target)}
					<tr>
						<td class="small ink2">{kinds[m.target.kind] ?? m.target.kind}</td>
						<td class="main">
							<a class="link mono small" href={d.href}>{d.label}</a>
							{#if d.sub}<div class="muted small mono trunc">{d.sub}</div>{/if}
						</td>
						<td class="small note">{m.note}</td>
						<td class="r num small">
							{int(m.hiding)} hidden
							{#if m.new}<div class="new">{int(m.new)} new</div>{/if}
						</td>
						<td class="small ink2 num" title={date(m.updated)}>{ago(m.updated)}</td>
						<td class="r actions">
							{#if m.new}
								<button class="btn small" disabled={busy === m.id} onclick={() => run(m.id, () => hide(m.target))}>Hide new too</button>
							{/if}
							<button class="btn small" disabled={busy === m.id} onclick={() => run(m.id, () => unhide(m.id))}>Unhide</button>
						</td>
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
		max-width: 720px;
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
	.actions {
		white-space: nowrap;
	}
	.actions .btn + .btn {
		margin-left: 6px;
	}
	.btn.small {
		height: 24px;
		font-size: 12px;
		padding: 0 8px;
	}
	.err {
		color: var(--sev-critical);
		margin-bottom: 8px;
	}
</style>
