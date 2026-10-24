<script lang="ts">
	// Failed checks with expandable description and fix; rows can flag or
	// hide the check on their resource.
	import { checkTypes } from '../checks';
	import type { CheckFinding } from '../types';
	import Empty from './Empty.svelte';
	import MarkMenu from './MarkMenu.svelte';
	import SevBadge from './SevBadge.svelte';
	import WorkloadLink from './WorkloadLink.svelte';

	let {
		findings,
		type = 'config',
		showResource = false,
		empty = 'No misconfigurations'
	}: { findings: CheckFinding[]; type?: string; showResource?: boolean; empty?: string } = $props();
	let open = $state<number | null>(null);
	const typeKnown = $derived(type in checkTypes);
</script>

{#if findings.length === 0}
	<Empty title={empty} good />
{:else}
	<table class="table">
		<thead>
			<tr>
				<th>Severity</th>
				<th>Check</th>
				{#if showResource}<th>Resource</th>{/if}
				<th>Message</th>
				{#if typeKnown}<th></th>{/if}
			</tr>
		</thead>
		<tbody>
			{#each findings as f, i (f.report.name + f.check.checkID + i)}
				<tr class="row" onclick={() => (open = open === i ? null : i)}>
					<td><SevBadge severity={f.check.severity} small /></td>
					<td class="title">
						{#if typeKnown}
							<a class="link mono small" href="/checks/{type}/{encodeURIComponent(f.check.checkID)}" onclick={(e) => e.stopPropagation()}
								>{f.check.checkID}</a
							>
						{:else}<span class="mono small">{f.check.checkID}</span>{/if}
						<div>{f.check.title}</div>
					</td>
					{#if showResource}<td class="res"><WorkloadLink w={f.resource} /></td>{/if}
					<td class="small ink2">{f.check.messages?.join(' ') ?? ''}</td>
					{#if typeKnown}
						<td class="r mark-col">
							<MarkMenu target={{ kind: 'resource-check', type, id: f.check.checkID, resource: f.resource }} contains={f.flagged} row />
						</td>
					{/if}
				</tr>
				{#if open === i}
					<tr class="detail">
						<td colspan={(showResource ? 4 : 3) + (typeKnown ? 1 : 0)}>
							{#if f.check.description}<p class="prose-sm">{f.check.description}</p>{/if}
							{#if f.check.remediation}<p class="prose-sm fix"><strong>Fix:</strong> {f.check.remediation}</p>{/if}
						</td>
					</tr>
				{/if}
			{/each}
		</tbody>
	</table>
{/if}

<style>
	.row {
		cursor: pointer;
	}
	.title {
		max-width: 380px;
	}
	.res {
		max-width: 300px;
	}
	.small {
		font-size: 12px;
	}
	.detail td {
		background: var(--surface-2);
	}
	.fix {
		margin-top: 6px;
	}

</style>
