<script lang="ts">
	// Tells that some findings on the page are hidden, with a link to manage them.
	import { int } from '../format';

	let { count, noun = 'finding' }: { count?: number; noun?: string } = $props();
</script>

{#if count}
	<p class="note muted">
		{int(count)} hidden {noun}{count === 1 ? '' : 's'} not shown. <a class="link" href="/marks">Manage</a>
	</p>
{/if}

<style>
	.note {
		font-size: 12.5px;
		margin-top: 8px;
	}
</style>
