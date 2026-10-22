<script lang="ts">
	// Image reference with the registry/repository dimmed and the tag strong.
	import { imageHref, splitImage } from '../format';

	let { ref, key, link = true }: { ref: string; key?: string; link?: boolean } = $props();
	const parts = $derived(splitImage(ref));
	const slash = $derived(parts.repo.lastIndexOf('/'));
</script>

{#if link && key}
	<a class="img" href={imageHref(key)} title={ref}>
		<span class="trunc"
			><span class="muted">{parts.repo.slice(0, slash + 1)}</span><span class="name">{parts.repo.slice(slash + 1)}</span
			>{#if parts.tag}<span class="tag">:{parts.tag}</span>{/if}</span
		>
	</a>
{:else}
	<span class="img" title={ref}>
		<span class="trunc"
			><span class="muted">{parts.repo.slice(0, slash + 1)}</span><span class="name">{parts.repo.slice(slash + 1)}</span
			>{#if parts.tag}<span class="tag">:{parts.tag}</span>{/if}</span
		>
	</span>
{/if}

<style>
	.img {
		display: inline-flex;
		max-width: min(100%, 380px);
		min-width: 0;
		font-family: var(--font-mono);
		font-size: 12.5px;
	}
	a.img:hover .name {
		text-decoration: underline;
		color: var(--accent-ink);
	}
	.name {
		font-weight: 500;
	}
	.tag {
		color: var(--ink-2);
	}
</style>
