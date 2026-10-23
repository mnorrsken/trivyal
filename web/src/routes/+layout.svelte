<script lang="ts">
	import '../app.css';
	import { page } from '$app/state';
	import { onMount } from 'svelte';
	import Search from '#lib/components/Search.svelte';
	import { live } from '#lib/live.svelte.ts';
	import { schemas } from '#lib/schema.svelte.ts';
	import { api } from '#lib/api.ts';
	import type { LayoutProps } from './$types';

	let { children }: LayoutProps = $props();
	let menu = $state(false);
	let version = $state('');
	let theme = $state<'auto' | 'light' | 'dark'>('auto');
	let user = $state<{ name?: string; email?: string } | null>(null);

	const nav = [
		{ href: '/', label: 'Dashboard', exact: true },
		{ href: '/vulnerabilities', label: 'Vulnerabilities' },
		{ href: '/checks/config', label: 'Config audit' },
		{ href: '/secrets', label: 'Exposed secrets' },
		{ href: '/checks/rbac', label: 'RBAC' },
		{ href: '/checks/infra', label: 'Infrastructure' },
		{ href: '/compliance', label: 'Compliance' },
		{ href: '/sbom', label: 'SBOM' },
		{ href: '/hidden', label: 'Hidden' }
	];
	const clusterNav = [
		{ href: '/workloads', label: 'Workloads', also: ['/workload', '/pod'] },
		{ href: '/namespaces', label: 'Namespaces', also: ['/namespace'] },
		{ href: '/nodes', label: 'Nodes', also: ['/node'] }
	];

	function isActive(href: string, exact = false) {
		const p = page.url.pathname;
		return exact ? p === href : p === href || p.startsWith(href + '/');
	}

	onMount(() => {
		live.start();
		schemas.load();
		api<{ version: string }>('version')
			.then((v) => (version = v.version))
			.catch(() => {});
		// Only answers when OIDC login is enabled.
		fetch('/auth/me')
			.then((r) => (r.ok ? r.json() : null))
			.then((u) => (user = u))
			.catch(() => {});
		try {
			const t = localStorage.getItem('trivyal-theme');
			if (t === 'light' || t === 'dark') theme = t;
		} catch {
			/* storage blocked */
		}
	});

	function cycleTheme() {
		theme = theme === 'auto' ? 'dark' : theme === 'dark' ? 'light' : 'auto';
		if (theme === 'auto') delete document.documentElement.dataset.theme;
		else document.documentElement.dataset.theme = theme;
		try {
			if (theme === 'auto') localStorage.removeItem('trivyal-theme');
			else localStorage.setItem('trivyal-theme', theme);
		} catch {
			/* storage blocked */
		}
	}

	$effect(() => {
		page.url.pathname;
		menu = false;
	});
</script>

<svelte:head>
	<title>trivyal</title>
</svelte:head>

<div class="shell">
	<header class="mobile">
		<button class="burger" onclick={() => (menu = !menu)} aria-label="Menu">☰</button>
		<a href="/" class="brand">trivyal</a>
	</header>
	<nav class:open={menu}>
		<a href="/" class="brand desktop">
			<img src="/favicon.svg" alt="" width="22" height="22" />
			trivyal
		</a>
		<Search />
		<ul>
			{#each nav as n (n.href)}
				<li><a href={n.href} class:active={isActive(n.href, n.exact)}>{n.label}</a></li>
			{/each}
		</ul>
		<div class="navhead">Cluster</div>
		<ul>
			{#each clusterNav as n (n.href)}
				<li>
					<a href={n.href} class:active={isActive(n.href) || n.also.some((a) => isActive(a))}>{n.label}</a>
				</li>
			{/each}
		</ul>
		{#if user}
			<div class="user">
				<span class="trunc" title={user.email}>{user.name || user.email}</span>
				<a href="/auth/logout" data-sveltekit-reload>Sign out</a>
			</div>
		{/if}
		<div class="foot">
			<span class="live" class:on={live.connected} title={live.connected ? 'Live updates on' : 'Live updates off'}
				><span class="dot"></span>{live.connected ? 'Live' : 'Offline'}</span
			>
			<button class="theme" onclick={cycleTheme} title="Theme: {theme}">
				{theme === 'auto' ? 'Auto' : theme === 'dark' ? 'Dark' : 'Light'}
			</button>
			{#if version}<span class="ver muted">{version}</span>{/if}
		</div>
	</nav>
	<main>
		{@render children()}
	</main>
</div>

<style>
	.shell {
		display: grid;
		grid-template-columns: 228px minmax(0, 1fr);
		min-height: 100vh;
	}
	nav {
		position: sticky;
		top: 0;
		height: 100vh;
		display: flex;
		flex-direction: column;
		gap: 14px;
		padding: 18px 14px;
		border-right: 1px solid var(--hairline);
		background: var(--surface);
	}
	.brand {
		display: flex;
		align-items: center;
		gap: 9px;
		font-weight: 650;
		font-size: 16px;
		letter-spacing: -0.01em;
		padding: 0 4px;
	}
	ul {
		display: flex;
		flex-direction: column;
		gap: 1px;
	}
	.navhead {
		font-size: 11px;
		font-weight: 600;
		letter-spacing: 0.04em;
		text-transform: uppercase;
		color: var(--muted);
		padding: 0 10px;
		margin-bottom: -8px;
	}
	ul a {
		display: block;
		padding: 7px 10px;
		border-radius: 6px;
		font-size: 13.5px;
		color: var(--ink-2);
	}
	ul a:hover {
		background: var(--surface-2);
		color: var(--ink);
	}
	ul a.active {
		background: var(--accent-wash);
		color: var(--accent-ink);
		font-weight: 550;
	}
	.user {
		margin-top: auto;
		display: flex;
		justify-content: space-between;
		gap: 8px;
		font-size: 12.5px;
		padding: 0 4px;
		color: var(--ink-2);
	}
	.user a {
		color: var(--accent-ink);
		flex: none;
	}
	.user + .foot {
		margin-top: 0;
	}
	.foot {
		margin-top: auto;
		display: flex;
		align-items: center;
		gap: 10px;
		font-size: 12px;
		padding: 0 4px;
	}
	.live {
		display: inline-flex;
		align-items: center;
		gap: 6px;
		color: var(--muted);
	}
	.live .dot {
		width: 7px;
		height: 7px;
		border-radius: 999px;
		background: var(--axis);
	}
	.live.on .dot {
		background: var(--good);
	}
	.theme {
		border: 1px solid var(--hairline);
		border-radius: 5px;
		padding: 1px 7px;
		color: var(--ink-2);
	}
	.ver {
		margin-left: auto;
	}
	main {
		padding: 24px 28px 48px;
		min-width: 0;
		max-width: 1440px;
	}
	.mobile {
		display: none;
	}
	@media (max-width: 860px) {
		.shell {
			grid-template-columns: minmax(0, 1fr);
		}
		.mobile {
			display: flex;
			align-items: center;
			gap: 10px;
			padding: 10px 16px;
			border-bottom: 1px solid var(--hairline);
			background: var(--surface);
			position: sticky;
			top: 0;
			z-index: 20;
		}
		.burger {
			font-size: 18px;
			width: 32px;
			height: 32px;
		}
		.desktop {
			display: none;
		}
		nav {
			display: none;
			position: fixed;
			top: 53px;
			left: 0;
			right: 0;
			bottom: 0;
			height: auto;
			z-index: 40;
		}
		nav.open {
			display: flex;
		}
		main {
			padding: 16px 16px 40px;
		}
	}
</style>
