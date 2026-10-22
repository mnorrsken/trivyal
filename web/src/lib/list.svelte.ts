// ListState keeps list filters, grouping, sorting and paging in the URL so
// every view can be bookmarked and shared.

import { goto } from '$app/navigation';
import { page } from '$app/state';

export class ListState {
	constructor(private defaults: { group?: string; size?: number } = {}) {}

	get q() {
		return page.url.searchParams.get('q') ?? '';
	}
	get group() {
		return page.url.searchParams.get('group') ?? this.defaults.group ?? '';
	}
	get sort() {
		return page.url.searchParams.get('sort') ?? '';
	}
	get page() {
		return Number(page.url.searchParams.get('page')) || 1;
	}
	get size() {
		return Number(page.url.searchParams.get('size')) || this.defaults.size || 50;
	}
	get stale() {
		return page.url.searchParams.get('stale') === '1';
	}

	/** Parameters for the API call. */
	get params(): Record<string, string | number | undefined> {
		return {
			q: this.q,
			group: this.group,
			sort: this.sort,
			page: this.page,
			size: this.size,
			stale: this.stale ? '1' : undefined
		};
	}

	/** Sets URL parameters; anything but a page change goes back to page 1. */
	update(changes: Record<string, string | number | undefined | null>, replace = false) {
		const url = new URL(page.url.href);
		for (const [k, v] of Object.entries(changes)) {
			if (v === undefined || v === null || v === '') url.searchParams.delete(k);
			else url.searchParams.set(k, String(v));
		}
		if (!('page' in changes)) url.searchParams.delete('page');
		if ('group' in changes) url.searchParams.delete('sort');
		if (url.searchParams.get('group') === this.defaults.group) url.searchParams.delete('group');
		goto(url, { replace, reset: false });
	}

	setQ(q: string, replace = false) {
		this.update({ q }, replace);
	}

	/**
	 * Click on a sortable column: first click sorts by it, second reverses.
	 * current is the sort the server applied (it fills in the default).
	 */
	toggleSort(key: string, current: string) {
		this.update({ sort: current === key ? '-' + key : key });
	}
}
