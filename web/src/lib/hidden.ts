// Hiding and unhiding; pages refetch right away through live.bump.

import { apiSend } from './api';
import { live } from './live.svelte';
import type { HideTarget, MarkInfo } from './types';

/** Hides target. A note of undefined keeps the note of an earlier hide. */
export async function hide(target: HideTarget, note?: string): Promise<MarkInfo> {
	const m = await apiSend<MarkInfo>('POST', 'hidden', { target, note });
	live.bump();
	return m;
}

export async function unhide(id: number): Promise<void> {
	await apiSend<void>('DELETE', 'hidden/' + id);
	live.bump();
}
