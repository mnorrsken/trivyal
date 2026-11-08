// Fetcher keeps the last good result while a refetch runs (no skeleton
// flash) and drops responses that arrive out of order.

export class Fetcher<T> {
	data = $state<T | null>(null);
	error = $state<string | null>(null);
	loading = $state(false);
	#seq = 0;
	#key: string | undefined;
	// Plain field: run() is called inside effects, and reading this.data
	// there would make every result trigger another run.
	#loaded = false;

	/**
	 * Runs fn. With a key, a rerun for the same key (a live refresh) keeps
	 * loading off, so the page does not dim.
	 */
	async run(fn: () => Promise<T>, key?: string) {
		const seq = ++this.#seq;
		const same = key !== undefined && key === this.#key && this.#loaded;
		this.#key = key;
		if (!same) this.loading = true;
		try {
			const d = await fn();
			if (seq !== this.#seq) return;
			this.data = d;
			this.#loaded = true;
			this.error = null;
		} catch (e) {
			if (seq !== this.#seq) return;
			this.error = e instanceof Error ? e.message : String(e);
		} finally {
			if (seq === this.#seq) this.loading = false;
		}
	}
}
