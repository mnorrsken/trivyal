// Fetcher keeps the last good result while a refetch runs (no skeleton
// flash) and drops responses that arrive out of order.

export class Fetcher<T> {
	data = $state<T | null>(null);
	error = $state<string | null>(null);
	loading = $state(false);
	#seq = 0;

	async run(fn: () => Promise<T>) {
		const seq = ++this.#seq;
		this.loading = true;
		try {
			const d = await fn();
			if (seq !== this.#seq) return;
			this.data = d;
			this.error = null;
		} catch (e) {
			if (seq !== this.#seq) return;
			this.error = e instanceof Error ? e.message : String(e);
		} finally {
			if (seq === this.#seq) this.loading = false;
		}
	}
}
