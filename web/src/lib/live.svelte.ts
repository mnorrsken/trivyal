// Live updates: the server pushes a "changed" event (debounced) whenever
// something in the cluster changes. Only pages that show ongoing work (the
// scans list) follow it, through live.cluster; refetching every page on
// every node heartbeat made them blink. live.generation changes only after
// a change made here (a flag or hide), so lists drop what was just hidden.

class Live {
	generation = $state(0);
	cluster = $state(0);
	connected = $state(false);
	#es: EventSource | null = null;

	start() {
		if (this.#es || typeof EventSource === 'undefined') return;
		const es = new EventSource('/api/v1/events');
		this.#es = es;
		es.addEventListener('hello', () => (this.connected = true));
		es.addEventListener('changed', (e) => {
			this.cluster = Number((e as MessageEvent).data) || this.cluster + 1;
		});
		es.onerror = () => (this.connected = false);
		es.onopen = () => (this.connected = true);
	}

	/** Refetch now, after a change made here. */
	bump() {
		this.generation++;
	}
}

export const live = new Live();
