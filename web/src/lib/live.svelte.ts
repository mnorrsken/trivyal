// Live updates: the server pushes a "changed" event (debounced) whenever a
// report changes; pages refetch when live.generation changes.

class Live {
	generation = $state(0);
	connected = $state(false);
	#es: EventSource | null = null;

	start() {
		if (this.#es || typeof EventSource === 'undefined') return;
		const es = new EventSource('/api/v1/events');
		this.#es = es;
		es.addEventListener('hello', () => (this.connected = true));
		es.addEventListener('changed', (e) => {
			this.generation = Number((e as MessageEvent).data) || this.generation + 1;
		});
		es.onerror = () => (this.connected = false);
		es.onopen = () => (this.connected = true);
	}

	/** Refetch now, after a change made here (the server event comes later). */
	bump() {
		this.generation++;
	}
}

export const live = new Live();
