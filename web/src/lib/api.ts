// Thin fetch wrapper for the Go API.

export class APIError extends Error {
	constructor(
		message: string,
		public status: number
	) {
		super(message);
	}
}

export async function api<T>(path: string, params?: Record<string, string | number | undefined>): Promise<T> {
	let url = '/api/v1/' + path;
	if (params) {
		const sp = new URLSearchParams();
		for (const [k, v] of Object.entries(params)) {
			if (v !== undefined && v !== '') sp.set(k, String(v));
		}
		const s = sp.toString();
		if (s) url += (url.includes('?') ? '&' : '?') + s;
	}
	return handle<T>(await fetch(url, { headers: { Accept: 'application/json' } }));
}

/** Sends a change (POST with a JSON body, DELETE). */
export async function apiSend<T>(method: 'POST' | 'DELETE', path: string, body?: unknown): Promise<T> {
	const res = await fetch('/api/v1/' + path, {
		method,
		headers: { Accept: 'application/json', ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) },
		body: body === undefined ? undefined : JSON.stringify(body)
	});
	return handle<T>(res);
}

async function handle<T>(res: Response): Promise<T> {
	if (res.status === 401) {
		// OIDC session expired: start a new login and come back here.
		location.href = '/auth/login?rd=' + encodeURIComponent(location.pathname + location.search);
		throw new APIError('login required', 401);
	}
	if (!res.ok) {
		let msg = res.statusText;
		try {
			msg = (await res.json()).error ?? msg;
		} catch {
			/* not JSON */
		}
		throw new APIError(msg, res.status);
	}
	return res.status === 204 ? (undefined as T) : res.json();
}
