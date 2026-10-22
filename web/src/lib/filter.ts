// Helpers for the filter language (see internal/query): split a filter
// string into tokens and toggle facet values without disturbing the rest of
// what the user typed.

export interface Token {
	raw: string;
	field?: string;
	values: string[];
	negate: boolean;
}

export function tokenize(s: string): string[] {
	const out: string[] = [];
	let cur = '';
	let quoted = false;
	for (const ch of s) {
		if (ch === '"') {
			quoted = !quoted;
			cur += ch;
		} else if (/\s/.test(ch) && !quoted) {
			if (cur) out.push(cur);
			cur = '';
		} else {
			cur += ch;
		}
	}
	if (cur) out.push(cur);
	return out;
}

export function parse(s: string): Token[] {
	return tokenize(s).map((raw) => {
		let body = raw;
		let negate = false;
		if (body.startsWith('-') && body.length > 1) {
			negate = true;
			body = body.slice(1);
		}
		const i = body.indexOf(':');
		const name = i > 0 ? body.slice(0, i) : '';
		if (!name || name.includes('"')) {
			return { raw, values: [raw.replace(/"/g, '')], negate: false };
		}
		const values = body
			.slice(i + 1)
			.replace(/"/g, '')
			.split(',')
			.map((v) => v.trim())
			.filter(Boolean);
		return { raw, field: name.toLowerCase(), values, negate };
	});
}

function quote(v: string): string {
	return /[\s,]/.test(v) ? `"${v}"` : v;
}

export function format(t: Token): string {
	if (!t.field) return t.raw;
	return (t.negate ? '-' : '') + t.field + ':' + t.values.map(quote).join(',');
}

function join(tokens: Token[]): string {
	return tokens
		.filter((t) => !t.field || t.values.length)
		.map(format)
		.join(' ');
}

const eq = (a: string, b: string) => a.toLowerCase() === b.toLowerCase();

/** Reports whether a positive term on field includes value. */
export function has(s: string, field: string, value: string): boolean {
	return parse(s).some((t) => t.field === field && !t.negate && t.values.some((v) => eq(v, value)));
}

/** Reports whether a negated term on field includes value. */
export function excluded(s: string, field: string, value: string): boolean {
	return parse(s).some((t) => t.field === field && t.negate && t.values.some((v) => eq(v, value)));
}

/**
 * Adds value to the positive term on field, or removes it if present.
 * With negate, works on the "-field:" term instead.
 */
export function toggle(s: string, field: string, value: string, negate = false): string {
	const tokens = parse(s);
	const t = tokens.find((t) => t.field === field && t.negate === negate);
	if (t) {
		const i = t.values.findIndex((v) => eq(v, value));
		if (i >= 0) t.values.splice(i, 1);
		else t.values.push(value);
	} else {
		tokens.push({ raw: '', field, values: [value], negate });
	}
	return join(tokens);
}

/** Replaces every term on field with field:values (none removes it). */
export function set(s: string, field: string, values: string[]): string {
	const tokens = parse(s).filter((t) => t.field !== field);
	if (values.length) tokens.push({ raw: '', field, values, negate: false });
	return join(tokens);
}

/** Removes the token at index. */
export function remove(s: string, index: number): string {
	const tokens = parse(s);
	tokens.splice(index, 1);
	return join(tokens);
}
