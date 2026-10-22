import { describe, expect, it } from 'vitest';
import { excluded, has, parse, remove, set, toggle, tokenize } from './filter';

describe('tokenize', () => {
	it('keeps quoted parts together', () => {
		expect(tokenize('a:"b c" d  "e f"')).toEqual(['a:"b c"', 'd', '"e f"']);
	});
});

describe('parse', () => {
	it('reads fields, values and negation', () => {
		expect(parse('sev:critical,high -ns:kube-system openssl')).toEqual([
			{ raw: 'sev:critical,high', field: 'sev', values: ['critical', 'high'], negate: false },
			{ raw: '-ns:kube-system', field: 'ns', values: ['kube-system'], negate: true },
			{ raw: 'openssl', values: ['openssl'], negate: false }
		]);
	});
});

describe('toggle', () => {
	it('adds a new term', () => {
		expect(toggle('openssl', 'sev', 'HIGH')).toBe('openssl sev:HIGH');
	});
	it('adds to an existing term', () => {
		expect(toggle('sev:critical', 'sev', 'high')).toBe('sev:critical,high');
	});
	it('removes a value and drops the empty term', () => {
		expect(toggle('sev:high ns:demo', 'sev', 'HIGH')).toBe('ns:demo');
	});
	it('handles negated terms separately', () => {
		expect(toggle('ns:demo', 'ns', 'kube-system', true)).toBe('ns:demo -ns:kube-system');
	});
	it('quotes values with spaces', () => {
		expect(toggle('', 'category', 'Kubernetes Security Check')).toBe('category:"Kubernetes Security Check"');
	});
	it('round-trips through has', () => {
		const s = toggle('', 'fixable', 'yes');
		expect(has(s, 'fixable', 'yes')).toBe(true);
		expect(has(toggle(s, 'fixable', 'yes'), 'fixable', 'yes')).toBe(false);
	});
});

describe('excluded, set, remove', () => {
	it('detects negated values', () => {
		expect(excluded('-ns:a,b', 'ns', 'B')).toBe(true);
		expect(has('-ns:a,b', 'ns', 'b')).toBe(false);
	});
	it('replaces terms', () => {
		expect(set('sev:low x -sev:high', 'sev', ['critical'])).toBe('x sev:critical');
		expect(set('sev:low x', 'sev', [])).toBe('x');
	});
	it('removes by index', () => {
		expect(remove('a:1 b c:2', 1)).toBe('a:1 c:2');
	});
});
