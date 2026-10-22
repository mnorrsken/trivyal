// Package query parses and evaluates the filter language used by every list
// in the UI:
//
//	sev:critical,high ns:demo -kind:Job cve:CVE-2024-* score:>=7 "free text"
//
// Terms are field:value pairs (comma = OR, leading "-" = NOT) and all terms
// must match (AND). Words without a known field prefix are free text that
// must appear somewhere in the row. Values compare case-insensitively; "*"
// is a wildcard; "=" forces an exact match on substring fields; a value
// starting with <, <=, > or >= compares numbers or,
// for Number fields, else naturally (versions and ISO dates order right).
package query

import (
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"
)

// Term is one field filter.
type Term struct {
	Field  string
	Values []string
	Negate bool
}

// Query is a parsed filter string.
type Query struct {
	Terms []Term
	Text  []string
}

// Match modes for a field.
const (
	Exact    = iota // whole value must match (or glob)
	Contains        // substring match (or glob)
	Number          // like Exact, but <, > compare as numbers
)

// Field describes one filterable field of a row type.
type Field struct {
	Name    string
	Aliases []string
	Mode    int
	Help    string
}

// Schema is the set of fields a list understands.
type Schema []Field

func (s Schema) lookup(name string) (Field, bool) {
	name = strings.ToLower(name)
	for _, f := range s {
		if f.Name == name || containsStr(f.Aliases, name) {
			return f, true
		}
	}
	return Field{}, false
}

func containsStr(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// Row is anything a query can be matched against.
type Row interface {
	// Field returns the values of a field (canonical name) for this row.
	Field(name string) []string
	// Text returns the lowercased text searched by free-text words.
	Text() string
}

// Parse parses a filter string against a schema. Unknown fields are an
// error so typos do not silently match nothing.
func Parse(s string, schema Schema) (Query, error) {
	var q Query
	for _, tok := range tokenize(s) {
		neg := false
		body := tok
		if strings.HasPrefix(body, "-") && len(body) > 1 {
			neg, body = true, body[1:]
		}
		name, val, ok := strings.Cut(body, ":")
		if !ok || name == "" || strings.ContainsAny(name, " \"") {
			w := strings.ToLower(strings.Trim(tok, "\""))
			if w != "" {
				q.Text = append(q.Text, w)
			}
			continue
		}
		f, known := schema.lookup(name)
		if !known {
			return Query{}, fmt.Errorf("unknown filter %q (known: %s)", name, schema.names())
		}
		var vals []string
		for _, v := range strings.Split(strings.Trim(val, "\""), ",") {
			if v = strings.TrimSpace(strings.ToLower(v)); v != "" {
				vals = append(vals, v)
			}
		}
		if len(vals) == 0 {
			continue
		}
		q.Terms = append(q.Terms, Term{Field: f.Name, Values: vals, Negate: neg})
	}
	return q, nil
}

func (s Schema) names() string {
	n := make([]string, len(s))
	for i, f := range s {
		n[i] = f.Name
	}
	sort.Strings(n)
	return strings.Join(n, ", ")
}

// tokenize splits on spaces, keeping double-quoted parts together
// (`title:"remote code"` and `"two words"` are one token each).
func tokenize(s string) []string {
	var out []string
	var b strings.Builder
	inQuote := false
	for _, r := range s {
		switch {
		case r == '"':
			inQuote = !inQuote
			b.WriteRune(r)
		case (r == ' ' || r == '\t' || r == '\n') && !inQuote:
			if b.Len() > 0 {
				out = append(out, b.String())
				b.Reset()
			}
		default:
			b.WriteRune(r)
		}
	}
	if b.Len() > 0 {
		out = append(out, b.String())
	}
	return out
}

// Matcher evaluates a query against rows.
type Matcher struct {
	q      Query
	schema Schema
}

// NewMatcher returns a matcher for q.
func NewMatcher(q Query, schema Schema) *Matcher {
	return &Matcher{q: q, schema: schema}
}

// Match reports whether r matches every term and every free-text word.
func (m *Matcher) Match(r Row) bool {
	return m.MatchExcept(r, "")
}

// MatchExcept is Match ignoring terms on one field; used for facet counts so
// a facet shows the other values it could be switched to.
func (m *Matcher) MatchExcept(r Row, skip string) bool {
	for _, t := range m.q.Terms {
		if t.Field == skip {
			continue
		}
		f, _ := m.schema.lookup(t.Field)
		if termMatch(t, f.Mode, r.Field(t.Field)) == t.Negate {
			return false
		}
	}
	if len(m.q.Text) > 0 {
		txt := r.Text()
		for _, w := range m.q.Text {
			if !strings.Contains(txt, w) {
				return false
			}
		}
	}
	return true
}

func termMatch(t Term, mode int, have []string) bool {
	for _, want := range t.Values {
		for _, h := range have {
			if valueMatch(want, strings.ToLower(h), mode) {
				return true
			}
		}
	}
	return false
}

func valueMatch(want, have string, mode int) bool {
	if exact, ok := strings.CutPrefix(want, "="); ok {
		return have == exact
	}
	if op, rest, ok := cutOp(want); ok {
		return compare(op, have, rest, mode)
	}
	if strings.ContainsAny(want, "*?[") {
		if ok, err := path.Match(want, have); err == nil {
			return ok
		}
	}
	if mode == Contains {
		return strings.Contains(have, want)
	}
	return have == want
}

func cutOp(v string) (string, string, bool) {
	for _, op := range []string{">=", "<=", ">", "<"} {
		if rest, ok := strings.CutPrefix(v, op); ok {
			return op, rest, true
		}
	}
	return "", "", false
}

func compare(op, have, want string, mode int) bool {
	if have == "" {
		return false
	}
	var c int
	hf, err1 := strconv.ParseFloat(have, 64)
	wf, err2 := strconv.ParseFloat(want, 64)
	switch {
	case mode == Number && err1 == nil && err2 == nil:
		switch {
		case hf < wf:
			c = -1
		case hf > wf:
			c = 1
		}
	default:
		c = CompareVersions(have, want)
	}
	switch op {
	case ">=":
		return c >= 0
	case "<=":
		return c <= 0
	case ">":
		return c > 0
	default:
		return c < 0
	}
}

// CompareVersions compares strings naturally: runs of digits compare as
// numbers, so "3.0.9" < "3.0.13" and ISO dates still order correctly.
func CompareVersions(a, b string) int {
	for a != "" && b != "" {
		da, ra := splitRun(a)
		db, rb := splitRun(b)
		if isDigit(da[0]) && isDigit(db[0]) {
			na := strings.TrimLeft(da, "0")
			nb := strings.TrimLeft(db, "0")
			if len(na) != len(nb) {
				if len(na) < len(nb) {
					return -1
				}
				return 1
			}
			if c := strings.Compare(na, nb); c != 0 {
				return c
			}
		} else if c := strings.Compare(da, db); c != 0 {
			return c
		}
		a, b = ra, rb
	}
	return strings.Compare(a, b)
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// splitRun returns the leading run of digits or non-digits and the rest.
func splitRun(s string) (string, string) {
	d := isDigit(s[0])
	i := 1
	for i < len(s) && isDigit(s[i]) == d {
		i++
	}
	return s[:i], s[i:]
}

// FacetValue is one value of a facet with its row count.
type FacetValue struct {
	Value string `json:"value"`
	Count int    `json:"count"`
}

// Keyer is implemented by rows that are copies of one logical item (the
// same vulnerability in several workloads); facets then count unique keys.
type Keyer interface {
	Key() string
}

// Facets counts values per field over rows matching the query, ignoring the
// query's own term on that field. Values are sorted by count, then name,
// and capped at limit per field (0 = no cap).
func (m *Matcher) Facets(rows []Row, fields []string, limit int) map[string][]FacetValue {
	counts := make(map[string]map[string]int, len(fields))
	seenKey := map[string]bool{}
	for _, f := range fields {
		counts[f] = map[string]int{}
	}
	for _, r := range rows {
		full := m.Match(r)
		key := ""
		if k, ok := r.(Keyer); ok {
			key = k.Key()
		}
		for _, f := range fields {
			if !full && !m.MatchExcept(r, f) {
				continue
			}
			seen := map[string]bool{}
			for _, v := range r.Field(f) {
				if v == "" || seen[v] {
					continue
				}
				seen[v] = true
				if key != "" {
					sk := f + "\x00" + v + "\x00" + key
					if seenKey[sk] {
						continue
					}
					seenKey[sk] = true
				}
				counts[f][v]++
			}
		}
	}
	out := make(map[string][]FacetValue, len(fields))
	for f, c := range counts {
		vals := make([]FacetValue, 0, len(c))
		for v, n := range c {
			vals = append(vals, FacetValue{Value: v, Count: n})
		}
		sort.Slice(vals, func(i, j int) bool {
			if vals[i].Count != vals[j].Count {
				return vals[i].Count > vals[j].Count
			}
			return vals[i].Value < vals[j].Value
		})
		if limit > 0 && len(vals) > limit {
			vals = vals[:limit]
		}
		out[f] = vals
	}
	return out
}
