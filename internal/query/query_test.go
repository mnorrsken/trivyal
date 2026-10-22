package query

import (
	"reflect"
	"strings"
	"testing"
)

var testSchema = Schema{
	{Name: "sev", Aliases: []string{"severity"}},
	{Name: "ns", Aliases: []string{"namespace"}},
	{Name: "image", Mode: Contains},
	{Name: "score", Mode: Number},
	{Name: "published"},
}

type row map[string][]string

func (r row) Field(n string) []string { return r[n] }
func (r row) Text() string {
	var b strings.Builder
	for _, v := range r {
		b.WriteString(strings.ToLower(strings.Join(v, " ")) + " ")
	}
	return b.String()
}

func TestParse(t *testing.T) {
	tests := []struct {
		in   string
		want Query
	}{
		{"", Query{}},
		{"sev:critical,HIGH", Query{Terms: []Term{{Field: "sev", Values: []string{"critical", "high"}}}}},
		{"severity:low", Query{Terms: []Term{{Field: "sev", Values: []string{"low"}}}}},
		{"-ns:kube-system openssl", Query{Terms: []Term{{Field: "ns", Values: []string{"kube-system"}, Negate: true}}, Text: []string{"openssl"}}},
		{`image:"my app" "two words"`, Query{Terms: []Term{{Field: "image", Values: []string{"my app"}}}, Text: []string{"two words"}}},
		{"sev:", Query{}},
	}
	for _, tt := range tests {
		got, err := Parse(tt.in, testSchema)
		if err != nil {
			t.Fatalf("Parse(%q): %v", tt.in, err)
		}
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("Parse(%q) = %+v, want %+v", tt.in, got, tt.want)
		}
	}
}

func TestParseUnknownField(t *testing.T) {
	if _, err := Parse("nope:x", testSchema); err == nil {
		t.Fatal("want error for unknown field")
	}
}

func TestMatch(t *testing.T) {
	r := row{
		"sev":       {"HIGH"},
		"ns":        {"demo"},
		"image":     {"registry.example.com/shop/web:1.2"},
		"score":     {"7.5"},
		"published": {"2024-03-01"},
	}
	tests := []struct {
		q    string
		want bool
	}{
		{"", true},
		{"sev:high", true},
		{"sev:critical", false},
		{"sev:critical,high", true},
		{"-sev:high", false},
		{"ns:dem", false},
		{"ns:dem*", true},
		{"image:shop/web", true},
		{"image:=shop/web", false},
		{"image:=registry.example.com/shop/web:1.2", true},
		{"score:>=7", true},
		{"score:>8", false},
		{"score:<7.25", false},
		{"published:>2024-01-01", true},
		{"published:<2024-01-01", false},
		{"image:*:1.10", false},
		{"web", true},
		{"web nothere", false},
		{"sev:high ns:other", false},
	}
	for _, tt := range tests {
		q, err := Parse(tt.q, testSchema)
		if err != nil {
			t.Fatalf("Parse(%q): %v", tt.q, err)
		}
		if got := NewMatcher(q, testSchema).Match(r); got != tt.want {
			t.Errorf("Match(%q) = %v, want %v", tt.q, got, tt.want)
		}
	}
}

func TestFacets(t *testing.T) {
	rows := []Row{
		row{"sev": {"HIGH"}, "ns": {"a"}},
		row{"sev": {"HIGH"}, "ns": {"b"}},
		row{"sev": {"LOW"}, "ns": {"a"}},
	}
	q, _ := Parse("sev:high", testSchema)
	f := NewMatcher(q, testSchema).Facets(rows, []string{"sev", "ns"}, 0)
	// The sev facet ignores the sev term, so LOW is still offered.
	wantSev := []FacetValue{{"HIGH", 2}, {"LOW", 1}}
	wantNS := []FacetValue{{"a", 1}, {"b", 1}}
	if !reflect.DeepEqual(f["sev"], wantSev) {
		t.Errorf("sev facet = %v, want %v", f["sev"], wantSev)
	}
	if !reflect.DeepEqual(f["ns"], wantNS) {
		t.Errorf("ns facet = %v, want %v", f["ns"], wantNS)
	}
}

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"3.0.9", "3.0.13", -1},
		{"3.0.13", "3.0.13", 0},
		{"1.10", "1.9", 1},
		{"2024-01-02", "2024-01-10", -1},
		{"1.2.3-r1", "1.2.3-r0", 1},
		{"1.2", "1.2.0", -1},
		{"abc", "abd", -1},
	}
	for _, tt := range tests {
		if got := CompareVersions(tt.a, tt.b); got != tt.want {
			t.Errorf("CompareVersions(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

type keyedRow struct {
	row
	key string
}

func (r keyedRow) Key() string { return r.key }

func TestFacetsDedupeByKey(t *testing.T) {
	rows := []Row{
		keyedRow{row{"sev": {"HIGH"}, "ns": {"a"}}, "x"},
		keyedRow{row{"sev": {"HIGH"}, "ns": {"b"}}, "x"},
		keyedRow{row{"sev": {"HIGH"}, "ns": {"a"}}, "y"},
	}
	f := NewMatcher(Query{}, testSchema).Facets(rows, []string{"sev", "ns"}, 0)
	if want := []FacetValue{{"HIGH", 2}}; !reflect.DeepEqual(f["sev"], want) {
		t.Errorf("sev facet = %v, want %v", f["sev"], want)
	}
	if want := []FacetValue{{"a", 2}, {"b", 1}}; !reflect.DeepEqual(f["ns"], want) {
		t.Errorf("ns facet = %v, want %v", f["ns"], want)
	}
}
