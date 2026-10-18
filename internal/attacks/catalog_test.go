package attacks

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestCatalogIsBoundedAndSafeForIsolatedProbe(t *testing.T) {
	names := Names()
	if len(names) != 7 {
		t.Fatalf("expected seven selectable attack categories, got %d", len(names))
	}
	all, err := Cases(names)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 21 {
		t.Fatalf("expected 21 fixed requests, got %d", len(all))
	}
	seen := map[string]bool{}
	for _, c := range all {
		if seen[c.ID] {
			t.Fatalf("duplicate case ID %q", c.ID)
		}
		seen[c.ID] = true
		if c.Method != http.MethodGet && c.Method != http.MethodPost {
			t.Fatalf("unexpected method %s", c.Method)
		}
		parsed, err := url.ParseRequestURI(c.Path)
		if err != nil || !strings.HasPrefix(parsed.Path, "/__waf_test__/") || parsed.Host != "" || parsed.Scheme != "" {
			t.Fatalf("case %s has unsafe request path %q", c.ID, c.Path)
		}
		if len(c.Body) > 1024 || len(c.Path) > 1024 {
			t.Fatalf("case %s exceeds bounded request size", c.ID)
		}
	}
	for _, name := range names {
		cases, _ := Cases([]string{name})
		var attacks, benign int
		for _, c := range cases {
			if c.WantBlock {
				attacks++
			} else {
				benign++
			}
		}
		if attacks != 2 || benign != 1 {
			t.Fatalf("%s must have two attack cases and one benign case", name)
		}
	}
}
