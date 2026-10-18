package attacks

import (
	"errors"
	"fmt"
	"net/http"
	"sort"
)

// Case is a fixed, inert request sent only to a test endpoint. The expected
// result describes WAF behavior, not whether an application is exploitable.
type Case struct {
	ID          string `json:"id"`
	Category    string `json:"category"`
	Title       string `json:"title"`
	Method      string `json:"method"`
	Path        string `json:"path"`
	ContentType string `json:"content_type,omitempty"`
	Body        string `json:"body,omitempty"`
	WantBlock   bool   `json:"want_block"`
}

var catalog = map[string][]Case{
	"sqli": {
		{ID: "sqli-query", Title: "SQL injection in query", Method: http.MethodGet, Path: "/__waf_test__/?id=1%27%20OR%20%271%27%3D%271", WantBlock: true},
		{ID: "sqli-form", Title: "SQL injection in form body", Method: http.MethodPost, Path: "/__waf_test__/", ContentType: "application/x-www-form-urlencoded", Body: "search=%27+UNION+SELECT+NULL--", WantBlock: true},
		{ID: "sqli-benign", Title: "Ordinary numeric parameter", Method: http.MethodGet, Path: "/__waf_test__/?id=42"},
	},
	"xss": {
		{ID: "xss-query", Title: "Script markup in query", Method: http.MethodGet, Path: "/__waf_test__/?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E", WantBlock: true},
		{ID: "xss-form", Title: "Event handler in form body", Method: http.MethodPost, Path: "/__waf_test__/", ContentType: "application/x-www-form-urlencoded", Body: "comment=%3Cimg+src%3Dx+onerror%3Dalert%281%29%3E", WantBlock: true},
		{ID: "xss-benign", Title: "Ordinary text parameter", Method: http.MethodGet, Path: "/__waf_test__/?q=hello"},
	},
	"path_traversal": {
		{ID: "traversal-query", Title: "Parent directory traversal in query", Method: http.MethodGet, Path: "/__waf_test__/?file=..%2F..%2Fetc%2Fpasswd", WantBlock: true},
		{ID: "traversal-form", Title: "Parent directory traversal in form body", Method: http.MethodPost, Path: "/__waf_test__/", ContentType: "application/x-www-form-urlencoded", Body: "file=..%2F..%2Fetc%2Fpasswd", WantBlock: true},
		{ID: "traversal-benign", Title: "Ordinary file name", Method: http.MethodGet, Path: "/__waf_test__/?file=report.txt"},
	},
	"cmdi": {
		{ID: "cmdi-query", Title: "Shell separator in query", Method: http.MethodGet, Path: "/__waf_test__/?name=test%3Becho+waf-probe", WantBlock: true},
		{ID: "cmdi-form", Title: "Shell substitution in form body", Method: http.MethodPost, Path: "/__waf_test__/", ContentType: "application/x-www-form-urlencoded", Body: "name=%24%28echo+waf-probe%29", WantBlock: true},
		{ID: "cmdi-benign", Title: "Ordinary name", Method: http.MethodGet, Path: "/__waf_test__/?name=test"},
	},
	"ssrf": {
		{ID: "ssrf-metadata", Title: "Cloud metadata URL as input", Method: http.MethodGet, Path: "/__waf_test__/?url=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2F", WantBlock: true},
		{ID: "ssrf-loopback", Title: "Loopback URL as input", Method: http.MethodPost, Path: "/__waf_test__/", ContentType: "application/x-www-form-urlencoded", Body: "url=http%3A%2F%2F127.0.0.1%2Fadmin", WantBlock: true},
		{ID: "ssrf-benign", Title: "Ordinary public URL", Method: http.MethodGet, Path: "/__waf_test__/?url=https%3A%2F%2Fexample.com%2F"},
	},
	"xxe": {
		{ID: "xxe-system", Title: "External entity in XML", Method: http.MethodPost, Path: "/__waf_test__/", ContentType: "application/xml", Body: `<!DOCTYPE probe [<!ENTITY xxe SYSTEM "file:///nonexistent-waf-probe">]><probe>&xxe;</probe>`, WantBlock: true},
		{ID: "xxe-parameter", Title: "Parameter entity in XML", Method: http.MethodPost, Path: "/__waf_test__/", ContentType: "application/xml", Body: `<!DOCTYPE probe [<!ENTITY % ext SYSTEM "file:///nonexistent-waf-probe"> %ext;]><probe>ok</probe>`, WantBlock: true},
		{ID: "xxe-benign", Title: "Ordinary XML", Method: http.MethodPost, Path: "/__waf_test__/", ContentType: "application/xml", Body: `<probe>ok</probe>`},
	},
	"ssti": {
		{ID: "ssti-braces", Title: "Template expression in query", Method: http.MethodGet, Path: "/__waf_test__/?template=%7B%7B7%2A7%7D%7D", WantBlock: true},
		{ID: "ssti-dollar", Title: "Expression language syntax in form body", Method: http.MethodPost, Path: "/__waf_test__/", ContentType: "application/x-www-form-urlencoded", Body: "template=%24%7B7%2A7%7D", WantBlock: true},
		{ID: "ssti-benign", Title: "Ordinary template text", Method: http.MethodGet, Path: "/__waf_test__/?template=welcome"},
	},
}

func Names() []string {
	names := make([]string, 0, len(catalog))
	for name := range catalog {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// ValidateSelection keeps every job's work bounded and rejects duplicates.
func ValidateSelection(names []string) error {
	if len(names) == 0 || len(names) > len(catalog) {
		return fmt.Errorf("select between 1 and %d attack categories", len(catalog))
	}
	seen := make(map[string]bool, len(names))
	for _, name := range names {
		if _, ok := catalog[name]; !ok || seen[name] {
			return errors.New("attack categories must be supported and unique")
		}
		seen[name] = true
	}
	return nil
}

func Cases(names []string) ([]Case, error) {
	if err := ValidateSelection(names); err != nil {
		return nil, err
	}
	cases := make([]Case, 0, len(names)*3)
	for _, name := range names {
		for _, c := range catalog[name] {
			c.Category = name
			cases = append(cases, c)
		}
	}
	return cases, nil
}
