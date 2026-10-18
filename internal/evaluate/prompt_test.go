package evaluate

import (
	"strings"
	"testing"

	"waf-rule-evaluations/internal/attacks"
	"waf-rule-evaluations/internal/core"
)

func TestWAFRulesSortedByPriority(t *testing.T) {
	j := core.Job{ID: "j", UserID: "u", Kind: "aws_waf", Snapshot: `{"WebACL":{"Name":"test","Rules":[{"Name":"late","Priority":20},{"Name":"early","Priority":1}]}}`, AttackCategories: []string{"sqli"}}
	results, _ := attacks.Planned(j.AttackCategories)
	p, err := Prompt(j, results)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Index(p, `priority=1 name="early"`) > strings.Index(p, `priority=20 name="late"`) {
		t.Fatal("priority order was not normalized")
	}
}

func TestModSecurityRequiresExpandedIncludes(t *testing.T) {
	j := core.Job{ID: "j", UserID: "u", Kind: "modsecurity", Snapshot: "Include /etc/modsecurity/rules/*.conf", AttackCategories: []string{"xss"}}
	results, _ := attacks.Planned(j.AttackCategories)
	if _, err := Prompt(j, results); err == nil {
		t.Fatal("unresolved Include must fail closed")
	}
}

func TestPromptLanguageAndSampleLimits(t *testing.T) {
	j := core.Job{ID: "j", UserID: "u", Kind: "modsecurity", Language: "en", Snapshot: "SecRuleEngine On", AttackCategories: []string{"sqli", "ssrf"}}
	results, _ := attacks.Planned(j.AttackCategories)
	p, err := Prompt(j, results)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Respond entirely in English", "category=ssrf", "unverified", "no request was executed"} {
		if !strings.Contains(p, want) {
			t.Fatalf("prompt missing %q", want)
		}
	}
	j.Language = "ja"
	p, err = Prompt(j, results)
	if err != nil || !strings.Contains(p, "Respond entirely in Japanese") {
		t.Fatalf("Japanese prompt missing language instruction: %v", err)
	}
}

func TestNaturalLanguageSummary(t *testing.T) {
	results := []attacks.CategoryResult{{Outcome: "samples_passed"}, {Outcome: "samples_failed"}, {Outcome: "unverified"}}
	if got := Summary("ja", results); !strings.Contains(got, "期待どおりだったものは1種類") || !strings.Contains(got, "OWASP Top 10") {
		t.Fatalf("unexpected Japanese summary: %s", got)
	}
	if got := Summary("en", results); !strings.Contains(got, "behaved as expected in 1") || !strings.Contains(got, "OWASP Top 10") {
		t.Fatalf("unexpected English summary: %s", got)
	}
}
