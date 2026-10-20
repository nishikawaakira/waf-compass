package evaluate

import (
	"strings"
	"testing"

	"waf-rule-evaluations/internal/core"
	"waf-rule-evaluations/internal/loganalysis"
)

func TestTrafficPromptOnlyUsesAggregates(t *testing.T) {
	job := core.Job{ID: "job", UserID: "user", Kind: "traffic_log", LogFormat: "combined", Language: "ja", Snapshot: "192.0.2.3 secret.example/123", AttackCategories: []string{}}
	stats := loganalysis.Stats{Format: "combined", Requests: 1, Signals: map[string]int{"sqli": 1}}
	prompt, err := TrafficPrompt(job, stats)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(prompt, "192.0.2.3") || strings.Contains(prompt, "secret.example") {
		t.Fatal("raw log leaked into prompt")
	}
	if !strings.Contains(prompt, "AWSManagedRulesSQLiRuleSet") {
		t.Fatal("expected SQLi candidate")
	}
}
