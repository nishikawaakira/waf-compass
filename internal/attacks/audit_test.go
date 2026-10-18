package attacks

import (
	"strings"
	"testing"
)

func TestAttachModSecurityRuleIDs(t *testing.T) {
	results := []CategoryResult{{Category: "sqli", Cases: []CaseResult{{CaseID: "sqli-query"}, {CaseID: "sqli-benign"}}}}
	log := `{"request":{"headers":{"X-Waf-Test-Case":"sqli-query"}},"audit_data":{"messages":["blocked [id \"100001\"]", "also [id \"100002\"]"]}}` + "\n" +
		`{"request":{"headers":{"X-Waf-Test-Case":"sqli-query"}},"audit_data":{"messages":["again [id \"100001\"]"]}}`
	AttachModSecurityRuleIDs(results, strings.NewReader(log))
	got := strings.Join(results[0].Cases[0].MatchedRuleIDs, ",")
	if got != "100001,100002" {
		t.Fatalf("got rule IDs %q", got)
	}
	if len(results[0].Cases[1].MatchedRuleIDs) != 0 {
		t.Fatal("benign case inherited attack rule IDs")
	}
}
