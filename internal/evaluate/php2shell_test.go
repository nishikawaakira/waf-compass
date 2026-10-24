package evaluate

import "testing"

func TestPHP2ShellManagedRuleCoverageAndOverrides(t *testing.T) {
	snapshot := `{"WebACL":{"Rules":[
	  {"Name":"early-allow","Priority":0,"Action":{"Allow":{}}},
	  {"Name":"php","Priority":1,"Statement":{"ManagedRuleGroupStatement":{"VendorName":"AWS","Name":"AWSManagedRulesPHPRuleSet","ScopeDownStatement":{"ByteMatchStatement":{}},"RuleActionOverrides":[{"Name":"PHP2Shell_BODY_Extended","ActionToUse":{"Count":{}}}]}} ,"OverrideAction":{"None":{}}}
	]}}`
	review, err := ReviewPHP2Shell(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if !review.ManagedRulePresent || review.ManagedVersion != "Default" || review.CVE109618 != "count_only" || review.CVE109619 != "configured_block" {
		t.Fatalf("unexpected default managed coverage: %+v", review)
	}
	if !review.ScopeDownPresent || len(review.PriorAllowRules) != 1 || review.PriorAllowRules[0] != "early-allow" {
		t.Fatalf("missing scope or evaluation-order finding: %+v", review)
	}
	for _, tc := range []struct{ version, want618, want619 string }{
		{"Version_2.2", "not_visible", "not_visible"},
		{"Version_2.3", "not_visible", "configured_block"},
		{"Version_2.4", "configured_block", "configured_block"},
	} {
		input := `{"WebACL":{"Rules":[{"Name":"php","Priority":1,"Statement":{"ManagedRuleGroupStatement":{"VendorName":"AWS","Name":"AWSManagedRulesPHPRuleSet","Version":"` + tc.version + `"}},"OverrideAction":{"None":{}}}]}}`
		got, err := ReviewPHP2Shell(input)
		if err != nil || got.CVE109618 != tc.want618 || got.CVE109619 != tc.want619 {
			t.Fatalf("version %s: %+v, %v", tc.version, got, err)
		}
	}
}

func TestPHP2ShellCustomRuleRequiresCompleteConjunction(t *testing.T) {
	complete := `{"WebACL":{"Rules":[{"Name":"custom","Priority":2,"Action":{"Block":{}},"Statement":{"AndStatement":{"Statements":[
	  {"ByteMatchStatement":{"SearchString":"POST","FieldToMatch":{"Method":{}},"PositionalConstraint":"EXACTLY"}},
	  {"OrStatement":{"Statements":[{"ByteMatchStatement":{"SearchString":"PHPSESSID","FieldToMatch":{"Cookies":{"MatchScope":"KEY"}},"PositionalConstraint":"EXACTLY"}}]}},
	  {"ByteMatchStatement":{"SearchString":"PHP_SESSION_UPLOAD_PROGRESS","FieldToMatch":{"Body":{}},"PositionalConstraint":"CONTAINS"}}
	]}}}]}}`
	review, err := ReviewPHP2Shell(complete)
	if err != nil || review.CVE109619 != "configured_block" || review.CVE109618 != "not_visible" || len(review.CustomRuleNames) != 1 {
		t.Fatalf("complete custom rule not recognized: %+v, %v", review, err)
	}
	incomplete := `{"WebACL":{"Rules":[{"Name":"named-only","Priority":2,"Action":{"Block":{}},"Statement":{"ByteMatchStatement":{"SearchString":"PHP_SESSION_UPLOAD_PROGRESS","FieldToMatch":{"Body":{}},"PositionalConstraint":"CONTAINS"}}}]}}`
	review, err = ReviewPHP2Shell(incomplete)
	if err != nil || review.CVE109619 != "not_visible" {
		t.Fatalf("incomplete rule must not be considered coverage: %+v, %v", review, err)
	}
}

func TestPHP2ShellGroupCountDominatesRuleBlockOverride(t *testing.T) {
	snapshot := `{"WebACL":{"Rules":[{"Name":"php","Priority":1,"Statement":{"ManagedRuleGroupStatement":{"VendorName":"AWS","Name":"AWSManagedRulesPHPRuleSet","RuleActionOverrides":[{"Name":"PHP2Shell_BODY","ActionToUse":{"Block":{}}}]}} ,"OverrideAction":{"Count":{}}}]}}`
	review, err := ReviewPHP2Shell(snapshot)
	if err != nil || review.CVE109618 != "count_only" || review.CVE109619 != "count_only" {
		t.Fatalf("group Count must prevent blocking: %+v, %v", review, err)
	}
}
