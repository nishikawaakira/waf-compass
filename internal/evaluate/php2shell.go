package evaluate

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// PHP2ShellReview reports visible WAF configuration, not exploit resistance.
// AWS can change managed-rule internals without changing a GetWebACL snapshot.
type PHP2ShellReview struct {
	ManagedRulePresent bool     `json:"managed_rule_present"`
	ManagedVersion     string   `json:"managed_version,omitempty"`
	CVE109618          string   `json:"cve_2026_109618"` // configured_block, count_only, not_visible
	CVE109619          string   `json:"cve_2026_109619"`
	CustomRuleNames    []string `json:"custom_rule_names,omitempty"`
	PriorAllowRules    []string `json:"prior_allow_rules,omitempty"`
	ScopeDownPresent   bool     `json:"scope_down_present,omitempty"`
}

func ReviewPHP2Shell(snapshot string) (PHP2ShellReview, error) {
	review := PHP2ShellReview{CVE109618: "not_visible", CVE109619: "not_visible"}
	var input struct {
		WebACL struct {
			Rules []struct {
				Name           string                     `json:"Name"`
				Priority       int                        `json:"Priority"`
				Statement      map[string]json.RawMessage `json:"Statement"`
				Action         map[string]json.RawMessage `json:"Action"`
				OverrideAction map[string]json.RawMessage `json:"OverrideAction"`
			} `json:"Rules"`
		} `json:"WebACL"`
	}
	if err := json.Unmarshal([]byte(snapshot), &input); err != nil {
		return review, fmt.Errorf("parse WAF snapshot: %w", err)
	}
	firstRelevantPriority := int(^uint(0) >> 1)
	for _, rule := range input.WebACL.Rules {
		if raw, ok := rule.Statement["ManagedRuleGroupStatement"]; ok {
			var group struct {
				Name                string          `json:"Name"`
				VendorName          string          `json:"VendorName"`
				Version             string          `json:"Version"`
				ScopeDownStatement  json.RawMessage `json:"ScopeDownStatement"`
				RuleActionOverrides []struct {
					Name        string                     `json:"Name"`
					ActionToUse map[string]json.RawMessage `json:"ActionToUse"`
				} `json:"RuleActionOverrides"`
				ExcludedRules []struct {
					Name string `json:"Name"`
				} `json:"ExcludedRules"`
			}
			if err := json.Unmarshal(raw, &group); err != nil {
				return review, err
			}
			if group.VendorName == "AWS" && group.Name == "AWSManagedRulesPHPRuleSet" {
				review.ManagedRulePresent = true
				if rule.Priority < firstRelevantPriority {
					firstRelevantPriority = rule.Priority
				}
				version := group.Version
				if version == "" {
					version = "Default"
				}
				if review.ManagedVersion == "" {
					review.ManagedVersion = version
				} else if review.ManagedVersion != version {
					review.ManagedVersion = "Multiple"
				}
				review.ScopeDownPresent = review.ScopeDownPresent || len(group.ScopeDownStatement) > 0
				covers618, covers619 := phpManagedVersionCoverage(version)
				status618, status619 := "configured_block", "configured_block"
				if hasAction(rule.OverrideAction, "Count") {
					status618, status619 = "count_only", "count_only"
				}
				for _, override := range group.RuleActionOverrides {
					if override.Name == "PHP2Shell_BODY" {
						status619 = overrideStatus(override.ActionToUse)
					}
					if override.Name == "PHP2Shell_BODY_Extended" {
						status618 = overrideStatus(override.ActionToUse)
					}
				}
				for _, excluded := range group.ExcludedRules {
					if excluded.Name == "PHP2Shell_BODY" {
						status619 = "count_only"
					}
					if excluded.Name == "PHP2Shell_BODY_Extended" {
						status618 = "count_only"
					}
				}
				// A group-level Count override applies after individual rule actions.
				if hasAction(rule.OverrideAction, "Count") {
					status618, status619 = "count_only", "count_only"
				}
				if covers618 {
					review.CVE109618 = strongerStatus(review.CVE109618, status618)
				}
				if covers619 {
					review.CVE109619 = strongerStatus(review.CVE109619, status619)
				}
			}
		}
		if raw, ok := rule.Statement["AndStatement"]; ok {
			var statement map[string]any
			if err := json.Unmarshal(raw, &statement); err != nil {
				return review, err
			}
			if officialCustomPattern(statement) {
				review.CustomRuleNames = append(review.CustomRuleNames, rule.Name)
				if rule.Priority < firstRelevantPriority {
					firstRelevantPriority = rule.Priority
				}
				if hasAction(rule.Action, "Block") {
					review.CVE109619 = strongerStatus(review.CVE109619, "configured_block")
				}
				if hasAction(rule.Action, "Count") {
					review.CVE109619 = strongerStatus(review.CVE109619, "count_only")
				}
			}
		}
	}
	for _, rule := range input.WebACL.Rules {
		if rule.Priority < firstRelevantPriority && hasAction(rule.Action, "Allow") && len(review.PriorAllowRules) < 20 {
			review.PriorAllowRules = append(review.PriorAllowRules, rule.Name)
		}
	}
	return review, nil
}

func phpManagedVersionCoverage(version string) (bool, bool) {
	if version == "Default" {
		return true, true
	}
	parts := strings.Split(strings.TrimPrefix(version, "Version_"), ".")
	if len(parts) < 2 || !strings.HasPrefix(version, "Version_") {
		return false, false
	}
	major, errMajor := strconv.Atoi(parts[0])
	minor, errMinor := strconv.Atoi(parts[1])
	if errMajor != nil || errMinor != nil {
		return false, false
	}
	return major > 2 || major == 2 && minor >= 4, major > 2 || major == 2 && minor >= 3
}

func hasAction(action map[string]json.RawMessage, name string) bool { _, ok := action[name]; return ok }
func overrideStatus(action map[string]json.RawMessage) string {
	if hasAction(action, "Block") {
		return "configured_block"
	}
	if hasAction(action, "Count") {
		return "count_only"
	}
	return "nonblocking_override"
}
func strongerStatus(current, candidate string) string {
	rank := map[string]int{"not_visible": 0, "count_only": 1, "nonblocking_override": 1, "configured_block": 2}
	if rank[candidate] > rank[current] {
		return candidate
	}
	return current
}

func officialCustomPattern(and map[string]any) bool {
	children, ok := and["Statements"].([]any)
	if !ok {
		return false
	}
	var method, session, progress bool
	for _, child := range children {
		statement, ok := child.(map[string]any)
		if !ok {
			continue
		}
		if match, ok := statement["ByteMatchStatement"].(map[string]any); ok {
			method = method || byteMatch(match, "POST", "Method", "EXACTLY")
			session = session || byteMatch(match, "PHPSESSID", "Body", "CONTAINS") || cookieKeyMatch(match)
			progress = progress || byteMatch(match, "PHP_SESSION_UPLOAD_PROGRESS", "Body", "CONTAINS")
		}
		if or, ok := statement["OrStatement"].(map[string]any); ok {
			branches, _ := or["Statements"].([]any)
			for _, branch := range branches {
				child, ok := branch.(map[string]any)
				if !ok {
					continue
				}
				match, ok := child["ByteMatchStatement"].(map[string]any)
				if !ok {
					continue
				}
				session = session || byteMatch(match, "PHPSESSID", "Body", "CONTAINS") || cookieKeyMatch(match)
			}
		}
	}
	return method && session && progress
}

func byteMatch(match map[string]any, search, field, constraint string) bool {
	if match["SearchString"] != search || match["PositionalConstraint"] != constraint {
		return false
	}
	fields, ok := match["FieldToMatch"].(map[string]any)
	if !ok {
		return false
	}
	_, ok = fields[field]
	return ok
}

func cookieKeyMatch(match map[string]any) bool {
	if match["SearchString"] != "PHPSESSID" || match["PositionalConstraint"] != "EXACTLY" {
		return false
	}
	fields, ok := match["FieldToMatch"].(map[string]any)
	if !ok {
		return false
	}
	cookies, ok := fields["Cookies"].(map[string]any)
	if !ok {
		return false
	}
	return cookies["MatchScope"] == "KEY"
}
