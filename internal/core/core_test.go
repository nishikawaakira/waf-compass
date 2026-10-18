package core

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestWorstCaseCostRoundsUpAndRejectsOverflow(t *testing.T) {
	got, err := WorstCaseMicroUSD(1, 1, 1, 1)
	if err != nil || got != 2 {
		t.Fatalf("got %d, %v; want 2 microUSD", got, err)
	}
	if _, err := WorstCaseMicroUSD(2_000_000_000, 1, 1_000_000_000_000, 1); err == nil {
		t.Fatal("expected overflow to fail closed")
	}
}

func TestJSTDayAtUTCBoundary(t *testing.T) {
	instant := time.Date(2026, 10, 18, 14, 59, 0, 0, time.UTC)
	if got := JSTDay(instant); got != "2026-10-18" {
		t.Fatalf("got %s", got)
	}
	if got := JSTDay(instant.Add(time.Minute)); got != "2026-10-19" {
		t.Fatalf("got %s", got)
	}
}

func TestJobValidation(t *testing.T) {
	j := Job{ID: "job-1", UserID: "user-1", Kind: "aws_waf", Snapshot: "{}", AttackCategories: []string{"sqli", "xss"}}
	if err := j.Validate(); err != nil {
		t.Fatal(err)
	}
	j.Snapshot = ""
	if err := j.Validate(); err == nil || errors.Is(err, ErrBudgetExceeded) {
		t.Fatalf("expected input error, got %v", err)
	}
}

func TestJobCategoryValidation(t *testing.T) {
	j := Job{ID: "job-1", UserID: "user-1", Kind: "modsecurity", Snapshot: "SecRuleEngine On", AttackCategories: []string{"sqli"}}
	if err := j.Validate(); err != nil {
		t.Fatal(err)
	}
	first := j.SnapshotHash()
	j.AttackCategories = []string{"xss"}
	if first == j.SnapshotHash() {
		t.Fatal("category selection must be part of snapshot identity")
	}
	j.AttackCategories = []string{"sqli", "sqli"}
	if err := j.Validate(); err == nil {
		t.Fatal("duplicate categories must be rejected")
	}
	j.AttackCategories = []string{"sqli"}
	j.ProbeResultKey = "probe-results/another-job.json"
	if err := j.Validate(); err == nil {
		t.Fatal("unrelated probe receipt must be rejected")
	}
}

func TestJobLanguageValidationAndHash(t *testing.T) {
	j := Job{ID: "job-1", UserID: "user-1", Kind: "aws_waf", Snapshot: "{}", AttackCategories: []string{"sqli"}}
	if err := j.Validate(); err != nil || j.ReportLanguage() != "ja" {
		t.Fatalf("legacy job should default to Japanese: %v", err)
	}
	japaneseHash := j.SnapshotHash()
	j.Language = "ja"
	if err := j.Validate(); err != nil || j.SnapshotHash() != japaneseHash {
		t.Fatalf("explicit Japanese should match legacy job: %v", err)
	}
	j.Language = "en"
	if err := j.Validate(); err != nil || j.SnapshotHash() == japaneseHash {
		t.Fatalf("English should be valid with distinct snapshot identity: %v", err)
	}
	j.Language = "fr"
	if err := j.Validate(); err == nil {
		t.Fatal("unsupported language should be rejected")
	}
}

func TestSnapshotByteLimit(t *testing.T) {
	j := Job{ID: "job-1", UserID: "user-1", Kind: "aws_waf", Snapshot: strings.Repeat("a", MaxSnapshotBytes), AttackCategories: []string{"sqli"}}
	if err := j.Validate(); err != nil {
		t.Fatalf("exactly 1 MiB should be accepted: %v", err)
	}
	j.Snapshot += "a"
	if err := j.Validate(); err == nil {
		t.Fatal("one byte over 1 MiB should be rejected")
	}
	j.Snapshot = strings.Repeat("界", MaxSnapshotBytes/3+1)
	if err := j.Validate(); err == nil {
		t.Fatal("limit must count UTF-8 bytes, not runes")
	}
}
