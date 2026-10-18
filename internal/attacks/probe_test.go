package attacks

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestProbeAndReceipt(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Query().Get("id") == "42" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()
	results, err := Probe(context.Background(), server.URL, []string{"sqli"})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].Outcome != "samples_passed" || len(results[0].Cases) != 3 {
		t.Fatalf("unexpected results: %+v", results)
	}
	receipt := Receipt{JobID: "j", SnapshotHash: strings.Repeat("a", 64), Results: results}
	if err := ValidateReceipt(receipt, receipt.JobID, receipt.SnapshotHash, []string{"sqli"}); err != nil {
		t.Fatal(err)
	}
	receipt.Results[0].Cases[0].Passed = false
	if err := ValidateReceipt(receipt, receipt.JobID, receipt.SnapshotHash, []string{"sqli"}); err == nil {
		t.Fatal("tampered receipt should be rejected")
	}
}

func TestProbeRejectsExternalTargets(t *testing.T) {
	for _, target := range []string{"https://127.0.0.1:8080", "http://example.com:8080", "http://127.0.0.1:8080/path", "http://127.0.0.1:8080@evil.example:80"} {
		if _, err := Probe(context.Background(), target, []string{"xss"}); err == nil {
			t.Errorf("accepted unsafe target %q", target)
		}
	}
}
