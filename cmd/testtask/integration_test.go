package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"waf-rule-evaluations/internal/attacks"
	"waf-rule-evaluations/internal/core"
)

// Run with WAF_DOCKER_INTEGRATION=1 go test ./cmd/testtask -run TestDockerProbe.
// This verifies the actual Apache/ModSecurity image, not a mocked HTTP server.
func TestDockerProbe(t *testing.T) {
	if os.Getenv("WAF_DOCKER_INTEGRATION") != "1" {
		t.Skip("set WAF_DOCKER_INTEGRATION=1 to run the isolated Docker smoke test")
	}
	root := filepath.Join("..", "..")
	image := "waf-testtask:integration"
	build := exec.CommandContext(t.Context(), "docker", "build", "-t", image, "-f", "Dockerfile.testtask", ".")
	build.Dir = root
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build ModSecurity image: %v\n%s", err, output)
	}
	// The XML test rule deliberately makes the raw DTD visible in ARGS_NAMES.
	// It is a harness fixture, not a recommended production XML processor.
	rules := strings.Join([]string{
		`SecRule ARGS "@rx (?i)(?:\bor\b|union)" "id:100001,phase:2,deny,status:403,log"`,
		`SecRule ARGS "@rx (?i)(?:script|onerror)" "id:100002,phase:2,deny,status:403,log"`,
		`SecRule ARGS "@contains ../" "id:100003,phase:2,deny,status:403,log"`,
		`SecRule ARGS "@contains waf-probe" "id:100004,phase:2,deny,status:403,log"`,
		`SecRule ARGS "@rx (?:169\.254\.169\.254|127\.0\.0\.1)" "id:100005,phase:2,deny,status:403,log"`,
		`SecRule REQUEST_HEADERS:Content-Type "@contains application/xml" "id:100010,phase:1,pass,nolog,ctl:requestBodyProcessor=URLENCODED"`,
		`SecRule ARGS_NAMES "@contains <!DOCTYPE" "id:100006,phase:2,deny,status:403,log"`,
		`SecRule ARGS "@contains 7*7" "id:100007,phase:2,deny,status:403,log"`,
	}, "\n") + "\n"
	names := attacks.Names()
	dir := t.TempDir()
	for _, tc := range []struct {
		name, snapshot, outcome string
	}{
		{"blocking", rules, "samples_passed"},
		{"disabled", "SecRuleEngine Off\n" + rules, "samples_failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			job := core.Job{ID: "integration-" + tc.name, UserID: "integration", Kind: "modsecurity", Language: "en", Snapshot: tc.snapshot, AttackCategories: names}
			job.ProbeResultKey = "probe-results/" + job.ID + ".json"
			data, err := json.Marshal(job)
			if err != nil {
				t.Fatal(err)
			}
			jobPath := filepath.Join(dir, tc.name+"-job.json")
			resultPath := filepath.Join(dir, tc.name+"-receipt.json")
			if err := os.WriteFile(jobPath, data, 0600); err != nil {
				t.Fatal(err)
			}
			run := exec.CommandContext(t.Context(), "docker", "run", "--rm", "--network", "none", "--memory", "512m", "--pids-limit", "256",
				"-e", "LOCAL_JOB_FILE=/input/"+filepath.Base(jobPath), "-e", "LOCAL_RESULT_FILE=/output/"+filepath.Base(resultPath),
				"-v", dir+":/input:ro", "-v", dir+":/output", image)
			if output, err := run.CombinedOutput(); err != nil {
				t.Fatalf("run isolated probe: %v\n%s", err, output)
			}
			contents, err := os.ReadFile(resultPath)
			if err != nil {
				t.Fatal(err)
			}
			var receipt attacks.Receipt
			if err := json.Unmarshal(contents, &receipt); err != nil {
				t.Fatal(err)
			}
			if err := attacks.ValidateReceipt(receipt, job.ID, job.SnapshotHash(), names); err != nil {
				t.Fatal(err)
			}
			for _, group := range receipt.Results {
				if group.Engine != "modsecurity2_apache" || group.Outcome != tc.outcome {
					t.Errorf("%s: got engine=%s outcome=%s, want %s", group.Category, group.Engine, group.Outcome, tc.outcome)
				}
			}
		})
	}
}
