// Probe is run next to a disposable ModSecurity testbed. It deliberately
// accepts only an HTTP loopback target and never sends traffic to a user URL.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"waf-rule-evaluations/internal/attacks"
	"waf-rule-evaluations/internal/core"
)

func main() {
	target := flag.String("target", "http://127.0.0.1:8080", "loopback ModSecurity testbed origin")
	jobPath := flag.String("job", "", "service-created job JSON file")
	flag.Parse()
	if *jobPath == "" {
		fmt.Fprintln(os.Stderr, "-job is required")
		os.Exit(1)
	}
	file, err := os.Open(*jobPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, core.MaxSnapshotBytes*6+8193))
	if err != nil || len(data) > core.MaxSnapshotBytes*6+8192 {
		fmt.Fprintln(os.Stderr, "job file is unreadable or too large")
		os.Exit(1)
	}
	var job core.Job
	if err := json.Unmarshal(data, &job); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := job.Validate(); err != nil || job.Kind != "modsecurity" {
		fmt.Fprintln(os.Stderr, "a valid ModSecurity job is required")
		os.Exit(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	results, err := attacks.Probe(ctx, *target, job.AttackCategories)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	receipt := attacks.Receipt{JobID: job.ID, SnapshotHash: job.SnapshotHash(), Results: results}
	if err := attacks.ValidateReceipt(receipt, job.ID, job.SnapshotHash(), job.AttackCategories); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := json.NewEncoder(os.Stdout).Encode(receipt); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
