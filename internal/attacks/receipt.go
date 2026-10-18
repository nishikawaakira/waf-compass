package attacks

import (
	"errors"
	"fmt"
	"regexp"
)

var receiptRuleID = regexp.MustCompile(`^[0-9]{1,12}$`)

// Receipt is written by a separate test task. The S3 prefix that stores it
// must be writable only by that task, never by a browser or rule uploader.
type Receipt struct {
	JobID        string           `json:"job_id"`
	SnapshotHash string           `json:"snapshot_hash"`
	Results      []CategoryResult `json:"results"`
}

// ValidateReceipt checks identity, coverage, and each observation. This is a
// consistency check; object provenance still depends on S3 IAM permissions.
func ValidateReceipt(r Receipt, jobID, snapshotHash string, names []string) error {
	if r.JobID != jobID || r.SnapshotHash != snapshotHash {
		return errors.New("probe receipt does not match the job snapshot")
	}
	if err := ValidateSelection(names); err != nil {
		return err
	}
	if len(r.Results) != len(names) {
		return errors.New("probe receipt category count mismatch")
	}
	for i, name := range names {
		result := r.Results[i]
		if result.Category != name || result.Mode != "local_http_probe" || (result.Engine != "loopback_http" && result.Engine != "modsecurity2_apache") {
			return fmt.Errorf("probe receipt category %d mismatch", i)
		}
		want, _ := Cases([]string{name})
		if len(result.Cases) != len(want) {
			return fmt.Errorf("probe receipt case count mismatch for %s", name)
		}
		outcome := "samples_passed"
		for j, c := range want {
			got := result.Cases[j]
			if got.CaseID != c.ID || got.Category != name || got.WantBlock != c.WantBlock {
				return fmt.Errorf("probe receipt case %d mismatch for %s", j, name)
			}
			observed := "error"
			switch {
			case got.HTTPStatus == 200:
				observed = "allowed"
			case got.HTTPStatus >= 400 && got.HTTPStatus < 500:
				observed = "blocked"
			}
			passed := (c.WantBlock && observed == "blocked") || (!c.WantBlock && observed == "allowed")
			if got.Observed != observed || got.Passed != passed {
				return fmt.Errorf("probe receipt observation mismatch for %s", c.ID)
			}
			if len(got.MatchedRuleIDs) > 32 {
				return fmt.Errorf("too many matched rule IDs for %s", c.ID)
			}
			for _, id := range got.MatchedRuleIDs {
				if !receiptRuleID.MatchString(id) {
					return fmt.Errorf("invalid matched rule ID for %s", c.ID)
				}
			}
			if observed == "error" {
				outcome = "inconclusive"
			} else if !passed && outcome != "inconclusive" {
				outcome = "samples_failed"
			}
		}
		if result.Outcome != outcome {
			return fmt.Errorf("probe receipt outcome mismatch for %s", name)
		}
	}
	return nil
}
