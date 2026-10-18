package attacks

import (
	"bytes"
	"encoding/json"
	"io"
	"regexp"
	"sort"
	"strings"
)

var ruleIDPattern = regexp.MustCompile(`\[id "([0-9]{1,12})"\]`)

// AttachModSecurityRuleIDs extracts rule IDs from the isolated testbed's
// JSON audit log. Missing or unsupported log formats leave IDs empty; HTTP
// outcomes remain the source of truth for the sample verdict.
func AttachModSecurityRuleIDs(results []CategoryResult, log io.Reader) {
	data, err := io.ReadAll(io.LimitReader(log, 2<<20))
	if err != nil {
		return
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	ids := make(map[string]map[string]bool)
	for {
		var event struct {
			Request struct {
				Headers map[string]string `json:"headers"`
			} `json:"request"`
			AuditData struct {
				Messages []string `json:"messages"`
			} `json:"audit_data"`
		}
		if err := decoder.Decode(&event); err != nil {
			break
		}
		caseID := ""
		for name, value := range event.Request.Headers {
			if strings.EqualFold(name, "X-WAF-Test-Case") {
				caseID = value
				break
			}
		}
		if caseID == "" {
			continue
		}
		if ids[caseID] == nil {
			ids[caseID] = make(map[string]bool)
		}
		for _, message := range event.AuditData.Messages {
			for _, match := range ruleIDPattern.FindAllStringSubmatch(message, 32) {
				ids[caseID][match[1]] = true
			}
		}
	}
	for i := range results {
		for j := range results[i].Cases {
			caseIDs := ids[results[i].Cases[j].CaseID]
			for id := range caseIDs {
				results[i].Cases[j].MatchedRuleIDs = append(results[i].Cases[j].MatchedRuleIDs, id)
			}
			sort.Strings(results[i].Cases[j].MatchedRuleIDs)
		}
	}
}
