package evaluate

import (
	"fmt"

	"waf-rule-evaluations/internal/attacks"
)

// Summary is a deterministic, human-readable description of the measured
// sample outcomes. The Bedrock assessment adds rule-specific explanation.
func Summary(language string, results []attacks.CategoryResult) string {
	var passed, failed, inconclusive, unverified int
	for _, result := range results {
		switch result.Outcome {
		case "samples_passed":
			passed++
		case "samples_failed":
			failed++
		case "inconclusive":
			inconclusive++
		default:
			unverified++
		}
	}
	if language == "en" {
		return fmt.Sprintf("Reviewed %d selected attack categories. The fixed samples behaved as expected in %d, differed from expectations in %d, could not be measured in %d, and were not executed in %d. These samples do not prove that the application is free of vulnerabilities or that every OWASP Top 10 risk is covered.", len(results), passed, failed, inconclusive, unverified)
	}
	return fmt.Sprintf("選択した%d種類の攻撃を評価しました。固定ケースで期待どおりだったものは%d種類、期待と異なったものは%d種類、測定できなかったものは%d種類、実行していないものは%d種類です。この結果だけでアプリケーションの脆弱性がないことや、OWASP Top 10 全体への対応は証明できません。", len(results), passed, failed, inconclusive, unverified)
}
