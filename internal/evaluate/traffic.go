package evaluate

import (
	"encoding/json"
	"fmt"

	"waf-rule-evaluations/internal/core"
	"waf-rule-evaluations/internal/loganalysis"
)

const TrafficSystem = `You explain AWS WAF rule candidates from aggregate access-log observations. The supplied sample covers only uploaded traffic, and log URL patterns are indicators, not proof of an attack, compromise, or WAF blocking. Never claim a rule will certainly block an attack. Do not infer request bodies, cookies, application vulnerabilities, or traffic outside the sample. For PHP2Shell, URL markers and PHP POST 5xx responses are weak triage signals only; these logs cannot confirm the exploit because they do not contain the multipart body or PHP runtime state. Zero signals do not rule it out. Never invent exact rule match conditions, rate thresholds, or managed-rule behavior. Recommend testing candidates in Count mode and reviewing sampled requests and false positives before enabling Block. State that an AWS WAF Web ACL must still be attached to the relevant CloudFront distribution or ALB and that logging should be enabled. Use only candidate rule groups in the user prompt; explain evidence and uncertainty. Do not repeat IP addresses, URLs, query strings, user agents, or other raw log data. Answer in natural language in the requested language with a concise conclusion, prioritized candidates, supporting counts, and deployment checks.`

func TrafficPrompt(job core.Job, stats loganalysis.Stats) (string, error) {
	if err := job.Validate(); err != nil {
		return "", err
	}
	if job.Kind != "traffic_log" || stats.Format != job.LogFormat {
		return "", fmt.Errorf("traffic log format mismatch")
	}
	candidates := []string{"AWSManagedRulesCommonRuleSet: baseline web request patterns; suitability and exclusions require testing"}
	if stats.Signals["sqli"] > 0 {
		candidates = append(candidates, "AWSManagedRulesSQLiRuleSet: SQLi-like URL indicators; confirm application has relevant database endpoints")
	}
	if stats.Signals["xss"]+stats.Signals["path_traversal"]+stats.Signals["cmdi"]+stats.Signals["ssrf"] > 0 {
		candidates = append(candidates, "AWSManagedRulesKnownBadInputsRuleSet: suspicious URL indicators; review exact rule coverage in Count mode")
	}
	if stats.PeakClientMinute >= 100 {
		candidates = append(candidates, "rate-based rule: one client had at least 100 requests in one observed minute; choose an actual threshold from broader baseline traffic")
	}
	if stats.PHP2ShellURLMarkers > 0 || stats.PHPPostServerErrors > 0 {
		candidates = append(candidates, "AWSManagedRulesPHPRuleSet: review current PHP2Shell_BODY and PHP2Shell_BODY_Extended managed rules and Count overrides; ordinary access logs cannot establish a PHP2Shell attempt or PHP patch status")
	}
	data, err := json.Marshal(stats)
	if err != nil {
		return "", err
	}
	language := "Japanese"
	if job.ReportLanguage() == "en" {
		language = "English"
	}
	return fmt.Sprintf("Respond entirely in %s. Analyze only this numeric aggregate of a %s access-log sample: %s\nAllowed AWS WAF candidates: %v\nThese are configuration candidates, not confirmed attack detections. PHP2Shell URL-marker counts and PHP POST 5xx counts are separate weak signals; do not combine them into a confirmed exploit count. Recommend checking AWS WAF match logs and PHP server logs, and applying the PHP security update. Do not recommend any candidate absent from the allowed list. Explain why raw access logs cannot establish which rule actually blocks traffic.\n", language, job.LogFormat, data, candidates), nil
}

func TrafficSummary(language string, stats loganalysis.Stats) string {
	if language == "en" {
		return fmt.Sprintf("Analyzed %d access-log requests: %d 4xx and %d 5xx responses. PHP2Shell-related triage signals: %d URLs with session/upload-progress markers and %d PHP POST requests with 5xx responses. These do not prove PHP2Shell exploitation or blocking; request bodies and PHP runtime state are not in these logs.", stats.Requests, stats.ClientErrors, stats.ServerErrors, stats.PHP2ShellURLMarkers, stats.PHPPostServerErrors)
	}
	return fmt.Sprintf("アクセスログ%d件を集計しました。4xxは%d件、5xxは%d件です。PHP2Shell関連の要調査指標は、セッション・アップロード進捗の文字列を含むURLが%d件、PHP宛てPOSTの5xx応答が%d件です。本文やPHPの実行状態はこのログに含まれず、攻撃や遮断の証明ではありません。", stats.Requests, stats.ClientErrors, stats.ServerErrors, stats.PHP2ShellURLMarkers, stats.PHPPostServerErrors)
}
