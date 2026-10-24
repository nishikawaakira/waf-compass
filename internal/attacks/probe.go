package attacks

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type CaseResult struct {
	CaseID         string   `json:"case_id"`
	Category       string   `json:"category"`
	WantBlock      bool     `json:"want_block"`
	HTTPStatus     int      `json:"http_status"`
	Observed       string   `json:"observed"` // blocked, allowed, or error
	Passed         bool     `json:"passed"`
	MatchedRuleIDs []string `json:"matched_rule_ids,omitempty"`
	Error          string   `json:"error,omitempty"`
}

type CategoryResult struct {
	Category string       `json:"category"`
	Mode     string       `json:"mode"`    // local_http_probe or static_review
	Outcome  string       `json:"outcome"` // samples_passed, samples_failed, inconclusive, or unverified
	Engine   string       `json:"engine,omitempty"`
	Cases    []CaseResult `json:"cases,omitempty"`
}

// Planned returns an explicitly unverified result for snapshots that have not
// been exercised against a real WAF. It must never be presented as a pass.
func Planned(names []string) ([]CategoryResult, error) {
	if err := ValidateSelection(names); err != nil {
		return nil, err
	}
	results := make([]CategoryResult, 0, len(names))
	for _, name := range names {
		results = append(results, CategoryResult{Category: name, Mode: "static_review", Outcome: "unverified"})
	}
	return results, nil
}

// Probe sends bounded, fixed requests to a loopback testbed. The testbed must
// return 200 for accepted requests and a 4xx status for WAF rejections. It
// should use a dummy backend that always returns 200, otherwise the outcome
// cannot be attributed to the WAF.
func Probe(ctx context.Context, target string, names []string) ([]CategoryResult, error) {
	cases, err := Cases(names)
	if err != nil {
		return nil, err
	}
	u, err := url.Parse(target)
	if err != nil || u.Scheme != "http" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("test target must be an http loopback origin with no path")
	}
	host := net.ParseIP(u.Hostname())
	if host == nil || !host.IsLoopback() {
		return nil, errors.New("test target must use a loopback IP address")
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 {
		return nil, errors.New("test target must include a valid port")
	}
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 2 * time.Second}).DialContext, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	byCategory := make(map[string]*CategoryResult, len(names))
	results := make([]CategoryResult, len(names))
	for i, name := range names {
		results[i] = CategoryResult{Category: name, Mode: "local_http_probe", Outcome: "samples_passed", Engine: "loopback_http"}
		byCategory[name] = &results[i]
	}
	for _, c := range cases {
		r := CaseResult{CaseID: c.ID, Category: c.Category, WantBlock: c.WantBlock}
		req, err := http.NewRequestWithContext(ctx, c.Method, target+c.Path, strings.NewReader(c.Body))
		if err == nil {
			req.Header.Set("X-WAF-Test-Case", c.ID)
			if c.ContentType != "" {
				req.Header.Set("Content-Type", c.ContentType)
			}
			if c.Cookie != "" {
				req.Header.Set("Cookie", c.Cookie)
			}
			var response *http.Response
			response, err = client.Do(req)
			if err == nil {
				r.HTTPStatus = response.StatusCode
				_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1024))
				_ = response.Body.Close()
			}
		}
		if err != nil {
			r.Observed = "error"
			r.Error = err.Error()
		} else {
			switch {
			case r.HTTPStatus == http.StatusOK:
				r.Observed = "allowed"
			case r.HTTPStatus >= 400 && r.HTTPStatus < 500:
				r.Observed = "blocked"
			default:
				r.Observed = "error"
				r.Error = fmt.Sprintf("unexpected status %d; dummy backend must return 200", r.HTTPStatus)
			}
		}
		r.Passed = (c.WantBlock && r.Observed == "blocked") || (!c.WantBlock && r.Observed == "allowed")
		category := byCategory[c.Category]
		category.Cases = append(category.Cases, r)
		if r.Observed == "error" {
			category.Outcome = "inconclusive"
		} else if !r.Passed && category.Outcome != "inconclusive" {
			category.Outcome = "samples_failed"
		}
	}
	return results, nil
}
