package loganalysis

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var ErrFormat = errors.New("ログフォーマットが違います")

type Stats struct {
	Format           string         `json:"format"`
	Requests         int            `json:"requests"`
	ClientErrors     int            `json:"client_errors"`
	ServerErrors     int            `json:"server_errors"`
	Signals          map[string]int `json:"signals"`
	PeakClientMinute int            `json:"peak_client_minute"`
}

var combined = regexp.MustCompile(`^([^ ]+) [^ ]+ [^ ]+ \[([^]]+)\] "([A-Z]+) ([^" ]+) HTTP/[0-9.]+" ([1-5][0-9]{2}) (?:[0-9]+|-) "[^"]*" "[^"]*"(?: .*)?$`)
var request = regexp.MustCompile(`^[A-Z]+ ([^ ]+) HTTP/[0-9.]+$`)
var signals = map[string]*regexp.Regexp{
	"sqli":           regexp.MustCompile(`(?i)(?:%27|['"]|union(?:%20|\+|\s)+select\b|select(?:%20|\+|\s)+.+\bfrom\b|or(?:%20|\+|\s)+1=1)`),
	"xss":            regexp.MustCompile(`(?i)(?:<script|%3cscript|javascript:|onerror(?:=|%3d))`),
	"path_traversal": regexp.MustCompile(`(?i)(?:\.\./|%2e%2e(?:%2f|/)|%252e%252e)`),
	"cmdi":           regexp.MustCompile(`(?i)(?:[;|](?:cat|id|curl|wget)(?:%20|\s|$)|%3b(?:cat|id|curl|wget))`),
	"ssrf":           regexp.MustCompile(`(?i)(?:169\.254\.169\.254|localhost|127\.0\.0\.1|metadata\.google\.internal)`),
}

func Analyze(format, input string) (Stats, error) {
	st := Stats{Format: format, Signals: map[string]int{}}
	if format != "cloudfront" && format != "alb" && format != "combined" || strings.ContainsRune(input, '\x00') {
		return st, ErrFormat
	}
	lines := strings.Split(strings.TrimSpace(strings.TrimPrefix(input, "\ufeff")), "\n")
	if len(lines) > 20000 {
		return st, ErrFormat
	}
	var fields []string
	counts := map[string]int{}
	for _, raw := range lines {
		line := strings.TrimSuffix(raw, "\r")
		if line == "" {
			continue
		}
		if format == "cloudfront" && strings.HasPrefix(line, "#") {
			if strings.HasPrefix(line, "#Fields:") {
				fields = strings.Fields(strings.TrimPrefix(line, "#Fields:"))
			}
			continue
		}
		var client, minute, target string
		var status int
		switch format {
		case "cloudfront":
			if len(fields) == 0 {
				return st, ErrFormat
			}
			values := strings.Split(line, "\t")
			if len(values) != len(fields) {
				return st, ErrFormat
			}
			m := map[string]string{}
			for i, name := range fields {
				m[name] = values[i]
			}
			if m["date"] == "" || m["time"] == "" || m["c-ip"] == "" || m["cs-uri-stem"] == "" {
				return st, ErrFormat
			}
			t, err := time.Parse("2006-01-02 15:04:05", m["date"]+" "+m["time"])
			if err != nil {
				return st, ErrFormat
			}
			minute = t.Format("2006-01-02T15:04")
			client = m["c-ip"]
			status, err = strconv.Atoi(m["sc-status"])
			if err != nil {
				return st, ErrFormat
			}
			target = m["cs-uri-stem"] + "?" + m["cs-uri-query"]
		case "alb":
			parts, err := splitALB(line)
			if err != nil || len(parts) < 14 || !map[string]bool{"http": true, "https": true, "h2": true, "grpcs": true, "ws": true, "wss": true}[parts[0]] {
				return st, ErrFormat
			}
			t, err := time.Parse(time.RFC3339Nano, parts[1])
			if err != nil {
				return st, ErrFormat
			}
			minute = t.UTC().Format("2006-01-02T15:04")
			client, _, err = net.SplitHostPort(parts[3])
			if err != nil || net.ParseIP(client) == nil {
				return st, ErrFormat
			}
			status, err = strconv.Atoi(parts[8])
			if err != nil {
				return st, ErrFormat
			}
			match := request.FindStringSubmatch(parts[12])
			if match == nil {
				return st, ErrFormat
			}
			target = match[1]
		case "combined":
			match := combined.FindStringSubmatch(line)
			if match == nil || net.ParseIP(match[1]) == nil {
				return st, ErrFormat
			}
			t, err := time.Parse("02/Jan/2006:15:04:05 -0700", match[2])
			if err != nil {
				return st, ErrFormat
			}
			minute = t.UTC().Format("2006-01-02T15:04")
			client = match[1]
			status, _ = strconv.Atoi(match[5])
			target = match[4]
		}
		if status < 100 || status > 599 || len(target) > 8192 {
			return st, ErrFormat
		}
		if parsed, err := url.ParseRequestURI(target); err != nil || parsed.Scheme != "" && parsed.Host == "" {
			return st, ErrFormat
		}
		st.Requests++
		if status >= 400 && status < 500 {
			st.ClientErrors++
		}
		if status >= 500 {
			st.ServerErrors++
		}
		for name, pattern := range signals {
			if pattern.MatchString(target) {
				st.Signals[name]++
			}
		}
		counts[client+"|"+minute]++
		if counts[client+"|"+minute] > st.PeakClientMinute {
			st.PeakClientMinute = counts[client+"|"+minute]
		}
	}
	if st.Requests == 0 {
		return st, ErrFormat
	}
	return st, nil
}

func splitALB(line string) ([]string, error) {
	var parts []string
	var b strings.Builder
	quoted := false
	for _, c := range line {
		switch c {
		case '"':
			quoted = !quoted
		case ' ':
			if quoted {
				b.WriteRune(c)
			} else if b.Len() > 0 {
				parts = append(parts, b.String())
				b.Reset()
			}
		default:
			b.WriteRune(c)
		}
	}
	if quoted {
		return nil, fmt.Errorf("unclosed quoted field")
	}
	if b.Len() > 0 {
		parts = append(parts, b.String())
	}
	return parts, nil
}
