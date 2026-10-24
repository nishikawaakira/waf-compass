package loganalysis

import (
	"errors"
	"strings"
	"testing"
)

const cf = "#Version: 1.0\n#Fields: date time c-ip cs-uri-stem cs-uri-query sc-status\n2026-10-20\t01:02:03\t192.0.2.1\t/search\tq=%3Cscript%3E\t403\n"
const alb = `https 2026-10-20T01:02:03.000000Z app/test/1 192.0.2.2:1234 10.0.0.1:443 0.001 0.001 0.001 200 200 100 200 "GET https://example.com/?id=1%20union%20select HTTP/1.1" "agent"` + "\n"
const combinedLog = `192.0.2.3 - - [20/Oct/2026:10:02:03 +0900] "GET /../../etc/passwd HTTP/1.1" 404 123 "-" "agent"` + "\n"

func TestAnalyzeFormatsAndNoRawData(t *testing.T) {
	for _, tc := range []struct{ format, input, signal string }{
		{"cloudfront", cf, "xss"}, {"alb", alb, "sqli"}, {"combined", combinedLog, "path_traversal"},
	} {
		st, err := Analyze(tc.format, tc.input)
		if err != nil {
			t.Fatalf("%s: %v", tc.format, err)
		}
		if st.Requests != 1 || st.Signals[tc.signal] != 1 {
			t.Fatalf("%s: %+v", tc.format, st)
		}
	}
}

func TestAnalyzeReaderStreamsMoreThanOldLineLimit(t *testing.T) {
	line := "2026-10-20\t01:02:03\t192.0.2.1\t/\t-\t200\n"
	input := "#Fields: date time c-ip cs-uri-stem cs-uri-query sc-status\n" + strings.Repeat(line, 20001)
	stats, err := AnalyzeReader("cloudfront", strings.NewReader(input))
	if err != nil || stats.Requests != 20001 {
		t.Fatalf("stats=%+v err=%v", stats, err)
	}
}

func TestPHP2ShellSignalsAreSeparateWeakLogIndicators(t *testing.T) {
	cloudfront := "#Fields: date time c-ip cs-method cs-uri-stem cs-uri-query sc-status\n" +
		"2026-10-24\t01:02:03\t192.0.2.1\tPOST\t/upload.php\tx=PHP%5FSESSION%5FUPLOAD%5FPROGRESS\t500\n" +
		"2026-10-24\t01:02:04\t192.0.2.1\tPOST\t/upload.php\t-\t200\n"
	stats, err := Analyze("cloudfront", cloudfront)
	if err != nil || stats.PHP2ShellURLMarkers != 1 || stats.PHPPostRequests != 2 || stats.PHPPostServerErrors != 1 {
		t.Fatalf("unexpected CloudFront PHP indicators: %+v, %v", stats, err)
	}
	albLog := `https 2026-10-24T01:02:03.000000Z app/test/1 192.0.2.2:1234 10.0.0.1:443 0.001 0.001 0.001 500 500 100 200 "POST https://example.com/upload.php?x=PHPSESSID HTTP/1.1" "agent"` + "\n"
	stats, err = Analyze("alb", albLog)
	if err != nil || stats.PHP2ShellURLMarkers != 1 || stats.PHPPostServerErrors != 1 {
		t.Fatalf("unexpected ALB PHP indicators: %+v, %v", stats, err)
	}
	combined := `192.0.2.3 - - [24/Oct/2026:10:02:03 +0900] "POST /upload.php HTTP/1.1" 500 123 "-" "agent"` + "\n"
	stats, err = Analyze("combined", combined)
	if err != nil || stats.PHP2ShellURLMarkers != 0 || stats.PHPPostServerErrors != 1 {
		t.Fatalf("unexpected Combined PHP indicators: %+v, %v", stats, err)
	}
}

func TestRejectWrongSelectionAndMalformedRows(t *testing.T) {
	for _, tc := range []struct{ format, input string }{
		{"alb", cf}, {"cloudfront", alb}, {"combined", cf},
		{"cloudfront", strings.Replace(cf, "\t403", "\tinvalid", 1)},
		{"cloudfront", "#Version: 1.0\n#Fields: date time c-ip cs-uri-stem cs-uri-query sc-status\n"},
		{"combined", "garbage"},
	} {
		if _, err := Analyze(tc.format, tc.input); !errors.Is(err, ErrFormat) {
			t.Fatalf("%s: expected format error, got %v", tc.format, err)
		}
	}
}
