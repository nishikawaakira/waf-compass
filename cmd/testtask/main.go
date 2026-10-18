// Testtask runs untrusted ModSecurity rules in a separate, credential-free
// container. Deploy it as a different ECS task from the Bedrock worker.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"waf-rule-evaluations/internal/attacks"
	"waf-rule-evaluations/internal/core"
)

const (
	setupPath = "/etc/modsecurity.d/setup.conf"
	rulesPath = "/etc/modsecurity.d/evaluation-rules.conf"
)

var forbiddenDirective = regexp.MustCompile(`(?im)^\s*(?:Include(?:Optional)?|SecRemoteRules|SecRuleScript)\s+`)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	if err := run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	if os.Getenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI") != "" || os.Getenv("AWS_CONTAINER_CREDENTIALS_FULL_URI") != "" || os.Getenv("AWS_ACCESS_KEY_ID") != "" {
		return errors.New("ModSecurity test task must not receive AWS credentials")
	}
	data, err := loadJob(ctx)
	if err != nil {
		return err
	}
	var job core.Job
	if err := json.Unmarshal(data, &job); err != nil {
		return fmt.Errorf("decode job: %w", err)
	}
	if err := job.Validate(); err != nil {
		return err
	}
	if job.Kind != "modsecurity" || job.ProbeResultKey == "" {
		return errors.New("test task requires a ModSecurity job with probe_result_key")
	}
	if forbiddenDirective.MatchString(job.Snapshot) {
		return errors.New("ruleset contains a directive unsupported by the isolated testbed")
	}
	if err := os.WriteFile(rulesPath, []byte(job.Snapshot), 0644); err != nil {
		return fmt.Errorf("write rules: %w", err)
	}
	// The stock image loads bundled CRS rules. Replace its include chain so
	// this run tests only the submitted, already-flattened ruleset.
	setup := "Include /etc/modsecurity.d/modsecurity.conf\nInclude /etc/modsecurity.d/modsecurity-override.conf\nInclude " + rulesPath + "\n"
	if err := os.WriteFile(setupPath, []byte(setup), 0644); err != nil {
		return fmt.Errorf("write ModSecurity include chain: %w", err)
	}
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer backend.Close()
	backendServer := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })}
	go func() { _ = backendServer.Serve(backend) }()
	defer backendServer.Close()

	command := exec.CommandContext(ctx, "/docker-entrypoint.sh", "httpd-foreground")
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Credential: &syscall.Credential{Uid: 999, Gid: 999}}
	command.WaitDelay = 2 * time.Second
	command.Env = cleanEnvironment(os.Environ(), map[string]string{
		"MANUAL_MODE": "1", "BACKEND": "http://" + backend.Addr().String(),
		"PORT": "8080", "SSL_PORT": "8443", "MODSEC_RULE_ENGINE": "On",
		"MODSEC_REQ_BODY_ACCESS": "On", "ACCESSLOG": "/dev/null", "METRICSLOG": "/dev/null",
		"ERRORLOG": "/usr/local/apache2/logs/error.log", "MODSEC_AUDIT_ENGINE": "RelevantOnly",
		"MODSEC_AUDIT_LOG": "/tmp/modsec-audit.log",
	})
	var apacheOutput lockedBuffer
	command.Stdout = &apacheOutput
	command.Stderr = &apacheOutput
	if err := command.Start(); err != nil {
		return fmt.Errorf("start ModSecurity: %w", err)
	}
	defer func() {
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		_ = command.Wait()
	}()
	if err := waitForTestbed(ctx, command); err != nil {
		return fmt.Errorf("ModSecurity testbed did not start: %w; output: %.2000s", err, apacheOutput.String())
	}
	results, err := attacks.Probe(ctx, "http://127.0.0.1:8080", job.AttackCategories)
	if err != nil {
		return err
	}
	for i := range results {
		results[i].Engine = "modsecurity2_apache"
	}
	if audit, err := os.Open("/tmp/modsec-audit.log"); err == nil {
		attacks.AttachModSecurityRuleIDs(results, audit)
		_ = audit.Close()
	}
	receipt := attacks.Receipt{JobID: job.ID, SnapshotHash: job.SnapshotHash(), Results: results}
	if err := attacks.ValidateReceipt(receipt, job.ID, job.SnapshotHash(), job.AttackCategories); err != nil {
		return err
	}
	resultData, err := json.Marshal(receipt)
	if err != nil {
		return err
	}
	return saveReceipt(ctx, resultData)
}

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func loadJob(ctx context.Context) ([]byte, error) {
	const maxBytes = core.MaxSnapshotBytes*6 + 8192
	if path := os.Getenv("LOCAL_JOB_FILE"); path != "" {
		file, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		return boundedRead(file, maxBytes)
	}
	url := os.Getenv("JOB_GET_URL")
	if !strings.HasPrefix(url, "https://") {
		return nil, errors.New("JOB_GET_URL must be an HTTPS presigned URL")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if err := applySignedHeaders(request, os.Getenv("JOB_GET_HEADERS")); err != nil {
		return nil, err
	}
	response, err := (&http.Client{Timeout: 10 * time.Second}).Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("job download returned %d", response.StatusCode)
	}
	return boundedRead(response.Body, maxBytes)
}

func boundedRead(r io.Reader, max int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil || int64(len(data)) > max {
		return nil, errors.New("input is unreadable or too large")
	}
	return data, nil
}

func saveReceipt(ctx context.Context, data []byte) error {
	if path := os.Getenv("LOCAL_RESULT_FILE"); path != "" {
		return os.WriteFile(path, data, 0600)
	}
	url := os.Getenv("RESULT_PUT_URL")
	if !strings.HasPrefix(url, "https://") {
		return errors.New("RESULT_PUT_URL must be an HTTPS presigned URL")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader(data))
	if err != nil {
		return err
	}
	if err := applySignedHeaders(request, os.Getenv("RESULT_PUT_HEADERS")); err != nil {
		return err
	}
	response, err := (&http.Client{Timeout: 10 * time.Second}).Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("receipt upload returned %d", response.StatusCode)
	}
	return nil
}

func cleanEnvironment(original []string, overrides map[string]string) []string {
	var result []string
	for _, item := range original {
		name, _, _ := strings.Cut(item, "=")
		if strings.HasPrefix(name, "AWS_") || strings.HasPrefix(name, "ECS_") {
			continue
		}
		if name == "JOB_GET_URL" || name == "JOB_GET_HEADERS" || name == "RESULT_PUT_URL" || name == "RESULT_PUT_HEADERS" || name == "LOCAL_JOB_FILE" || name == "LOCAL_RESULT_FILE" {
			continue
		}
		if _, replaced := overrides[name]; !replaced {
			result = append(result, item)
		}
	}
	for name, value := range overrides {
		result = append(result, name+"="+value)
	}
	return result
}

func applySignedHeaders(request *http.Request, encoded string) error {
	if encoded == "" {
		return nil
	}
	var headers http.Header
	if err := json.Unmarshal([]byte(encoded), &headers); err != nil {
		return fmt.Errorf("decode signed headers: %w", err)
	}
	for name, values := range headers {
		if strings.EqualFold(name, "Host") {
			if len(values) != 1 {
				return errors.New("invalid signed Host header")
			}
			request.Host = values[0]
			continue
		}
		for _, value := range values {
			request.Header.Add(name, value)
		}
	}
	return nil
}

func waitForTestbed(ctx context.Context, command *exec.Cmd) error {
	client := &http.Client{Timeout: 500 * time.Millisecond}
	deadline := time.NewTimer(30 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(150 * time.Millisecond)
	defer tick.Stop()
	for {
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1:8080/healthz", nil)
		response, err := client.Do(request)
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return nil
			}
		}
		if command.ProcessState != nil && command.ProcessState.Exited() {
			return errors.New("Apache exited")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return errors.New("startup timeout")
		case <-tick.C:
		}
	}
}
