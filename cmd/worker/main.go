package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	brtypes "github.com/aws/aws-sdk-go-v2/service/bedrockruntime/types"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"waf-rule-evaluations/internal/attacks"
	"waf-rule-evaluations/internal/budget"
	"waf-rule-evaluations/internal/core"
	"waf-rule-evaluations/internal/evaluate"
	"waf-rule-evaluations/internal/loganalysis"
	"waf-rule-evaluations/internal/probeexec"
)

type settings struct {
	JobBucket       string
	JobKey          string
	ResultBucket    string
	BudgetTable     string
	ModelID         string
	InputRate       int64 // microUSD per million tokens
	OutputRate      int64 // microUSD per million tokens
	MaxInputTokens  int32
	MaxOutputTokens int32
}

type report struct {
	JobID            string                   `json:"job_id"`
	Kind             string                   `json:"kind"`
	Language         string                   `json:"language"`
	SnapshotHash     string                   `json:"snapshot_hash"`
	ModelID          string                   `json:"model_id"`
	JSTDay           string                   `json:"jst_day"`
	Assessment       string                   `json:"assessment"`
	Summary          string                   `json:"summary"`
	InputTokens      int32                    `json:"input_tokens"`
	OutputTokens     int32                    `json:"output_tokens"`
	ReservedMicroUSD int64                    `json:"reserved_micro_usd"`
	AttackResults    []attacks.CategoryResult `json:"attack_results"`
	LogStats         *loganalysis.Stats       `json:"log_stats,omitempty"`
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()
	if err := run(ctx); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context) error {
	s, err := loadSettings()
	if err != nil {
		return err
	}
	awsConfig, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return fmt.Errorf("load AWS configuration: %w", err)
	}
	s3Client := s3.NewFromConfig(awsConfig)
	// A timed-out inference may already have been billed. Disable SDK retries so
	// one reservation can never cause more than one model invocation attempt.
	bedrockClient := bedrockruntime.NewFromConfig(awsConfig, func(o *bedrockruntime.Options) {
		o.Retryer = aws.NopRetryer{}
	})
	ddbClient := dynamodb.NewFromConfig(awsConfig)

	job, err := readJob(ctx, s3Client, s.JobBucket, s.JobKey)
	if err != nil {
		return err
	}
	var attackResults []attacks.CategoryResult
	var logStats *loganalysis.Stats
	var uploadedDigest string
	if job.Kind == "traffic_log" {
		var stats loganalysis.Stats
		if job.LogObjectKey != "" {
			stats, uploadedDigest, err = analyzeUploadedLog(ctx, s3Client, s.JobBucket, job)
		} else {
			stats, err = loganalysis.Analyze(job.LogFormat, job.Snapshot)
		}
		if err != nil {
			if errors.Is(err, loganalysis.ErrFormat) {
				if recordErr := recordLogFormatFailure(ctx, ddbClient, s.BudgetTable, job); recordErr != nil {
					return fmt.Errorf("record format failure: %w", recordErr)
				}
			}
			return err
		}
		logStats = &stats
	} else {
		attackResults, err = attacks.Planned(job.AttackCategories)
		if err != nil {
			return err
		}
	}
	day := core.JSTDay(time.Now())
	var reserved int64
	if job.ProbeResultKey != "" {
		probeSettings, err := probeexec.LoadSettings()
		if err != nil {
			return err
		}
		// Reserve the maximum configured input cost before starting the probe.
		// This also consumes the user's daily slot before any ECS test charges.
		reserved, err = core.WorstCaseMicroUSD(s.MaxInputTokens, s.MaxOutputTokens, s.InputRate, s.OutputRate)
		if err != nil {
			return err
		}
		if err := (budget.Store{Client: ddbClient, Table: s.BudgetTable}).Reserve(ctx, job, day, reserved); err != nil {
			return err
		}
		receipt, err := probeexec.Run(ctx, ecs.NewFromConfig(awsConfig), s3.NewPresignClient(s3Client), s3Client, probeSettings, job, s.JobBucket, s.JobKey, s.ResultBucket)
		if err != nil {
			return err
		}
		attackResults = receipt.Results
	}
	var prompt string
	if logStats != nil {
		prompt, err = evaluate.TrafficPrompt(job, *logStats)
	} else {
		prompt, err = evaluate.Prompt(job, attackResults)
	}
	if err != nil {
		return err
	}
	messages := []brtypes.Message{{Role: brtypes.ConversationRoleUser, Content: []brtypes.ContentBlock{&brtypes.ContentBlockMemberText{Value: prompt}}}}
	systemText := evaluate.System
	if logStats != nil {
		systemText = evaluate.TrafficSystem
	}
	system := []brtypes.SystemContentBlock{&brtypes.SystemContentBlockMemberText{Value: systemText}}
	tokenCount, err := bedrockClient.CountTokens(ctx, &bedrockruntime.CountTokensInput{
		ModelId: aws.String(s.ModelID),
		Input:   &brtypes.CountTokensInputMemberConverse{Value: brtypes.ConverseTokensRequest{Messages: messages, System: system}},
	})
	if err != nil {
		return fmt.Errorf("CountTokens failed; no budget was reserved and Bedrock was not invoked: %w", err)
	}
	if tokenCount.InputTokens == nil || *tokenCount.InputTokens <= 0 || *tokenCount.InputTokens > s.MaxInputTokens {
		return fmt.Errorf("input token count is missing or above configured limit of %d", s.MaxInputTokens)
	}
	if job.ProbeResultKey == "" {
		reserved, err = core.WorstCaseMicroUSD(*tokenCount.InputTokens, s.MaxOutputTokens, s.InputRate, s.OutputRate)
		if err != nil {
			return err
		}
		if err := (budget.Store{Client: ddbClient, Table: s.BudgetTable}).Reserve(ctx, job, day, reserved); err != nil {
			return err
		}
	}
	if core.JSTDay(time.Now()) != day {
		return errors.New("JST day changed after reservation; Bedrock was not invoked")
	}

	response, err := bedrockClient.Converse(ctx, &bedrockruntime.ConverseInput{
		ModelId:         aws.String(s.ModelID),
		Messages:        messages,
		System:          system,
		InferenceConfig: &brtypes.InferenceConfiguration{MaxTokens: aws.Int32(s.MaxOutputTokens)},
		RequestMetadata: map[string]string{"job_id": job.ID, "kind": job.Kind},
	})
	if err != nil {
		return fmt.Errorf("Converse failed; reservation remains charged to the daily ceiling: %w", err)
	}
	assessment, err := responseText(response)
	if err != nil {
		return err
	}
	r := report{
		JobID: job.ID, Kind: job.Kind, Language: job.ReportLanguage(), SnapshotHash: job.SnapshotHash(), ModelID: s.ModelID,
		JSTDay: day, Assessment: assessment, Summary: evaluate.Summary(job.ReportLanguage(), attackResults),
		ReservedMicroUSD: reserved, AttackResults: attackResults, LogStats: logStats,
	}
	if uploadedDigest != "" {
		r.SnapshotHash = uploadedDigest
	}
	if logStats != nil {
		r.Summary = evaluate.TrafficSummary(job.ReportLanguage(), *logStats)
	}
	if response.Usage != nil {
		r.InputTokens = aws.ToInt32(response.Usage.InputTokens)
		r.OutputTokens = aws.ToInt32(response.Usage.OutputTokens)
	}
	resultKey := "results/" + job.ID + ".json"
	if err := writeReport(ctx, s3Client, s.ResultBucket, resultKey, r); err != nil {
		return err
	}
	_, err = ddbClient.UpdateItem(ctx, &dynamodb.UpdateItemInput{
		TableName:                aws.String(s.BudgetTable),
		Key:                      map[string]ddbtypes.AttributeValue{"pk": &ddbtypes.AttributeValueMemberS{Value: "JOB#" + job.ID}},
		UpdateExpression:         aws.String("SET #status = :complete, result_key = :result"),
		ConditionExpression:      aws.String("#status = :reserved"),
		ExpressionAttributeNames: map[string]string{"#status": "status"},
		ExpressionAttributeValues: map[string]ddbtypes.AttributeValue{
			":complete": &ddbtypes.AttributeValueMemberS{Value: "complete"},
			":reserved": &ddbtypes.AttributeValueMemberS{Value: "reserved"},
			":result":   &ddbtypes.AttributeValueMemberS{Value: resultKey},
		},
	})
	if err != nil {
		return fmt.Errorf("report written to S3 but job status update failed: %w", err)
	}
	log.Printf("completed job %s; Bedrock reservation %d microUSD; report s3://%s/%s", job.ID, reserved, s.ResultBucket, resultKey)
	return nil
}

func analyzeUploadedLog(ctx context.Context, client *s3.Client, bucket string, job core.Job) (loganalysis.Stats, string, error) {
	var empty loganalysis.Stats
	result, err := client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(job.LogObjectKey)})
	if err != nil {
		return empty, "", fmt.Errorf("read uploaded log: %w", err)
	}
	defer result.Body.Close()
	if result.ContentLength == nil || *result.ContentLength <= 0 || *result.ContentLength > core.MaxTrafficLogBytes {
		return empty, "", loganalysis.ErrFormat
	}
	hash := sha256.New()
	stats, err := loganalysis.AnalyzeReader(job.LogFormat, io.TeeReader(io.LimitReader(result.Body, core.MaxTrafficLogBytes+1), hash))
	if err != nil {
		return empty, "", err
	}
	return stats, hex.EncodeToString(hash.Sum(nil)), nil
}

func recordLogFormatFailure(ctx context.Context, client *dynamodb.Client, table string, job core.Job) error {
	_, err := client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(table),
		Item: map[string]ddbtypes.AttributeValue{
			"pk":         &ddbtypes.AttributeValueMemberS{Value: "JOB#" + job.ID},
			"status":     &ddbtypes.AttributeValueMemberS{Value: "failed"},
			"error_code": &ddbtypes.AttributeValueMemberS{Value: "LOG_FORMAT"},
			"expires_at": &ddbtypes.AttributeValueMemberN{Value: strconv.FormatInt(time.Now().Add(3*24*time.Hour).Unix(), 10)},
		},
		ConditionExpression: aws.String("attribute_not_exists(pk)"),
	})
	return err
}

func loadSettings() (settings, error) {
	required := func(name string) (string, error) {
		v := strings.TrimSpace(os.Getenv(name))
		if v == "" {
			return "", fmt.Errorf("%s is required", name)
		}
		return v, nil
	}
	var s settings
	var err error
	for _, field := range []struct {
		name string
		dest *string
	}{
		{"JOB_BUCKET", &s.JobBucket}, {"JOB_KEY", &s.JobKey}, {"RESULT_BUCKET", &s.ResultBucket},
		{"BUDGET_TABLE", &s.BudgetTable}, {"BEDROCK_MODEL_ID", &s.ModelID},
	} {
		*field.dest, err = required(field.name)
		if err != nil {
			return s, err
		}
	}
	parsePositive := func(name string) (int64, error) {
		v, err := required(name)
		if err != nil {
			return 0, err
		}
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n <= 0 {
			return 0, fmt.Errorf("%s must be a positive integer", name)
		}
		return n, nil
	}
	s.InputRate, err = parsePositive("BEDROCK_INPUT_MICROUSD_PER_MILLION")
	if err != nil {
		return s, err
	}
	s.OutputRate, err = parsePositive("BEDROCK_OUTPUT_MICROUSD_PER_MILLION")
	if err != nil {
		return s, err
	}
	n, err := parsePositive("MAX_INPUT_TOKENS")
	if err != nil || n > 1_000_000 {
		return s, errors.New("MAX_INPUT_TOKENS must be 1..1000000")
	}
	s.MaxInputTokens = int32(n)
	n, err = parsePositive("MAX_OUTPUT_TOKENS")
	if err != nil || n > 100_000 {
		return s, errors.New("MAX_OUTPUT_TOKENS must be 1..100000")
	}
	s.MaxOutputTokens = int32(n)
	return s, nil
}

func readJob(ctx context.Context, client *s3.Client, bucket, key string) (core.Job, error) {
	var job core.Job
	// JSON escaping can expand each snapshot byte to a six-byte \u escape.
	const maxJobBytes = core.MaxSnapshotBytes*6 + 8*1024
	result, err := client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(key)})
	if err != nil {
		return job, fmt.Errorf("read S3 job: %w", err)
	}
	defer result.Body.Close()
	content, err := io.ReadAll(io.LimitReader(result.Body, maxJobBytes+1))
	if err != nil {
		return job, err
	}
	if len(content) > maxJobBytes {
		return job, errors.New("job object exceeds configured limit")
	}
	if err := json.Unmarshal(content, &job); err != nil {
		return job, err
	}
	return job, job.Validate()
}

func responseText(response *bedrockruntime.ConverseOutput) (string, error) {
	if response == nil {
		return "", errors.New("empty Bedrock response")
	}
	if response.StopReason != brtypes.StopReasonEndTurn {
		return "", fmt.Errorf("Bedrock assessment did not finish normally: %s", response.StopReason)
	}
	message, ok := response.Output.(*brtypes.ConverseOutputMemberMessage)
	if !ok {
		return "", errors.New("Bedrock response had no message")
	}
	var chunks []string
	for _, content := range message.Value.Content {
		if t, ok := content.(*brtypes.ContentBlockMemberText); ok {
			chunks = append(chunks, t.Value)
		}
	}
	if len(chunks) == 0 {
		return "", errors.New("Bedrock response had no text")
	}
	return strings.Join(chunks, "\n"), nil
}

func writeReport(ctx context.Context, client *s3.Client, bucket, key string, value report) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	_, err = client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(bucket), Key: aws.String(key), Body: bytes.NewReader(data),
		ContentType: aws.String("application/json"),
	})
	if err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	return nil
}
