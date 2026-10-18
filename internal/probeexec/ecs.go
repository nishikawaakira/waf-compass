package probeexec

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"

	"waf-rule-evaluations/internal/attacks"
	"waf-rule-evaluations/internal/core"
)

type Settings struct {
	Cluster        string
	TaskDefinition string
	Container      string
	Subnets        []string
	SecurityGroups []string
}

func LoadSettings() (Settings, error) {
	s := Settings{
		Cluster:        strings.TrimSpace(os.Getenv("PROBE_ECS_CLUSTER")),
		TaskDefinition: strings.TrimSpace(os.Getenv("PROBE_ECS_TASK_DEFINITION")),
		Container:      strings.TrimSpace(os.Getenv("PROBE_ECS_CONTAINER")),
		Subnets:        splitIDs(os.Getenv("PROBE_ECS_SUBNETS")),
		SecurityGroups: splitIDs(os.Getenv("PROBE_ECS_SECURITY_GROUPS")),
	}
	if s.Cluster == "" || s.TaskDefinition == "" || s.Container == "" || len(s.Subnets) == 0 || len(s.SecurityGroups) == 0 {
		return s, errors.New("probe ECS cluster, task definition, container, subnets, and security groups are required")
	}
	return s, nil
}

func splitIDs(value string) []string {
	var result []string
	for _, raw := range strings.Split(value, ",") {
		if item := strings.TrimSpace(raw); item != "" {
			result = append(result, item)
		}
	}
	return result
}

type ECSAPI interface {
	DescribeTaskDefinition(context.Context, *ecs.DescribeTaskDefinitionInput, ...func(*ecs.Options)) (*ecs.DescribeTaskDefinitionOutput, error)
	RunTask(context.Context, *ecs.RunTaskInput, ...func(*ecs.Options)) (*ecs.RunTaskOutput, error)
	DescribeTasks(context.Context, *ecs.DescribeTasksInput, ...func(*ecs.Options)) (*ecs.DescribeTasksOutput, error)
	StopTask(context.Context, *ecs.StopTaskInput, ...func(*ecs.Options)) (*ecs.StopTaskOutput, error)
}

type Presigner interface {
	PresignGetObject(context.Context, *s3.GetObjectInput, ...func(*s3.PresignOptions)) (*v4.PresignedHTTPRequest, error)
	PresignPutObject(context.Context, *s3.PutObjectInput, ...func(*s3.PresignOptions)) (*v4.PresignedHTTPRequest, error)
}

type ReceiptReader interface {
	GetObject(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error)
}

// Run uses a dedicated ECS task definition with no task role. The caller must
// reserve the user's daily slot and worst-case Bedrock budget before calling.
func Run(ctx context.Context, client ECSAPI, presigner Presigner, reader ReceiptReader, s Settings, job core.Job, jobBucket, jobKey, resultBucket string) (attacks.Receipt, error) {
	var empty attacks.Receipt
	if job.Kind != "modsecurity" || job.ProbeResultKey == "" {
		return empty, errors.New("ModSecurity job with probe_result_key required")
	}
	definition, err := client.DescribeTaskDefinition(ctx, &ecs.DescribeTaskDefinitionInput{TaskDefinition: aws.String(s.TaskDefinition)})
	if err != nil {
		return empty, fmt.Errorf("describe probe task definition: %w", err)
	}
	if definition.TaskDefinition == nil || aws.ToString(definition.TaskDefinition.TaskRoleArn) != "" || definition.TaskDefinition.NetworkMode != ecstypes.NetworkModeAwsvpc {
		return empty, errors.New("probe task definition must use awsvpc and have no task role")
	}
	containerFound := false
	for _, container := range definition.TaskDefinition.ContainerDefinitions {
		if aws.ToString(container.Name) == s.Container {
			containerFound = true
		}
	}
	if !containerFound {
		return empty, errors.New("probe container name not found in task definition")
	}
	getURL, err := presigner.PresignGetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(jobBucket), Key: aws.String(jobKey)}, func(o *s3.PresignOptions) { o.Expires = 15 * time.Minute })
	if err != nil {
		return empty, fmt.Errorf("presign probe input: %w", err)
	}
	putURL, err := presigner.PresignPutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(resultBucket), Key: aws.String(job.ProbeResultKey)}, func(o *s3.PresignOptions) { o.Expires = 15 * time.Minute })
	if err != nil {
		return empty, fmt.Errorf("presign probe result: %w", err)
	}
	getHeaders, err := json.Marshal(getURL.SignedHeader)
	if err != nil {
		return empty, err
	}
	putHeaders, err := json.Marshal(putURL.SignedHeader)
	if err != nil {
		return empty, err
	}
	tokenSum := sha256.Sum256([]byte(job.ID))
	started, err := client.RunTask(ctx, &ecs.RunTaskInput{
		Cluster: aws.String(s.Cluster), TaskDefinition: aws.String(s.TaskDefinition), LaunchType: ecstypes.LaunchTypeFargate,
		Count: aws.Int32(1), StartedBy: aws.String(job.ID), ClientToken: aws.String(hex.EncodeToString(tokenSum[:])),
		NetworkConfiguration: &ecstypes.NetworkConfiguration{AwsvpcConfiguration: &ecstypes.AwsVpcConfiguration{
			Subnets: s.Subnets, SecurityGroups: s.SecurityGroups, AssignPublicIp: ecstypes.AssignPublicIpDisabled,
		}},
		Overrides: &ecstypes.TaskOverride{ContainerOverrides: []ecstypes.ContainerOverride{{Name: aws.String(s.Container), Environment: []ecstypes.KeyValuePair{
			{Name: aws.String("JOB_GET_URL"), Value: aws.String(getURL.URL)},
			{Name: aws.String("JOB_GET_HEADERS"), Value: aws.String(string(getHeaders))},
			{Name: aws.String("RESULT_PUT_URL"), Value: aws.String(putURL.URL)},
			{Name: aws.String("RESULT_PUT_HEADERS"), Value: aws.String(string(putHeaders))},
		}}}},
	})
	if err != nil {
		return empty, fmt.Errorf("start probe ECS task: %w", err)
	}
	if len(started.Failures) != 0 || len(started.Tasks) != 1 || started.Tasks[0].TaskArn == nil {
		return empty, fmt.Errorf("probe ECS task did not start: %v", started.Failures)
	}
	taskARN := aws.ToString(started.Tasks[0].TaskArn)
	completed := false
	defer func() {
		if !completed {
			stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, _ = client.StopTask(stopCtx, &ecs.StopTaskInput{Cluster: aws.String(s.Cluster), Task: aws.String(taskARN), Reason: aws.String("WAF evaluation ended")})
		}
	}()

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		receipt, err := readReceipt(ctx, reader, resultBucket, job.ProbeResultKey)
		if err == nil {
			if err := attacks.ValidateReceipt(receipt, job.ID, job.SnapshotHash(), job.AttackCategories); err != nil {
				return empty, fmt.Errorf("probe receipt validation: %w", err)
			}
			for _, result := range receipt.Results {
				if result.Engine != "modsecurity2_apache" {
					return empty, errors.New("probe receipt was not produced by the configured ModSecurity 2 testbed")
				}
			}
			completed = true
			return receipt, nil
		}
		var noSuchKey *s3types.NoSuchKey
		if !errors.As(err, &noSuchKey) {
			return empty, fmt.Errorf("read probe receipt: %w", err)
		}
		tasks, err := client.DescribeTasks(ctx, &ecs.DescribeTasksInput{Cluster: aws.String(s.Cluster), Tasks: []string{taskARN}})
		if err != nil {
			return empty, fmt.Errorf("describe probe task: %w", err)
		}
		if len(tasks.Tasks) == 1 && tasks.Tasks[0].LastStatus != nil && *tasks.Tasks[0].LastStatus == "STOPPED" {
			return empty, fmt.Errorf("probe task stopped before writing a receipt: %s", aws.ToString(tasks.Tasks[0].StoppedReason))
		}
		select {
		case <-ctx.Done():
			return empty, ctx.Err()
		case <-ticker.C:
		}
	}
}

func readReceipt(ctx context.Context, reader ReceiptReader, bucket, key string) (attacks.Receipt, error) {
	var receipt attacks.Receipt
	result, err := reader.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(key)})
	if err != nil {
		return receipt, err
	}
	defer result.Body.Close()
	const maxReceiptBytes = 64 * 1024
	data, err := io.ReadAll(io.LimitReader(result.Body, maxReceiptBytes+1))
	if err != nil || len(data) > maxReceiptBytes {
		return receipt, errors.New("probe receipt is unreadable or too large")
	}
	if err := json.Unmarshal(data, &receipt); err != nil {
		return receipt, fmt.Errorf("decode probe receipt: %w", err)
	}
	return receipt, nil
}
