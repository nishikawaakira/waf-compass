package probeexec

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"waf-rule-evaluations/internal/attacks"
	"waf-rule-evaluations/internal/core"
)

type fakeECS struct {
	roleArn string
	run     *ecs.RunTaskInput
}

func (f *fakeECS) DescribeTaskDefinition(context.Context, *ecs.DescribeTaskDefinitionInput, ...func(*ecs.Options)) (*ecs.DescribeTaskDefinitionOutput, error) {
	return &ecs.DescribeTaskDefinitionOutput{TaskDefinition: &ecstypes.TaskDefinition{
		TaskRoleArn: aws.String(f.roleArn), NetworkMode: ecstypes.NetworkModeAwsvpc,
		ContainerDefinitions: []ecstypes.ContainerDefinition{{Name: aws.String("probe")}},
	}}, nil
}
func (f *fakeECS) RunTask(_ context.Context, input *ecs.RunTaskInput, _ ...func(*ecs.Options)) (*ecs.RunTaskOutput, error) {
	f.run = input
	return &ecs.RunTaskOutput{Tasks: []ecstypes.Task{{TaskArn: aws.String("arn:aws:ecs:region:account:task/test")}}}, nil
}
func (f *fakeECS) DescribeTasks(context.Context, *ecs.DescribeTasksInput, ...func(*ecs.Options)) (*ecs.DescribeTasksOutput, error) {
	return &ecs.DescribeTasksOutput{}, nil
}
func (f *fakeECS) StopTask(context.Context, *ecs.StopTaskInput, ...func(*ecs.Options)) (*ecs.StopTaskOutput, error) {
	return &ecs.StopTaskOutput{}, nil
}

type fakePresigner struct{}

func (fakePresigner) PresignGetObject(context.Context, *s3.GetObjectInput, ...func(*s3.PresignOptions)) (*v4.PresignedHTTPRequest, error) {
	return &v4.PresignedHTTPRequest{URL: "https://s3.example/job"}, nil
}
func (fakePresigner) PresignPutObject(context.Context, *s3.PutObjectInput, ...func(*s3.PresignOptions)) (*v4.PresignedHTTPRequest, error) {
	return &v4.PresignedHTTPRequest{URL: "https://s3.example/result"}, nil
}

type fakeReader struct{ receipt []byte }

func (f fakeReader) GetObject(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	return &s3.GetObjectOutput{Body: io.NopCloser(bytes.NewReader(f.receipt))}, nil
}

func TestRunLaunchesPrivateCredentialFreeTask(t *testing.T) {
	job := core.Job{ID: "job1", UserID: "user1", Kind: "modsecurity", Snapshot: "SecRuleEngine On", AttackCategories: []string{"sqli"}, ProbeResultKey: "probe-results/job1.json"}
	cases, _ := attacks.Cases(job.AttackCategories)
	result := attacks.CategoryResult{Category: "sqli", Mode: "local_http_probe", Outcome: "samples_passed", Engine: "modsecurity2_apache"}
	for _, c := range cases {
		status, observed := 200, "allowed"
		if c.WantBlock {
			status, observed = 403, "blocked"
		}
		result.Cases = append(result.Cases, attacks.CaseResult{CaseID: c.ID, Category: c.Category, WantBlock: c.WantBlock, HTTPStatus: status, Observed: observed, Passed: true})
	}
	data, _ := json.Marshal(attacks.Receipt{JobID: job.ID, SnapshotHash: job.SnapshotHash(), Results: []attacks.CategoryResult{result}})
	client := &fakeECS{}
	settings := Settings{Cluster: "cluster", TaskDefinition: "task", Container: "probe", Subnets: []string{"subnet-1"}, SecurityGroups: []string{"sg-1"}}
	if _, err := Run(context.Background(), client, fakePresigner{}, fakeReader{data}, settings, job, "jobs", "job.json", "results"); err != nil {
		t.Fatal(err)
	}
	if client.run == nil || client.run.LaunchType != ecstypes.LaunchTypeFargate || client.run.NetworkConfiguration.AwsvpcConfiguration.AssignPublicIp != ecstypes.AssignPublicIpDisabled || len(aws.ToString(client.run.ClientToken)) != 64 {
		t.Fatalf("probe task was not private Fargate: %+v", client.run)
	}
	client = &fakeECS{roleArn: "arn:aws:iam::123:role/unsafe"}
	if _, err := Run(context.Background(), client, fakePresigner{}, fakeReader{data}, settings, job, "jobs", "job.json", "results"); err == nil || client.run != nil {
		t.Fatal("task role should be rejected before launching")
	}
}
