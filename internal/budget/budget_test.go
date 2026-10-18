package budget

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"waf-rule-evaluations/internal/core"
)

type fakeTransactor struct {
	called bool
	err    error
}

func (f *fakeTransactor) TransactWriteItems(_ context.Context, in *dynamodb.TransactWriteItemsInput, _ ...func(*dynamodb.Options)) (*dynamodb.TransactWriteItemsOutput, error) {
	f.called = true
	if f.err != nil {
		return nil, f.err
	}
	if len(in.TransactItems) != 3 || in.TransactItems[0].Put == nil || in.TransactItems[1].Update == nil || in.TransactItems[2].Update == nil {
		return nil, errors.New("reservation did not include all three atomic writes")
	}
	if v, ok := in.TransactItems[1].Update.ExpressionAttributeValues[":remaining"].(*types.AttributeValueMemberN); !ok || v.Value != "0" {
		return nil, errors.New("wrong remaining budget at boundary")
	}
	if _, ok := in.TransactItems[0].Put.Item["expires_at"].(*types.AttributeValueMemberN); !ok {
		return nil, errors.New("job expiry is missing")
	}
	for _, item := range in.TransactItems[1:] {
		if _, ok := item.Update.ExpressionAttributeValues[":expires_at"].(*types.AttributeValueMemberN); !ok {
			return nil, errors.New("quota expiry is missing")
		}
	}
	return &dynamodb.TransactWriteItemsOutput{}, nil
}

func TestReserveReportsGlobalBudgetLimit(t *testing.T) {
	f := &fakeTransactor{err: &types.TransactionCanceledException{CancellationReasons: []types.CancellationReason{
		{Code: ptr("None")}, {Code: ptr("ConditionalCheckFailed")}, {Code: ptr("None")},
	}}}
	s := Store{Client: f, Table: "quota"}
	j := core.Job{ID: "j", UserID: "u", Kind: "aws_waf", Snapshot: "{}", AttackCategories: []string{"sqli"}}
	if err := s.Reserve(context.Background(), j, "2026-10-18", 1); !errors.Is(err, core.ErrBudgetExceeded) {
		t.Fatalf("got %v; want budget exceeded", err)
	}
}

func ptr(s string) *string { return &s }

func TestReserveEnforcesDailyCeilingBeforeCall(t *testing.T) {
	f := &fakeTransactor{}
	s := Store{Client: f, Table: "quota"}
	j := core.Job{ID: "j", UserID: "u", Kind: "aws_waf", Snapshot: "{}", AttackCategories: []string{"sqli"}}
	if err := s.Reserve(context.Background(), j, "2026-10-18", core.DailyBudgetMicroUSD+1); !errors.Is(err, core.ErrBudgetExceeded) {
		t.Fatalf("got %v", err)
	}
	if f.called {
		t.Fatal("DynamoDB was called for an over-budget job")
	}
	if err := s.Reserve(context.Background(), j, "2026-10-18", core.DailyBudgetMicroUSD); err != nil {
		t.Fatal(err)
	}
}
