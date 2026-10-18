package budget

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"waf-rule-evaluations/internal/core"
)

var ErrRejected = errors.New("reservation rejected")
var ErrDuplicateJob = errors.New("job already submitted")
var ErrUserLimit = errors.New("user daily evaluation limit reached")

type Transactor interface {
	TransactWriteItems(context.Context, *dynamodb.TransactWriteItemsInput, ...func(*dynamodb.Options)) (*dynamodb.TransactWriteItemsOutput, error)
}

type Store struct {
	Client Transactor
	Table  string
}

// Reserve is the only path to Bedrock. One transaction claims the job, charges
// its worst-case cost against the JST day, and consumes the user's daily slot.
// Failed or interrupted jobs retain their reservation; this errs on the side
// of spending less rather than overspending or invoking the model twice.
func (s Store) Reserve(ctx context.Context, job core.Job, day string, costMicroUSD int64) error {
	if s.Client == nil || s.Table == "" || day == "" {
		return errors.New("budget store is not configured")
	}
	if err := job.Validate(); err != nil {
		return err
	}
	if costMicroUSD <= 0 || costMicroUSD > core.DailyBudgetMicroUSD {
		return core.ErrBudgetExceeded
	}
	dayStart, err := time.ParseInLocation("2006-01-02", day, time.FixedZone("JST", 9*60*60))
	if err != nil {
		return fmt.Errorf("invalid JST day: %w", err)
	}
	expiresAt := dayStart.AddDate(0, 0, 32).Unix()
	limitBeforeWrite := core.DailyBudgetMicroUSD - costMicroUSD
	str := func(v string) types.AttributeValue { return &types.AttributeValueMemberS{Value: v} }
	num := func(v int64) types.AttributeValue {
		return &types.AttributeValueMemberN{Value: strconv.FormatInt(v, 10)}
	}
	jobPK := "JOB#" + job.ID
	userPK := "USER#" + day + "#" + job.UserID
	budgetPK := "BUDGET#" + day
	_, err = s.Client.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{
		TransactItems: []types.TransactWriteItem{
			{Put: &types.Put{
				TableName: aws.String(s.Table),
				Item: map[string]types.AttributeValue{
					"pk": str(jobPK), "status": str("reserved"), "user_id": str(job.UserID),
					"day": str(day), "reserved_micro_usd": num(costMicroUSD), "snapshot_hash": str(job.SnapshotHash()), "expires_at": num(expiresAt),
				},
				ConditionExpression: aws.String("attribute_not_exists(pk)"),
			}},
			{Update: &types.Update{
				TableName:                aws.String(s.Table),
				Key:                      map[string]types.AttributeValue{"pk": str(budgetPK)},
				UpdateExpression:         aws.String("SET #reserved = if_not_exists(#reserved, :zero) + :cost, expires_at = if_not_exists(expires_at, :expires_at)"),
				ConditionExpression:      aws.String("attribute_not_exists(#reserved) OR #reserved <= :remaining"),
				ExpressionAttributeNames: map[string]string{"#reserved": "reserved_micro_usd"},
				ExpressionAttributeValues: map[string]types.AttributeValue{
					":zero": num(0), ":cost": num(costMicroUSD), ":remaining": num(limitBeforeWrite), ":expires_at": num(expiresAt),
				},
			}},
			{Update: &types.Update{
				TableName:                aws.String(s.Table),
				Key:                      map[string]types.AttributeValue{"pk": str(userPK)},
				UpdateExpression:         aws.String("SET #used = if_not_exists(#used, :zero) + :one, expires_at = if_not_exists(expires_at, :expires_at)"),
				ConditionExpression:      aws.String("attribute_not_exists(#used) OR #used < :one"),
				ExpressionAttributeNames: map[string]string{"#used": "used"},
				ExpressionAttributeValues: map[string]types.AttributeValue{
					":zero": num(0), ":one": num(1), ":expires_at": num(expiresAt),
				},
			}},
		},
	})
	if err != nil {
		var canceled *types.TransactionCanceledException
		if errors.As(err, &canceled) {
			conditional := func(index int) bool {
				return len(canceled.CancellationReasons) > index &&
					aws.ToString(canceled.CancellationReasons[index].Code) == "ConditionalCheckFailed"
			}
			if conditional(0) {
				return ErrDuplicateJob
			}
			if conditional(1) {
				return core.ErrBudgetExceeded
			}
			if conditional(2) {
				return ErrUserLimit
			}
			return fmt.Errorf("%w: %v", ErrRejected, err)
		}
		return fmt.Errorf("reserve Bedrock budget: %w", err)
	}
	return nil
}
