package main

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	brtypes "github.com/aws/aws-sdk-go-v2/service/bedrockruntime/types"
)

func TestResponseTextRejectsTruncation(t *testing.T) {
	response := &bedrockruntime.ConverseOutput{
		StopReason: brtypes.StopReasonMaxTokens,
		Output: &brtypes.ConverseOutputMemberMessage{Value: brtypes.Message{
			Content: []brtypes.ContentBlock{&brtypes.ContentBlockMemberText{Value: "partial report"}},
		}},
	}
	if _, err := responseText(response); err == nil {
		t.Fatal("a truncated natural-language report must not be published")
	}
	response.StopReason = brtypes.StopReasonGuardrailIntervened
	if _, err := responseText(response); err == nil {
		t.Fatal("a filtered report must not be published as a complete assessment")
	}
	response.StopReason = brtypes.StopReasonEndTurn
	if got, err := responseText(response); err != nil || got != "partial report" {
		t.Fatalf("complete response = %q, %v", got, err)
	}
}
