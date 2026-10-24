package core

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strings"
	"time"

	"waf-rule-evaluations/internal/attacks"
)

const DailyBudgetMicroUSD int64 = 3_000_000
const MaxSnapshotBytes = 1 << 20
const MaxTrafficLogBytes = 50 << 20

var ErrBudgetExceeded = errors.New("daily Bedrock budget exceeded")
var safeID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

// Job is written by the authenticated web tier to a private S3 object.
// The worker never accepts a model ID, price, or token limit from this object.
type Job struct {
	ID               string   `json:"id"`
	UserID           string   `json:"user_id"`
	Kind             string   `json:"kind"` // aws_waf, modsecurity, or traffic_log
	LogFormat        string   `json:"log_format,omitempty"`
	LogObjectKey     string   `json:"log_object_key,omitempty"`
	Language         string   `json:"language,omitempty"` // ja or en; empty means ja for old jobs
	Snapshot         string   `json:"snapshot"`
	AttackCategories []string `json:"attack_categories"`
	ProbeResultKey   string   `json:"probe_result_key,omitempty"`
}

func (j Job) Validate() error {
	if !safeID.MatchString(j.ID) || !safeID.MatchString(j.UserID) {
		return errors.New("job id and user id must be 1-128 ASCII letters, digits, hyphens, or underscores")
	}
	if j.Kind != "aws_waf" && j.Kind != "modsecurity" && j.Kind != "traffic_log" {
		return errors.New("unsupported kind")
	}
	if j.Language != "" && j.Language != "ja" && j.Language != "en" {
		return errors.New("language must be ja or en")
	}
	if j.Kind == "traffic_log" {
		if j.LogFormat != "cloudfront" && j.LogFormat != "alb" && j.LogFormat != "combined" {
			return errors.New("unsupported log format")
		}
		if j.LogObjectKey != "" {
			if j.LogObjectKey != "jobs/data/"+j.ID+".log" || j.Snapshot != "" {
				return errors.New("invalid traffic log object reference")
			}
		} else if strings.TrimSpace(j.Snapshot) == "" || len(j.Snapshot) > MaxSnapshotBytes {
			return errors.New("inline traffic log must be nonempty and at most 1 MiB")
		}
		if len(j.AttackCategories) != 0 {
			return errors.New("traffic log jobs cannot select attack categories")
		}
	} else {
		if j.LogFormat != "" || j.LogObjectKey != "" {
			return errors.New("log fields are only allowed for traffic logs")
		}
		if strings.TrimSpace(j.Snapshot) == "" || len(j.Snapshot) > MaxSnapshotBytes {
			return errors.New("snapshot must be nonempty and at most 1 MiB")
		}
		if err := attacks.ValidateSelection(j.AttackCategories); err != nil {
			return err
		}
	}
	if j.ProbeResultKey != "" {
		if j.Kind != "modsecurity" || j.ProbeResultKey != "probe-results/"+j.ID+".json" {
			return errors.New("probe_result_key is only allowed for ModSecurity and must match the job id")
		}
	}
	return nil
}

func (j Job) SnapshotHash() string {
	categories, _ := json.Marshal(j.AttackCategories)
	identity := j.Kind + "\n" + j.LogFormat + "\n" + j.Snapshot + "\n" + string(categories) + "\n" + j.ReportLanguage()
	if j.LogObjectKey != "" {
		identity += "\n" + j.LogObjectKey
	}
	sum := sha256.Sum256([]byte(identity))
	return hex.EncodeToString(sum[:])
}

func (j Job) ReportLanguage() string {
	if j.Language == "en" {
		return "en"
	}
	return "ja"
}

func JSTDay(t time.Time) string {
	return t.In(time.FixedZone("JST", 9*60*60)).Format("2006-01-02")
}

// PriceMicroUSDPerMillion is the current model price in millionths of a USD
// per million tokens. For example, USD 0.80/M tokens is 800000.
// The rates are mandatory deployment configuration, not caller input.
func WorstCaseMicroUSD(inputTokens, maxOutputTokens int32, inputRate, outputRate int64) (int64, error) {
	if inputTokens <= 0 || maxOutputTokens <= 0 || inputRate <= 0 || outputRate <= 0 {
		return 0, errors.New("positive token counts and price rates are required")
	}
	if inputRate > 1_000_000_000_000 || outputRate > 1_000_000_000_000 {
		return 0, errors.New("price rate out of range")
	}
	in, err := ceilMulDiv(int64(inputTokens), inputRate, 1_000_000)
	if err != nil {
		return 0, err
	}
	out, err := ceilMulDiv(int64(maxOutputTokens), outputRate, 1_000_000)
	if err != nil || in > math.MaxInt64-out {
		return 0, errors.New("cost overflow")
	}
	return in + out, nil
}

func ceilMulDiv(a, b, divisor int64) (int64, error) {
	if a > (math.MaxInt64-(divisor-1))/b {
		return 0, fmt.Errorf("cost overflow")
	}
	return (a*b + divisor - 1) / divisor, nil
}
