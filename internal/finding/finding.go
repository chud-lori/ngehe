// Package finding holds the shared Finding type produced by every detector.
package finding

type Severity string

const (
	SevCritical Severity = "critical"
	SevHigh     Severity = "high"
	SevMedium   Severity = "medium"
	SevLow      Severity = "low"
	SevInfo     Severity = "info"
)

type Finding struct {
	Rule           string   `json:"rule"`
	Severity       Severity `json:"severity"`
	Method         string   `json:"method"`
	URL            string   `json:"url"`
	Path           string   `json:"path"`
	BaselineStatus int      `json:"baseline_status,omitempty"`
	OffenderName   string   `json:"offender_session,omitempty"`
	OffenderStatus int      `json:"offender_status,omitempty"`
	BodySimilar    float64  `json:"body_similarity,omitempty"`
	Param          string   `json:"param,omitempty"`
	Payload        string   `json:"payload,omitempty"`
	Evidence       string   `json:"evidence,omitempty"`
	Why            string   `json:"why"`
	Next           string   `json:"next,omitempty"` // exploit-chain hint, populated from playbook
}

func SevRank(s Severity) int {
	switch s {
	case SevCritical:
		return 0
	case SevHigh:
		return 1
	case SevMedium:
		return 2
	case SevLow:
		return 3
	default:
		return 4
	}
}
