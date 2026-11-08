package render

import (
	"fmt"
	"strings"

	"github.com/opensecurity-dev/security-docs-spec/spec"
)

// ExportName is the file name the machine-readable copy is written under,
// and the name the Markdown index links to.
const ExportName = "security-docs.json"

// ExportJSON returns the machine-readable copy of what Render publishes for
// the same audience: the set filtered by ForAudience, as JSON. Publishing
// both from one filtered view keeps the human-readable and machine-readable
// forms consistent, as FedRAMP's certification data sharing rules ask.
//
// Unless draft is set, it refuses a set that still has unassessed claims,
// because Render leaves those out and the two forms would differ.
func ExportJSON(set *spec.DocumentSet, audience spec.Visibility, draft bool) ([]byte, error) {
	if audience == "" {
		audience = spec.VisibilityPublic
	}
	view, err := set.ForAudience(audience)
	if err != nil {
		return nil, err
	}
	if !draft {
		if paths := unassessed(view); len(paths) > 0 {
			more := ""
			if len(paths) > 3 {
				more = fmt.Sprintf(" and %d more", len(paths)-3)
				paths = paths[:3]
			}
			return nil, fmt.Errorf("render: %s has unassessed claims (%s%s); assess them or export a draft",
				audience, strings.Join(paths, ", "), more)
		}
	}
	view.Schema = ""
	return spec.Marshal(view)
}

// unassessed lists the JSON paths of claims with status todo or no status.
func unassessed(set *spec.DocumentSet) []string {
	var out []string
	set.WalkClaims(func(path string, c *spec.Claim) {
		if c.Status == "" || c.Status == spec.StatusTodo {
			out = append(out, path)
		}
	})
	return out
}
