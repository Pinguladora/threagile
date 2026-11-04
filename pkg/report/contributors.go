package report

import (
	"strings"

	"github.com/Pinguladora/threagile/pkg/types"
)

// contributorsLine lists the contributors of the model besides its author, as
// "Contributors: name (contact), ...", or returns "" when there are none.
// Contributors without a name are skipped.
func contributorsLine(model *types.Model) string {
	names := make([]string, 0, len(model.Contributors))
	for _, contributor := range model.Contributors {
		if contributor == nil || strings.TrimSpace(contributor.Name) == "" {
			continue
		}

		name := strings.TrimSpace(contributor.Name)
		if contact := strings.TrimSpace(contributor.Contact); contact != "" {
			name += " (" + contact + ")"
		}
		names = append(names, name)
	}

	if len(names) == 0 {
		return ""
	}

	return "Contributors: " + strings.Join(names, ", ")
}
