package render

import (
	"strings"
	"unicode"

	"github.com/leodip/goiabada/core/api"
)

// choiceDescriptionMax is the longest description a choice in a list carries whole. A longer one is
// cut, since one long description would widen the whole list, and the field shows the chosen
// entry's description whole beneath it.
const choiceDescriptionMax = 50

// Shorten answers text cut to at most limit characters, an ellipsis standing for what was cut. The
// script that builds a list of permissions shortens the same way, in permission-list.js.
func Shorten(text string, limit int) string {
	runes := []rune(strings.TrimSpace(text))
	if len(runes) <= limit {
		return string(runes)
	}
	return strings.TrimRightFunc(string(runes[:limit-1]), unicode.IsSpace) + "…"
}

// ResourceChoice is a resource as a list to choose one from shows it: its identifier, with its
// description shortened beside it in the label, and whole for the field to show once it is chosen.
type ResourceChoice struct {
	Id                 int64
	ResourceIdentifier string
	Label              string
	Description        string
}

// ResourceChoices maps resources to the choices a list shows, in their order.
func ResourceChoices(resources []api.ResourceResponse) []ResourceChoice {
	choices := make([]ResourceChoice, 0, len(resources))
	for _, r := range resources {
		label := r.ResourceIdentifier
		if d := strings.TrimSpace(r.Description); d != "" {
			label += " – " + Shorten(d, choiceDescriptionMax)
		}
		choices = append(choices, ResourceChoice{Id: r.Id, ResourceIdentifier: r.ResourceIdentifier,
			Label: label, Description: strings.TrimSpace(r.Description)})
	}
	return choices
}
