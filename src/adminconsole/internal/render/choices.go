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

// Choice is an entry as a list to choose one from shows it: its identifier, with its description
// shortened beside it in the label, and whole for the field to show once it is chosen.
type Choice struct {
	Id          int64
	Identifier  string
	Label       string
	Description string
}

func choiceOf(id int64, identifier, description string) Choice {
	label := identifier
	description = strings.TrimSpace(description)
	if description != "" {
		label += " – " + Shorten(description, choiceDescriptionMax)
	}
	return Choice{Id: id, Identifier: identifier, Label: label, Description: description}
}

// ResourceChoices maps resources to the choices a list shows, in their order.
func ResourceChoices(resources []api.ResourceResponse) []Choice {
	choices := make([]Choice, 0, len(resources))
	for _, r := range resources {
		choices = append(choices, choiceOf(r.Id, r.ResourceIdentifier, r.Description))
	}
	return choices
}

// GroupChoices maps groups to the choices a list shows, in their order.
func GroupChoices(groups []api.GroupResponse) []Choice {
	choices := make([]Choice, 0, len(groups))
	for _, g := range groups {
		choices = append(choices, choiceOf(g.Id, g.GroupIdentifier, g.Description))
	}
	return choices
}

// PermissionChoices maps one resource's permissions to the choices a list shows, in their order,
// each named by its permission identifier alone.
func PermissionChoices(permissions []api.PermissionResponse) []Choice {
	choices := make([]Choice, 0, len(permissions))
	for _, p := range permissions {
		choices = append(choices, choiceOf(p.Id, p.PermissionIdentifier, p.Description))
	}
	return choices
}
