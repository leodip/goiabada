package render

import (
	"strings"
	"testing"

	"github.com/leodip/goiabada/core/api"
	"github.com/stretchr/testify/assert"
)

func TestShorten_CutsPastTheBoundWithAnEllipsis(t *testing.T) {
	assert.Equal(t, "Order management API", Shorten("  Order management API ", 50), "a short text is kept whole")
	assert.Equal(t, strings.Repeat("a", 50), Shorten(strings.Repeat("a", 50), 50), "a text at the bound is kept whole")
	assert.Equal(t, strings.Repeat("a", 49)+"…", Shorten(strings.Repeat("a", 51), 50))
	assert.Equal(t, "Internal reporting, dashboards and scheduled…",
		Shorten("Internal reporting, dashboards and scheduled exports", 46), "no space is left before the ellipsis")
	assert.Equal(t, "Relatórios internos, painéis e exportações agend…",
		Shorten("Relatórios internos, painéis e exportações agendadas", 49), "characters are counted, not bytes")
}

func TestResourceChoices_LabelEachWithItsShortenedDescription(t *testing.T) {
	choices := ResourceChoices([]api.ResourceResponse{
		{ID: 1, ResourceIdentifier: "orders-api", Description: "Order management API"},
		{ID: 2, ResourceIdentifier: "reporting", Description: "Internal reporting, dashboards and scheduled exports for finance"},
		{ID: 3, ResourceIdentifier: "bare"},
	})

	assert.Equal(t, []Choice{
		{ID: 1, Identifier: "orders-api", Label: "orders-api – Order management API", Description: "Order management API"},
		{ID: 2, Identifier: "reporting", Label: "reporting – Internal reporting, dashboards and scheduled expo…",
			Description: "Internal reporting, dashboards and scheduled exports for finance"},
		{ID: 3, Identifier: "bare", Label: "bare"},
	}, choices)
}

func TestGroupChoices_LabelEachWithItsShortenedDescription(t *testing.T) {
	choices := GroupChoices([]api.GroupResponse{
		{ID: 4, GroupIdentifier: "finance", Description: " Finance team "},
		{ID: 5, GroupIdentifier: "bare"},
	})

	assert.Equal(t, []Choice{
		{ID: 4, Identifier: "finance", Label: "finance – Finance team", Description: "Finance team"},
		{ID: 5, Identifier: "bare", Label: "bare"},
	}, choices)
}

func TestPermissionChoices_NameEachByItsPermissionIdentifier(t *testing.T) {
	choices := PermissionChoices([]api.PermissionResponse{
		{ID: 6, PermissionIdentifier: "read", Description: "Read orders", Resource: api.ResourceResponse{ResourceIdentifier: "orders-api"}},
		{ID: 7, PermissionIdentifier: "write"},
	})

	assert.Equal(t, []Choice{
		{ID: 6, Identifier: "read", Label: "read – Read orders", Description: "Read orders"},
		{ID: 7, Identifier: "write", Label: "write"},
	}, choices)
}
