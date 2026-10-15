package authflow

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	datamocks "github.com/leodip/goiabada/authserver/internal/data/mocks"
	"github.com/leodip/goiabada/authserver/internal/record"
	"github.com/leodip/goiabada/core/logging/logtest"
)

// The client behind a ceremony, for the trust decision of an error response a step reaches without
// having loaded it: the client the identifier names, or nil, the untrusted case, when the lookup
// fails, which is logged at error and never answered as a 500 (#108).
func TestClientProvenance(t *testing.T) {
	t.Run("the client the identifier names", func(t *testing.T) {
		database := datamocks.NewDatabase(t)
		client := &record.Client{Id: 7, ClientIdentifier: "provenance-client"}
		ctx := context.Background()
		database.On("GetClientByClientIdentifier", ctx, mock.Anything, "provenance-client").Return(client, nil).Once()

		got := clientProvenance(ctx, database, "provenance-client")

		assert.Same(t, client, got)
	})

	t.Run("a failed load is unresolved provenance, logged at error", func(t *testing.T) {
		logged := logtest.CaptureSlog(t)
		database := datamocks.NewDatabase(t)
		ctx := context.Background()
		database.On("GetClientByClientIdentifier", ctx, mock.Anything, "provenance-client").Return(nil, assert.AnError).Once()

		got := clientProvenance(ctx, database, "provenance-client")

		assert.Nil(t, got)
		records := logged.Records()
		require.Len(t, records, 1)
		assert.Equal(t, "ERROR", records[0].Level.String())
		assert.Equal(t, "unable to load the client while answering it with an error, treating its provenance as unresolved",
			records[0].Message)
		assert.Equal(t, "provenance-client", records[0].Attrs["client_identifier"])
	})
}
