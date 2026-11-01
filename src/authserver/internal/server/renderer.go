package server

import (
	"context"

	"github.com/leodip/goiabada/authserver/internal/legaldocuments"
	"github.com/leodip/goiabada/authserver/internal/render"
)

// newRenderer builds a renderer over the server's templates and static files that draws the legal
// footer on the sign-in pages' layouts. Every renderer the server builds comes from here, so no page
// of either layout is drawn without its footer (#622).
func (s *Server) newRenderer() *render.Renderer {
	reader := legaldocuments.NewReader(s.database)
	return render.New(s.templateFS, s.staticFS).WithLegalFooter(
		func(ctx context.Context, clientIdentifier string) ([]render.LegalDocumentLink, error) {
			inEffect, err := reader.ForClient(ctx, clientIdentifier)
			if err != nil {
				return nil, err
			}
			links := make([]render.LegalDocumentLink, len(inEffect))
			for i, d := range inEffect {
				links[i] = render.LegalDocumentLink{Title: d.Current.Title, ShortName: d.Document.ShortName}
			}
			return links, nil
		})
}
