// Package web embeds the auth server's templates, static files and OpenAPI document, and serves the
// first two as an fs.FS rooted at its own directory, through TemplateFS and StaticFS, and the third
// as bytes, through OpenAPISpec. It runs at startup, before any request, and is one of the few
// places a plain slog record is admitted (#320).
package web
