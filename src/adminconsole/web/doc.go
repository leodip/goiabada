// Package web embeds the admin console's templates and static files, and serves each as an
// fs.FS rooted at its own directory, through TemplateFS and StaticFS. It runs at startup, before
// any request, and is one of the few places a plain slog record is admitted (#320).
package web
