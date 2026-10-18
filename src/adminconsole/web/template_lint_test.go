package web

import (
	"testing"

	"github.com/leodip/goiabada/core/guard"
)

// The three rules below run in both servers and live once, in core/guard/template_lint.go, which
// carries each one's reasoning and the shared walk (#333). What stays here is this module's own
// evidence for them and the FS they are held against: templateFS, the //go:embed set this binary
// renders from. #105's check on the redirect URI and web origin cells was here too, until #120's
// html_sink_lint_test.go took over what it held, on every page.

// TestTemplates_NoHTMLInTitle guards the admin_users_* bug: markup in the {{define "title"}} block
// renders literally in the browser tab.
func TestTemplates_NoHTMLInTitle(t *testing.T) {
	guard.AssertTemplatesNoHTMLInTitle(t, templateFS, "template")
}

// TestTemplates_NoCsrfField guards the half of the CSRF token deletion that nothing else in this
// module observes. Measured here rather than assumed: restoring {{ .csrfField }} to
// account_phone.html, which TestRender_AccountPhone and TestRender_JSBootstrapNoKeyLeak both render
// from a bind map that no longer carries it, left the whole adminconsole tier green. The bind side
// of the same deletion is guarded by internal/handlers/csrf_lint_test.go, which draws the same
// lexical boundary.
func TestTemplates_NoCsrfField(t *testing.T) {
	guard.AssertTemplatesNoCsrfField(t, templateFS, "template")
}

// TestTemplates_HtmlLangNotHardcoded guards the <html lang="en"> bug: page layouts must render the
// lang attribute from the active locale. This module's email layouts are exempt, being per-locale
// sibling files.
func TestTemplates_HtmlLangNotHardcoded(t *testing.T) {
	guard.AssertTemplatesHtmlLangNotHardcoded(t, templateFS, "template")
}

// TestTemplates_AreWellFormed holds this server's pages to well-formed HTML and to the
// accessibility rules a template can be held to unrendered, through
// core/guard.AssertWellFormedTemplates, which carries each rule and its reasoning (#617). Each page
// is read as served, in the layouts the handlers under ../internal render it in.
func TestTemplates_AreWellFormed(t *testing.T) {
	guard.AssertWellFormedTemplates(t, templateFS, "template", "../internal", emailTemplates, pendingTemplates)
}

// emailTemplates are not pages: no rule reads them.
var emailTemplates = []string{"layouts/email_layout.html"}

// pendingTemplates are the pages not yet brought under the rules (#617). The guard reports one that
// meets them all, so the list only shrinks, page by page, to nothing.
var pendingTemplates = []string{
	"account_address.html", "account_change_password.html", "account_email.html",
	"account_email_verification.html", "account_logout_form_post.html",
	"account_manage_consents.html", "account_otp.html", "account_phone.html", "account_picture.html",
	"account_profile.html", "account_user_sessions.html", "admin_clients.html",
	"admin_clients_authentication.html", "admin_clients_delete.html", "admin_clients_logo.html",
	"admin_clients_new.html", "admin_clients_oauth2_flows.html", "admin_clients_permissions.html",
	"admin_clients_redirect_uris.html", "admin_clients_settings.html", "admin_clients_tokens.html",
	"admin_clients_usersessions.html", "admin_clients_web_origins.html", "admin_groups.html",
	"admin_groups_attributes.html", "admin_groups_attributes_add.html",
	"admin_groups_attributes_edit.html", "admin_groups_delete.html", "admin_groups_members.html",
	"admin_groups_members_add.html", "admin_groups_new.html", "admin_groups_permissions.html",
	"admin_groups_settings.html", "admin_resources.html", "admin_resources_delete.html",
	"admin_resources_groups_with_permission.html", "admin_resources_new.html",
	"admin_resources_permissions.html", "admin_resources_settings.html",
	"admin_resources_users_with_permission.html", "admin_resources_users_with_permission_add.html",
	"admin_settings_audit_log_viewer.html", "admin_settings_audit_logs.html",
	"admin_settings_email.html", "admin_settings_email_sendtest.html", "admin_settings_general.html",
	"admin_settings_keys.html", "admin_settings_tokens.html", "admin_users_address.html",
	"admin_users_attributes.html", "admin_users_attributes_add.html",
	"admin_users_attributes_edit.html", "admin_users_authentication.html",
	"admin_users_consents.html", "admin_users_delete.html", "admin_users_details.html",
	"admin_users_email.html", "admin_users_groups.html", "admin_users_new.html",
	"admin_users_permissions.html", "admin_users_phone.html", "admin_users_picture.html",
	"admin_users_profile.html", "admin_users_sessions.html", "error.html", "index.html",
	"not_found.html", "unauthorized.html",
}
