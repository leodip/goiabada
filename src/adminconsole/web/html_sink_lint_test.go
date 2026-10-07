package web

import (
	"testing"

	"github.com/leodip/goiabada/core/guard"
)

// TestServedPages_HandNoDataToAnHTMLParser holds every page and script this server serves to the
// rule core/guard.AssertNoHTMLSinks carries with its reasoning (#120): no value reaches the document
// through an HTML or JavaScript parser. It covers what #105's check on the redirect URI and web
// origin cells held, both the write and the read side, on every page rather than two.
//
// htmlSinkAllowances is every site that still does it, named by file and line so it does not drift.
// None is safe by construction: each is kept from executing only by the auth server's input
// validators. #120 converts each one to text and removes its entry, and an entry left behind after
// its site is fixed fails this test. The dialog's own line is the one that stays, as the audited
// branch that renders a message built by the escaping markup builder.
func TestServedPages_HandNoDataToAnHTMLParser(t *testing.T) {
	guard.AssertNoHTMLSinks(t, htmlSinkAllowances, templateFS, staticFS)
}

var htmlSinkAllowances = []guard.HTMLSinkAllowance{
	{File: "static/utils.js", Text: `document.getElementById(id + "_modalDialogMessage").innerHTML = message;`},
	{File: "template/admin_clients_permissions.html", Text: `cell1.innerHTML = value.Scope;`},
	{File: "template/admin_clients_permissions.html", Text: `cell2.innerHTML = getTrashCanMarkup("", "deletePermission(event, this);", "data-permissionid='" + parseInt(key, 10) + "'");`},
	{File: "template/admin_clients_redirect_uris.html", Text: `cell2.innerHTML = getTrashCanMarkup("", "deleteRedirectURI(event, this);", "");`},
	{File: "template/admin_clients_web_origins.html", Text: `cell2.innerHTML = getTrashCanMarkup("", "deleteWebOrigin(event, this);", "");`},
	{File: "template/admin_groups_members_add.html", Text: `subjectCell.innerHTML = user.Subject;`},
	{File: "template/admin_groups_members_add.html", Text: `usernameCell.innerHTML = user.Username;`},
	{File: "template/admin_groups_members_add.html", Text: "emailCell.innerHTML = `<a href=\"/admin/users/${user.Id}/details\" class=\"link link-hover link-secondary\">${user.Email}</a>`;"},
	{File: "template/admin_groups_members_add.html", Text: `givenNameCell.innerHTML = user.GivenName;`},
	{File: "template/admin_groups_members_add.html", Text: `middleNameCell.innerHTML = user.MiddleName;`},
	{File: "template/admin_groups_members_add.html", Text: `familyNameCell.innerHTML = user.FamilyName;`},
	{File: "template/admin_groups_members_add.html", Text: `addToGroupButton.setAttribute("onclick", "AddUserToGroup(event, this, " + user.Id + ", '" + user.Email + "');");`},
	{File: "template/admin_groups_members_add.html", Text: `cell.innerHTML = "<span class='p-1 rounded text-warning-content bg-warning'>{{ T $.ctx "adminconsole.admin_groups.members_add.results_truncated_prefix" }}" + maxRows + "{{ T $.ctx "adminconsole.admin_groups.members_add.results_truncated_suffix" }}</span>";`},
	{File: "template/admin_groups_permissions.html", Text: `cell1.innerHTML = value.Scope;`},
	{File: "template/admin_groups_permissions.html", Text: `cell2.innerHTML = getTrashCanMarkup("", "deletePermission(event, this);", "data-permissionid='" + parseInt(key, 10) + "'");`},
	{File: "template/admin_resources_permissions.html", Text: `cell1.innerHTML = perm.permissionIdentifier;`},
	{File: "template/admin_resources_permissions.html", Text: `cell2.innerHTML = perm.description;`},
	{File: "template/admin_resources_permissions.html", Text: `cell3.innerHTML = getEditMarkup("", "editPermission(event, this);", "data-permissionid='" + perm.id + "'");`},
	{File: "template/admin_resources_permissions.html", Text: `cell4.innerHTML = getTrashCanMarkup("", "deletePermission(event, this);", "data-permissionid='" + perm.id + "'");`},
	{File: "template/admin_resources_users_with_permission_add.html", Text: `subjectCell.innerHTML = user.Subject;`},
	{File: "template/admin_resources_users_with_permission_add.html", Text: `usernameCell.innerHTML = user.Username;`},
	{File: "template/admin_resources_users_with_permission_add.html", Text: "emailCell.innerHTML = `<a href=\"/admin/users/${user.Id}/details\" class=\"link link-hover link-secondary\">${user.Email}</a>`;"},
	{File: "template/admin_resources_users_with_permission_add.html", Text: `givenNameCell.innerHTML = user.GivenName;`},
	{File: "template/admin_resources_users_with_permission_add.html", Text: `middleNameCell.innerHTML = user.MiddleName;`},
	{File: "template/admin_resources_users_with_permission_add.html", Text: `familyNameCell.innerHTML = user.FamilyName;`},
	{File: "template/admin_resources_users_with_permission_add.html", Text: `grantPermissionButton.setAttribute("onclick", "GrantPermission(event, this, " + user.Id + ", '" + user.Email + "');");`},
	{File: "template/admin_resources_users_with_permission_add.html", Text: `cell.innerHTML = "<span class='p-1 rounded text-warning-content bg-warning'>{{ T $.ctx "adminconsole.admin_resources.users_with_permission_add.results_truncated_prefix" }}" + maxRows + "{{ T $.ctx "adminconsole.admin_resources.users_with_permission_add.results_truncated_suffix" }}</span>";`},
	{File: "template/admin_settings_keys.html", Text: `viewPublicKeyDialogPEMContent.innerHTML = key.PublicKeyPEM;`},
	{File: "template/admin_settings_keys.html", Text: `viewPublicKeyDialogASN1DERContent.innerHTML = key.PublicKeyASN1DER;`},
	{File: "template/admin_settings_keys.html", Text: `viewPublicKeyDialogJWKContent.innerHTML = key.PublicKeyJWK;`},
	{File: "template/admin_users_groups.html", Text: `cell1.innerHTML = "<a class='link link-hover' href='/admin/groups/" + assignedGroup.id + "/settings'>" + assignedGroup.groupIdentifier + "</a>";`},
	{File: "template/admin_users_groups.html", Text: `cell2.innerHTML = getTrashCanMarkup("", "deleteGroupMembership(event, this);", "data-groupid='" + assignedGroup.id + "'");`},
	{File: "template/admin_users_permissions.html", Text: `cell1.innerHTML = value.Scope;`},
	{File: "template/admin_users_permissions.html", Text: `cell2.innerHTML = getTrashCanMarkup("", "deletePermission(event, this);", "data-permissionid='" + parseInt(key, 10) + "'");`},
}
