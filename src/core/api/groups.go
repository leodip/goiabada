package api

import (
	"time"
)

type GroupResponse struct {
	Id                   int64      `json:"id"`
	CreatedAt            *time.Time `json:"createdAt"`
	UpdatedAt            *time.Time `json:"updatedAt"`
	GroupIdentifier      string     `json:"groupIdentifier"`
	Description          string     `json:"description"`
	IncludeInIdToken     bool       `json:"includeInIdToken"`
	IncludeInAccessToken bool       `json:"includeInAccessToken"`
	MemberCount          int        `json:"memberCount"`
}

type GetGroupsResponse struct {
	Groups []GroupResponse `json:"groups"`
}

type CreateGroupRequest struct {
	GroupIdentifier      string `json:"groupIdentifier"`
	Description          string `json:"description"`
	IncludeInIdToken     bool   `json:"includeInIdToken"`
	IncludeInAccessToken bool   `json:"includeInAccessToken"`
}

type CreateGroupResponse struct {
	Group GroupResponse `json:"group"`
}

type GetGroupResponse struct {
	Group GroupResponse `json:"group"`
}

type UpdateGroupRequest struct {
	GroupIdentifier      string `json:"groupIdentifier"`
	Description          string `json:"description"`
	IncludeInIdToken     bool   `json:"includeInIdToken"`
	IncludeInAccessToken bool   `json:"includeInAccessToken"`
}

type UpdateGroupResponse struct {
	Group GroupResponse `json:"group"`
}

type AddGroupMemberRequest struct {
	UserId int64 `json:"userId"`
}

type GetGroupMembersResponse struct {
	Members []UserResponse `json:"members"`
	Total   int            `json:"total"`
	Page    int            `json:"page"`
	Size    int            `json:"size"`
}

type GroupAttributeResponse struct {
	Id                   int64      `json:"id"`
	CreatedAt            *time.Time `json:"createdAt"`
	UpdatedAt            *time.Time `json:"updatedAt"`
	Key                  string     `json:"key"`
	Value                string     `json:"value"`
	IncludeInIdToken     bool       `json:"includeInIdToken"`
	IncludeInAccessToken bool       `json:"includeInAccessToken"`
	GroupId              int64      `json:"groupId"`
}

type GetGroupAttributesResponse struct {
	Attributes []GroupAttributeResponse `json:"attributes"`
}

type GetGroupAttributeResponse struct {
	Attribute GroupAttributeResponse `json:"attribute"`
}

type CreateGroupAttributeRequest struct {
	Key                  string `json:"key"`
	Value                string `json:"value"`
	IncludeInIdToken     bool   `json:"includeInIdToken"`
	IncludeInAccessToken bool   `json:"includeInAccessToken"`
	GroupId              int64  `json:"groupId"`
}

type CreateGroupAttributeResponse struct {
	Attribute GroupAttributeResponse `json:"attribute"`
}

type UpdateGroupAttributeRequest struct {
	Key                  string `json:"key"`
	Value                string `json:"value"`
	IncludeInIdToken     bool   `json:"includeInIdToken"`
	IncludeInAccessToken bool   `json:"includeInAccessToken"`
}

type UpdateGroupAttributeResponse struct {
	Attribute GroupAttributeResponse `json:"attribute"`
}

// UpdateGroupPermissionsRequest replaces the whole set of permissions granted to a group.
// ExpectedPermissionIds is as on UpdateUserPermissionsRequest (#428).
type UpdateGroupPermissionsRequest struct {
	PermissionIds         []int64 `json:"permissionIds"`
	ExpectedPermissionIds []int64 `json:"expectedPermissionIds"`
}

type GetGroupPermissionsResponse struct {
	Group       GroupResponse        `json:"group"`
	Permissions []PermissionResponse `json:"permissions"`
}

// GroupWithPermissionResponse embeds group info and indicates whether
// the group has a specific permission (used for annotated group search).
type GroupWithPermissionResponse struct {
	GroupResponse
	HasPermission bool `json:"hasPermission"`
}

// SearchGroupsWithPermissionAnnotationResponse returns paginated groups
// annotated with whether they have a specific permission assigned.
type SearchGroupsWithPermissionAnnotationResponse struct {
	Groups []GroupWithPermissionResponse `json:"groups"`
	Total  int                           `json:"total"`
	Page   int                           `json:"page"`
	Size   int                           `json:"size"`
}
