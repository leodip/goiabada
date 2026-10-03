package api

type ResourceResponse struct {
	Id                 int64  `json:"id"`
	ResourceIdentifier string `json:"resourceIdentifier"`
	Description        string `json:"description"`
	// IsSystemLevelResource travels because the API enforces it and a consumer has to mirror it:
	// the resource handlers refuse a rename and a delete on a system-level resource, and the admin
	// console disables those controls to match. It is on the wire rather than recomputed by each
	// consumer, the way IsSystemLevelClient already is, because a local copy of the rule can
	// disagree with the server's and offer a control the API then answers 403 to (#350).
	IsSystemLevelResource bool `json:"isSystemLevelResource"`
}

type GetResourcesResponse struct {
	Resources []ResourceResponse `json:"resources"`
}

// CreateResourceRequest is used to create a new resource via the admin API.
// Validation (required fields, identifier format, uniqueness, description length)
// is performed by the authserver.
type CreateResourceRequest struct {
	ResourceIdentifier string `json:"resourceIdentifier"`
	Description        string `json:"description"`
}

type CreateResourceResponse struct {
	Resource ResourceResponse `json:"resource"`
}

// GetResourceResponse returns the details of a single resource
type GetResourceResponse struct {
	Resource ResourceResponse `json:"resource"`
}

// UpdateResourceRequest is used to update an existing resource via the admin API.
// Validation (required fields, identifier format, uniqueness, description length)
// is performed by the authserver.
type UpdateResourceRequest struct {
	ResourceIdentifier string `json:"resourceIdentifier"`
	Description        string `json:"description"`
}

// UpdateResourceResponse returns the updated resource
type UpdateResourceResponse struct {
	Resource ResourceResponse `json:"resource"`
}

type PermissionResponse struct {
	Id                   int64            `json:"id"`
	PermissionIdentifier string           `json:"permissionIdentifier"`
	Description          string           `json:"description"`
	ResourceId           int64            `json:"resourceId"`
	Resource             ResourceResponse `json:"resource"`
}

type GetPermissionsByResourceResponse struct {
	Permissions []PermissionResponse `json:"permissions"`
}

// UpdateResourcePermissionsRequest replaces the set of permission definitions
// for a resource. The auth server validates, sanitizes, applies create/update/delete,
// and audits.
//
// ExpectedPermissions is the resource's permissions as the caller last read them, each entry's id,
// identifier and description as stored, required and compared as ExpectedPermissionIds is on
// UpdateUserPermissionsRequest: absent or null is refused, [] means the caller read none, and a
// stored list that differs answers 409 CONCURRENT_UPDATE (#428).
type UpdateResourcePermissionsRequest struct {
	Permissions         []ResourcePermissionUpsert `json:"permissions"`
	ExpectedPermissions []ResourcePermissionUpsert `json:"expectedPermissions"`
}

// ResourcePermissionUpsert represents a permission to create or update.
// If Id <= 0 or omitted, a new permission is created.
type ResourcePermissionUpsert struct {
	Id                   int64  `json:"id,omitempty"`
	PermissionIdentifier string `json:"permissionIdentifier"`
	Description          string `json:"description"`
}

// GetUsersByPermissionResponse returns users that have a given permission
// with pagination metadata.
type GetUsersByPermissionResponse struct {
	Users []UserResponse `json:"users"`
	Total int            `json:"total"`
	Page  int            `json:"page"`
	Size  int            `json:"size"`
}
