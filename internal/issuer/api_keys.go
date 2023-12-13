package issuer

type APIKey struct {
	APIKeyID  string
	APISecret string
	Roles     []Role
}

func NewAPIKey(roles []Role) APIKey {
	return APIKey{
		APIKeyID:  GenerateRandomStringURLSafe(64),
		APISecret: GenerateRandomStringURLSafe(64),
		Roles:     roles,
	}
}

func (apikey *APIKey) GetRoles() []Role {
	return apikey.Roles
}

func (apikey *APIKey) GetAPIKeyID() string {
	return apikey.APIKeyID
}

func (apikey *APIKey) GetAPISecret() string {
	return apikey.APISecret
}

func (apikey *APIKey) AddRole(role Role) {
	apikey.Roles = append(apikey.Roles, role)
}

type Role struct {
	RoleID      string
	Description string
	Permissions []string
}

func (role *Role) GetRoleID() string {
	return role.RoleID
}

func (role *Role) GetDescription() string {
	return role.Description
}

func (role *Role) GetPermissions() []string {
	return role.Permissions
}

func (role *Role) AddPermission(permission string) {
	role.Permissions = append(role.Permissions, permission)
}
