package issuer

import "fmt"

type APIKey struct {
	APIKeyID  string `json:"key-id"`
	APISecret string `json:"secret"`
	Roles     []Role `json:"roles"`
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

func (apikey APIKey) String() string {
	return fmt.Sprintf(apikey.APIKeyID)
}

type Role struct {
	RoleID      string   `json:"id"`
	Description string   `json:"desc"`
	Permissions []string `json:"perms"`
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

func (role *Role) String() string {
	return fmt.Sprintf(role.RoleID, role.Description)
}
