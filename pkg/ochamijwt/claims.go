package ochamijwt

import (
	"github.com/golang-jwt/jwt/v5"
)

// OchamiClaims defines the way Ochami JWTs are structured.
// It includes and extends the Registered JWT claims from https://datatracker.ietf.org/doc/html/rfc7519#section-4.1

type OchamiClaims struct {
	jwt.RegisteredClaims
	/*
		// the `iss` (Issuer) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.1
		// In Ochami, there should be one Issuer per authentication domain.  It is permissable to have multiple tenants share an issuer.  The subject must be unique within an issuer.
		Issuer string `json:"iss,omitempty"`

		// the `sub` (Subject) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.2
		// In Ochami, the subject for user authorization should be an API Key and unique within the issuer.  It is an opaque identifier.
		Subject string `json:"sub,omitempty"`

		// the `aud` (Audience) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3
		// In Ochami, the audience claim is used to indicate which microservices will consider the token valid.
		Audience jwt.ClaimStrings `json:"aud,omitempty"`

		// the `exp` (Expiration Time) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.4
		ExpiresAt *jwt.NumericDate `json:"exp,omitempty"`

		// the `nbf` (Not Before) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.5
		NotBefore *jwt.NumericDate `json:"nbf,omitempty"`

		// the `iat` (Issued At) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.6
		IssuedAt *jwt.NumericDate `json:"iat,omitempty"`

		// the `jti` (JWT ID) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.7
		ID string `json:"jti,omitempty"`
	*/
	// The following claims are specific to Ochami

	// Username is the username of the user who is authorized by this token.
	Username string `json:"username"`
	// Tenant is the opaque identifier that describes which tenant actions should consider this token valid.
	Tenant string `json:"tenant"`
	// Region is the opaque identifier that describes which region actions should consider this token valid.
	Region string `json:"region"`
}

// GetIssuer returns the issuer of the token.
func (c OchamiClaims) GetIssuer() (string, error) {
	return c.RegisteredClaims.GetIssuer()
}

// GetSubject returns the subject of the token.
func (c OchamiClaims) GetSubject() (string, error) {
	return c.RegisteredClaims.GetSubject()
}

// GetAudience returns the audience of the token.
func (c OchamiClaims) GetAudience() (jwt.ClaimStrings, error) {
	return c.RegisteredClaims.GetAudience()
}

// GetExpirationTime returns the expiration time of the token.
func (c OchamiClaims) GetExpirationTime() (*jwt.NumericDate, error) {
	return c.RegisteredClaims.GetExpirationTime()
}

// GetNotBefore returns the not before time of the token.
func (c OchamiClaims) GetNotBefore() (*jwt.NumericDate, error) {
	return c.RegisteredClaims.GetNotBefore()
}

// GetIssuedAt returns the issued at time of the token.
func (c OchamiClaims) GetIssuedAt() (*jwt.NumericDate, error) {
	return c.RegisteredClaims.GetIssuedAt()
}

// GetTenant returns the opaque identifier that describes which tenant actions should consider this token valid.
func (c OchamiClaims) GetTenant() string {
	return c.Tenant
}

// GetRegion returns the opaque identifier that describes which region actions should consider this token valid.
func (c OchamiClaims) GetRegion() string {
	return c.Region
}

// GetUsernmae returns the username of the user who is authorized by this token.
func (c OchamiClaims) GetUsername() (string, error) {
	return c.Username, nil
}
