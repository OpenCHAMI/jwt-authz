package issuer

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

func TestIssuer_IssueTokenforAPIKey(t *testing.T) {
	is := &Issuer{
		IssuerURL: "https://example.com",
		SecretKey: "secret",
	}

	apiKey := APIKey{
		APIKeyID: "api-key-id",
	}

	username := "john.doe"
	tenant := "acme"
	region := "us-west"

	tokenString, err := is.IssueTokenforAPIKey(apiKey, username, tenant, region)

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(is.SecretKey), nil
	})

	assert.Equal(t, token.Claims.(jwt.MapClaims)["iss"].(string), is.IssuerURL)

	assert.Equal(t, token.Valid, true)
	assert.Equal(t, nil, err)
}
