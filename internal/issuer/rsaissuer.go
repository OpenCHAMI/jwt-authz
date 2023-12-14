package issuer

import (
	"crypto/rsa"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/openchami/jwt-authz/pkg/ochamijwt"
)

type RSAIssuer struct {
	IssuerURL string
	RSAKey    *rsa.PrivateKey
}

func (is *RSAIssuer) IssueTokenforAPIKey(apiKey APIKey, username string, tenant string, region string) (string, error) {
	claims := ochamijwt.OchamiClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    is.IssuerURL,
			Subject:   apiKey.APIKeyID,
			Audience:  []string{"bss", "api", "test"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			NotBefore: jwt.NewNumericDate(time.Now()),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ID:        uuid.NewString(),
		},
		Username: username,
		Tenant:   tenant,
		Region:   region,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	tokenString, err := token.SignedString(is.RSAKey)

	if err != nil {
		return "", err
	}
	if len(tokenString) > 4096 {
		return "", errors.New("Token is too large.  Please reduce the size of the claims.")
	}

	return tokenString, nil

}
