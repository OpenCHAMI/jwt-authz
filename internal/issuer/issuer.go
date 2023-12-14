package issuer

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/openchami/jwt-authz/pkg/ochamijwt"
)

type Issuer struct {
	IssuerURL string
	SecretKey string
}

func (is *Issuer) IssueTokenforAPIKey(apiKey APIKey, username string, tenant string, region string) (string, error) {
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
	// TODO: Switch this to use RSA signatures based on the functions in key_manager.go
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString([]byte(is.SecretKey))

	if err != nil {
		return "", err
	}
	if len(tokenString) > 4096 {
		return "", errors.New("Token is too large.  Please reduce the size of the claims.")
	}

	return tokenString, nil

}

func (is *Issuer) VerifyTokenforAPIKey(tokenString string, apiKey APIKey) error {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(is.SecretKey), nil
	})

	if err != nil {
		return err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		if claims["sub"] == apiKey.APIKeyID {
			return nil
		}
	}

	return errors.New("Invalid token")
}

func (is *Issuer) ParseTokenWithClaims(tokenString string) (jwt.Claims, error) {
	return parseToken(tokenString, is.SecretKey)
}

func parseToken(tokenString string, secretKey string) (ochamijwt.OchamiClaims, error) {
	var claims ochamijwt.OchamiClaims
	token, err := jwt.ParseWithClaims(tokenString, &claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(secretKey), nil
	})

	if err != nil {
		return ochamijwt.OchamiClaims{}, err
	}

	if _, ok := token.Claims.(ochamijwt.OchamiClaims); ok && token.Valid {
		return claims, nil
	}

	return ochamijwt.OchamiClaims{}, errors.New("Invalid token")
}
