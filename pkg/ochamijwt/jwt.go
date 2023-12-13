package ochamijwt

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// TokenFactory holds the reusable parts of issuing tokens.
type TokenFactory struct {
	IssuerSecret []byte

	// the 'iss' (Issuer) claim https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.1
	// For OpenCHAMI, we have one JWT issuer per orchestration system
	Issuer string `json:"iss,omitempty"`

	// the `sub` (Subject) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.2
	// For OpenCHAMI, we have one JWT subject API Key.
	Subject string `json:"sub,omitempty"`

	// the `aud` (Audience) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3
	// For OpenCHAMI, we use the audience claim to indicate which microservices will consider the token valid.
	// This isn't particularly elegant and we may need to rethink it.
	Audience jwt.ClaimStrings `json:"aud,omitempty"`
}

func (tf *TokenFactory) NewSignedTokenWithClaims(claims OchamiClaims) string {
	// A usual scenario is to set the expiration time relative to the current time
	claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(24 * time.Hour))
	claims.IssuedAt = jwt.NewNumericDate(time.Now())
	claims.NotBefore = jwt.NewNumericDate(time.Now())
	claims.Issuer = tf.Issuer
	claims.ID = uuid.NewString()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString(tf.IssuerSecret)

	return tokenString
}

func NewTokenFactory(secretKey string, issuer string, subject string) TokenFactory {
	tf := TokenFactory{
		Issuer:       issuer,
		IssuerSecret: []byte(secretKey),
		Subject:      subject,
	}

	return tf
}

func NewClaims(username string, tenantId string, region string) OchamiClaims {
	claims := OchamiClaims{
		Username: username,
		Tenant:   tenantId,
	}

	// A usual scenario is to set the expiration time relative to the current time
	claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(24 * time.Hour))
	claims.IssuedAt = jwt.NewNumericDate(time.Now())
	claims.NotBefore = jwt.NewNumericDate(time.Now())
	claims.Issuer = "test"
	claims.Subject = "somebody"
	claims.ID = "1"
	claims.Audience = []string{"somebody_else", "mom", "dad"}

	return claims
}

func createToken(username string, secretKey []byte) (string, error) {

	claims := NewClaims("alovelltroy", "tenant-1", "us-west-1")

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString(secretKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func verifyToken(tokenString string, secretKey []byte) error {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return secretKey, nil
	})

	if err != nil {
		return err
	}

	if !token.Valid {
		return fmt.Errorf("invalid token")
	}

	return nil
}

func parseToken(tokenString string, secretKey []byte) (string, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return secretKey, nil
	})

	if err != nil {
		return "", err
	}

	if !token.Valid {
		return "", fmt.Errorf("invalid token")
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		fmt.Println(claims["foo"], claims["nbf"])
		for k, v := range claims {
			fmt.Printf("key[%s] value[%s]\n", k, v)
		}
	} else {
		fmt.Println(err)
	}

	return "token.Claims.(jwt.MapClaims)", nil
}
