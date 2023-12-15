package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"github.com/openchami/jwt-authz/pkg/ochamijwt"
)

func main() {
	addr := ":3334"
	fmt.Printf("Starting Server on %v\n", addr)
	// create a new echo instance
	e := echo.New()

	verifier := JWTVerifier{}
	verifier.LoadPublicKeyFromURL("http://localhost:3333/pubkey")

	e.Use(verifier.JWTVerify)

	e.GET("/protected", BasicHandler)

	e.Logger.Fatal(e.Start(addr))

}

func BasicHandler(c echo.Context) error {
	return c.JSON(200, "Hello World!")
}

type JWTVerifier struct {
	PublicKey *rsa.PublicKey
}

func (jv *JWTVerifier) LoadPublicKeyFromURL(url string) {
	pubKeyClient := http.Client{}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		log.Fatal(err)
	}

	res, err := pubKeyClient.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	if res.Body != nil {
		defer res.Body.Close()
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		log.Fatal(err)
	}

	// fmt.Println(string(body))  This should be the public key in PEM format
	// That means that it starts and ends with the ----BEGIN RSA PUBLIC KEY---- and ----END RSA PUBLIC KEY---- lines
	// The included string should start with MII

	pubKeyPEM, rest := pem.Decode(body)
	if pubKeyPEM == nil || pubKeyPEM.Type != "RSA PUBLIC KEY" {
		log.Fatal("Failed to decode PEM block containing public key", pubKeyPEM, rest)
	}
	pub, err := x509.ParsePKCS1PublicKey(pubKeyPEM.Bytes)
	if err != nil {
		log.Fatal(err)
	}

	jv.PublicKey = pub
}

func (jv *JWTVerifier) JWTVerify(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		for header, values := range c.Request().Header {
			if header == "Authorization" {
				// fmt.Println("Found Authorization Header:", values[0])

				token, err := jwt.Parse(strings.TrimSpace(values[0]), func(token *jwt.Token) (interface{}, error) {
					return jv.PublicKey, nil
				})
				if err != nil {
					fmt.Println("There's something wrong with the token:", err, values[0])
					token, err = manualJWTParse(values[0], jv.PublicKey)
					return c.JSON(409, "Unauthorized")
				}
				c.Set("user", token.Claims)
				fmt.Println("Token is valid")
				return next(c)
			}
		}
		fmt.Println("No Authorization Header Found")
		return c.JSON(409, "Unauthorized")
	}
}

func manualJWTParse(tokenString string, publicKey *rsa.PublicKey) (*jwt.Token, error) {
	var token jwt.Token

	// This is a manual parse of the token.  It doesn't verify the signature.

	// The token is a string, so we need to parse it into a token object
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		// Without three parts, the token is invalid.
		return &token, fmt.Errorf("Invalid token format.")
	}
	// The token is made up of three parts separated by a '.'
	// The first part is the header, the second part is the claims, and the third part is the signature.
	// The header and claims are JSON objects that have been base64 encoded.

	// The header is a JSON object that contains information about the token.
	// The header contains the algorithm used to sign the token.
	// The header is base64 encoded, so we need to decode it.
	header := parts[0]
	decodedHeader, err := base64.RawURLEncoding.DecodeString(header)
	if err != nil {
		fmt.Println("Error decoding header: " + err.Error())
		return &token, err
	}
	// Print the raw string header
	fmt.Println("Header: " + string(decodedHeader))
	// Print the json decoded header
	json.Unmarshal(decodedHeader, &token.Header)
	fmt.Println("Header: " + fmt.Sprintf("%+v", token.Header))

	// The claims are a JSON object that contains information about the user.
	// The claims are base64 encoded, so we need to decode them.
	claims := parts[1]
	decodedClaims, err := base64.RawURLEncoding.DecodeString(claims)
	if err != nil {
		fmt.Println("Error decoding claims: " + err.Error())
		return &token, err
	}
	// Print the raw string claims
	fmt.Println("Claims: " + string(decodedClaims))
	// Print the json decoded claims
	tokenClaims := ochamijwt.OchamiClaims{}
	json.Unmarshal(decodedClaims, &tokenClaims)
	fmt.Println("Claims: " + fmt.Sprintf("%+v", tokenClaims))

	// The signature is a hash of the header and claims, signed with the secret key.
	// The signature is used to verify that the header and claims have not been tampered with.
	// The RSA Public Key has been previously shared by the issuer.
	signature := parts[2]
	// The signature is base64 encoded, so we need to decode it.
	decodedSignature, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		fmt.Println("Error decoding signature: " + err.Error())
		return &token, err
	}
	// Print the raw string signature
	fmt.Println("Signature: " + string(decodedSignature))
	// Verify the signature
	err = jwt.SigningMethodRS256.Verify(strings.Join(parts[0:2], "."), decodedSignature, publicKey)
	if err != nil {
		fmt.Println("Error verifying signature: " + err.Error())
		return &token, err
	}

	return &token, nil
}
