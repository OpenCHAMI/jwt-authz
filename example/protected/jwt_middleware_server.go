package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
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
				token, err := jwt.Parse(values[0], func(token *jwt.Token) (interface{}, error) {
					return jv.PublicKey, nil
				})
				if err != nil {
					fmt.Println("There's something wrong with the token:", err, values[0])
					return c.JSON(409, "Unauthorized")
				}
				c.Set("user", token.Claims)
				return next(c)
			}
		}
		fmt.Println("No Authorization Header Found")
		return c.JSON(409, "Unauthorized")
	}
}
