package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/openchami/jwt-authz/internal/issuer"
)

var RSAPrivateKey rsa.PrivateKey

// This package implements an echo http server for demonstrating the generation and distribution of JWTs.
// It is farcically insecure and use of it will surely get you laughed at in security-minded circles.

func main() {
	addr := ":3333"
	fmt.Printf("Starting Server on %v\n", addr)
	// create a new echo instance
	e := echo.New()

	// Create an RSA Private Key
	fmt.Println("Creating an RSA key for use with the RSA issuer.")
	RSAPrivateKey, err := issuer.GeneratePrivateKey(4096)
	if err != nil {
		panic(err)
	}
	fmt.Println("The RSA private key is: " + base64.RawURLEncoding.EncodeToString(RSAPrivateKey.N.Bytes()))
	fmt.Println("Shhh... Don't tell anyone!")

	// Uncomment this line if you want to see your PEM files on disk
	// If you want the PublicKey, you're better off getting it from the /pubkey route
	// writePEMFiles(RSAPrivateKey)

	// Use the RSA Private Key to create our issuer
	var rsaIssuer = issuer.RSAIssuer{
		IssuerURL: "https://issuer.ochami.dev",
		RSAKey:    RSAPrivateKey,
	}

	// Create a disposable TokenServer
	ts := TokenServer{
		Issuer:  &rsaIssuer,
		APIKeys: make(map[string]issuer.APIKey),
		Tokens:  make(map[uuid.UUID]string),
	}

	e.GET("/apikey", GetNewAPIkey)
	e.POST("/token", ts.GenerateToken)
	e.GET("/pubkey", ts.PubKey)

	e.Logger.Fatal(e.Start(addr))

}

type TokenServer struct {
	Issuer  *issuer.RSAIssuer
	APIKeys map[string]issuer.APIKey // This is a map of keyid to keys
	Tokens  map[uuid.UUID]string     // This is a map of token ids to encrypted signed tokens
}

func (ts *TokenServer) GenerateToken(c echo.Context) error {
	myKey := &issuer.APIKey{}
	c.Bind(myKey)
	myTokenString, err := ts.Issuer.IssueTokenforAPIKey(*myKey, "nikola", "tenant-2", "region-1")
	if err != nil {
		panic(err)
	}
	return c.JSON(http.StatusCreated, myTokenString)
}

func (ts *TokenServer) PubKey(c echo.Context) error {
	publicKey := ts.Issuer.RSAKey.PublicKey

	publicKeyPEM := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(&publicKey),
	}
	buf := new(bytes.Buffer)
	if err := pem.Encode(buf, publicKeyPEM); err != nil {
		return c.JSON(201, publicKeyPEM)
	}
	return c.String(200, buf.String())

}

func GetNewAPIkey(c echo.Context) error {
	key := issuer.NewAPIKey([]issuer.Role{})
	return c.JSON(200, key)
}

func writePEMFiles(RSAPrivateKey *rsa.PrivateKey) {
	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(RSAPrivateKey),
	}
	privateKeyFile, err := os.Create("private_key.pem")
	if err != nil {
		panic(err)
	}
	pem.Encode(privateKeyFile, privateKeyPEM)
	privateKeyFile.Close()

	publicKey := &RSAPrivateKey.PublicKey

	publicKeyPEM := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(publicKey),
	}
	publicKeyFile, err := os.Create("public_key.pem")
	if err != nil {
		panic(err)
	}
	pem.Encode(publicKeyFile, publicKeyPEM)
	publicKeyFile.Close()
}
