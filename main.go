package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/openchami/jwt-authz/internal/issuer"
	"github.com/openchami/jwt-authz/pkg/ochamijwt"
)

const (
	// Iterations is the number of times we will issue a token
	Iterations = 128
)

func main() {
	var region = "us-west-1"
	var tenant = "tenant-1"
	var keys []issuer.APIKey
	var issuerURL = "https://jwt.ochami.dev"

	fmt.Println("This application will create two issuers and use each one of them", Iterations, "times to create signed tokens and then read those tokens.")

	fmt.Println("Creating an issuer secret for use with the HMAC issuer.")
	randomness := issuer.GenerateRandomStringURLSafe(64)
	secretKey := region + ":" + tenant + ":" + randomness
	fmt.Println("The secret key is: " + secretKey)

	// Create an HMAC issuer
	var is = issuer.Issuer{
		IssuerURL: issuerURL,
		SecretKey: secretKey,
	}

	fmt.Println("Creating an RSA key for use with the RSA issuer.")
	privateKey, err := issuer.GeneratePrivateKey(4096)
	if err != nil {
		panic(err)
	}
	fmt.Println("The RSA private key is: " + base64.RawURLEncoding.EncodeToString(privateKey.N.Bytes()))
	fmt.Println("Shhh... Don't tell anyone!")

	// Create an RSA issuer
	var rsaIssuer = issuer.RSAIssuer{
		IssuerURL: issuerURL,
		RSAKey:    *privateKey,
	}

	fmt.Println("Creating", Iterations, "API Keys that we can use.")

	for i := 0; i < Iterations; i++ {
		keys = append(keys, issuer.NewAPIKey([]issuer.Role{}))
	}

	fmt.Println("Issuing", Iterations, "tokens with the HMAC issuer and verifying them with the secret key.")
	for j, myKey := range keys {
		// The HMAC Issuer has a helper function for Issuing a token for an API Key
		signedHMACToken, err := is.IssueTokenforAPIKey(myKey, "alovelltroy", tenant, region)
		if err != nil {
			fmt.Println(err)
		}
		// Once we have a token, we can use it immediately.  If we want to understand what's inside, we can parse it.
		// HMAC signatures are based on a secret key that must be shared between the issuer and the verifier.
		// Only use it if you're prepared to trust that the verifier can keep the secret safe.
		// NB: There's no protection available to prevent the verifier from creating "fradulent" tokens.
		myToken, err := jwt.ParseWithClaims(signedHMACToken, &ochamijwt.OchamiClaims{}, func(token *jwt.Token) (interface{}, error) {
			return []byte(is.SecretKey), nil
		})
		if err != nil {
			log.Fatal(err)
		} else if myClaims, ok := myToken.Claims.(*ochamijwt.OchamiClaims); ok {
			myUsername, _ := myClaims.GetUsername()
			myIssuer, _ := myClaims.GetIssuer()
			myIssueTime, _ := myClaims.GetIssuedAt()
			fmt.Println(j+1, strconv.Itoa(len(signedHMACToken))+"B", myUsername, myIssuer, myIssueTime.String())
		} else {
			log.Fatal("unknown claims type, cannot proceed")
		}

		// Uncomment the next two lines if you want to see how the manual parsing works
		// NB: Our manual parsing does not attempt to verify the signature
		// fmt.Println("Parsing the signed token manually.")
		// parseSignedToken(signedHMACToken)
	}

	fmt.Println("Issuing", Iterations, "tokens with the RSA issuer and verifying them with the public key.")

	for k, myKey := range keys {

		// Without a dedicated helper function for issuing tokens with an API Key, we get to see how the sausage is made
		// First we have to create a struct with our RegisteredClaims and our custom OchamiClaims
		rsaClaims := ochamijwt.OchamiClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    rsaIssuer.IssuerURL,
				Subject:   myKey.GetAPIKeyID(),
				Audience:  []string{"bss", "api", "test"},
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
				NotBefore: jwt.NewNumericDate(time.Now()),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
				ID:        uuid.NewString(),
			},
			Username: "nikola",
			Tenant:   "tenant-1",
			Region:   "region-1",
		}

		// Then we create a token with the claims and include the RSA signing method in the header.
		rsaToken := jwt.NewWithClaims(jwt.SigningMethodRS256, rsaClaims)
		// Finally, we sign the token with the RSA private key
		rsaTokenString, err := rsaToken.SignedString(privateKey)
		if err != nil {
			panic(err)
		}
		// Once we have a token, we can use it immediately.  If we want to understand what's inside, we can parse it.
		// RSA signatures are based on a public/private key pair.  The issuer signs the token with the private key and the verifier verifies the signature with the public key.
		// The public key can be shared with the verifier without compromising the security of the system.
		myRSAToken, err := jwt.ParseWithClaims(rsaTokenString, &ochamijwt.OchamiClaims{}, func(token *jwt.Token) (interface{}, error) {
			return privateKey.Public(), nil
		})
		if err != nil {
			log.Fatal(err)
		} else if myRSAClaims, ok := myRSAToken.Claims.(*ochamijwt.OchamiClaims); ok {
			myRSAUsername, _ := myRSAClaims.GetUsername()
			myRSAIssuer, _ := myRSAClaims.GetIssuer()
			myRSAIssueTime, _ := myRSAClaims.GetIssuedAt()
			fmt.Println("RSA:", k+1, strconv.Itoa(len(rsaTokenString))+"B", myRSAUsername, myRSAIssuer, myRSAIssueTime.String())

		} else {
			log.Fatal("unknown claims type, cannot proceed")
		}

		// Sleep between 0 and 50 Milliseconds before continuing
		// randomSleep, _ := rand.Int(rand.Reader, big.NewInt(50))
		// fmt.Println("Sleeping for " + randomSleep.String() + " milliseconds")
		// time.Sleep(time.Duration(randomSleep.Int64()) * time.Millisecond)

	}

}

// parseSignedToken takes a signed token and parses it into its three parts.
// It then decodes the header and claims and prints them.
// This function doesn't attempt to verify anything using the siganture
// It is intended to be used as a learning tool.
// A JWT is simply a set of base64 encoded JSON objects separated by a '.'
// Each segment has a defined schema and purpose.
//
//	The header and signature form the envelope.
//	The structure in between ("Claims") contains all the user-serviceable parts.
//
// The IETF defines the structure and a set of "Registered Claims"  https://datatracker.ietf.org/doc/html/rfc7519#section-4.1
// The OchamiClaims struct extends the RegisteredClaims with a few more fields that are specific to Ochami.
// Further examples and learning are present in the go-jwt codebase at: https://github.com/golang-jwt/jwt/blob/main/example_test.go#L103
func parseSignedToken(signedToken string) {
	token := jwt.Token{
		Header: make(map[string]interface{}),
		Claims: ochamijwt.OchamiClaims{},
		Method: jwt.SigningMethodHS256,
		Valid:  false,
	}
	// A JWT is made up of three parts separated by a '.'  Each one is a base64 encoded string.
	// The first part is the header, the second part is the claims, and the third part is the signature.
	// The header and claims are JSON objects that have been base64 encoded.
	// The signature is a hash of the header and claims, signed with the secret key.
	// The signature is used to verify that the header and claims have not been tampered with.
	// The secret key is only known to the issuer and the verifier.
	parts := strings.Split(signedToken, ".")
	if len(parts) != 3 {
		// Without three parts, the token is invalid.
		panic("Invalid token format.")
	}
	header := parts[0]
	decodedHeader, err := base64.RawURLEncoding.DecodeString(header)
	if err != nil {
		fmt.Println("Error decoding header: " + err.Error())
		panic(err)
	}
	// Print the raw string header
	fmt.Println("Header: " + string(decodedHeader))
	// Print the json decoded header
	json.Unmarshal(decodedHeader, &token.Header)
	fmt.Println("Header: " + fmt.Sprintf("%+v", token.Header))

	claims := parts[1]
	decodedClaims, err := base64.RawURLEncoding.DecodeString(claims)
	if err != nil {
		fmt.Println("Error decoding claims: " + err.Error())
		panic(err)
	}
	// Print the raw string claims
	fmt.Println("Claims: " + string(decodedClaims))
	// Print the json decoded claims
	tokenClaims := ochamijwt.OchamiClaims{}
	json.Unmarshal(decodedClaims, &tokenClaims)
	fmt.Println("Claims: " + fmt.Sprintf("%+v", tokenClaims))

	signature := parts[2]

	// Print the raw string signature
	fmt.Println("Signature: " + signature)

}
