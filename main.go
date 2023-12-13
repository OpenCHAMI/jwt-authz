package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/openchami/jwt-authz/internal/issuer"
	"github.com/openchami/jwt-authz/pkg/ochamijwt"
)

func main() {
	var region = "us-west-1"
	var tenant = "tenant-1"
	var keys []issuer.APIKey
	var issuerURL = "https://authauth.alovelltroy.dev"
	// tokens := make(map[string]string)

	fmt.Println("Creating an issuer secret for use in this experiment.")
	randomness := issuer.GenerateRandomStringURLSafe(64)

	secretKey := region + ":" + tenant + ":" + randomness
	fmt.Println("The secret key is: " + secretKey)

	var is = issuer.Issuer{
		IssuerURL: issuerURL,
		SecretKey: secretKey,
	}

	fmt.Println("Creating 128 API Keys and issuing tokens for them.")

	for i := 0; i < 128; i++ {
		keys = append(keys, issuer.NewAPIKey([]issuer.Role{}))
		myKey := keys[len(keys)-1]
		// fmt.Println("API Key ID: " + myKey.GetAPIKeyID())
		signedToken, err := is.IssueTokenforAPIKey(myKey, "alovelltroy", tenant, region)
		if err != nil {
			fmt.Println(err)
		}

		fmt.Println("Parsing the signed token manually.")
		parseSignedToken(signedToken)

		// fmt.Println("Parsing the signed token using ParseWithClaims")
		// Parse the token without verifying the signature
		myToken, err := jwt.ParseWithClaims(signedToken, &ochamijwt.OchamiClaims{}, func(token *jwt.Token) (interface{}, error) {
			return []byte(is.SecretKey), nil
		})
		if err != nil {
			log.Fatal(err)
		} else if myClaims, ok := myToken.Claims.(*ochamijwt.OchamiClaims); ok {
			myUsername, _ := myClaims.GetUsername()
			myIssuer, _ := myClaims.GetIssuer()
			myIssueTime, _ := myClaims.GetIssuedAt()
			fmt.Println(i+1, strconv.Itoa(len(signedToken))+"B", myUsername, myIssuer, myIssueTime.String())
		} else {
			log.Fatal("unknown claims type, cannot proceed")
		}

	}

}

// parseSignedToken takes a signed token and parses it into its three parts.
// It then decodes the header and claims and prints them.
// This function doesn't attempt to verify anything using the siganture
// It is intended to be used as a learning tool.
// A JWT is simply a set of base64 encoded JSON objects separated by a '.'
// Each segment has a defined schema and purpose.
//      The header and signature form the envelope.
//      The structure in between ("Claims") contains all the user-serviceable parts.
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
