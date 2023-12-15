# Authorization with JWT in an Ochami System

The microservices in Ochami are based on the microservices from the original CSM project.  When delployed as part of a CSM system, all authentication and authorization are handled by the infrastructure that surrounds the microservices.  For ochami, we can't count on all the same infrastructure so we need to assume a posture of checking authorization at both the API Gateway as well as through the individual microservices.  Amature pilots describe this as "flying two mistakes high" which is more evocative than "defense in depth".  Both descriptions are appropriate.

When the gateway and mesh are both protecting microservices, it is possible to outsource all the jwt validataion and policy processing.  Without both systems, individual microservices need to understand how to interpret the claims in a jwt directly and they need the capacity to validate the signed hash.  The code in this repository implements a very simple issuer and demonstrates how to manually parse a jwt.

## Build and Install

This is a demonstration repo that does not ship any libararies or binaries.  Feel free to experiment with the software by building it yourself with `go build .` in the main source directory.

## Running the demo applications

There are two http echo servers included in the [example](/example/) directory.  The [issuer](/example/issuer/) acts as an issuer.  It creates an RSA keypair on startup and exposes three routes for generating API Keys, Tokens, and retrieving the RSA Public Key for verification.  The [other echo microservice](/example/protected/) verifies tokens and protects it's one route with a piece of middleware.

Each is a single file that can be started with `go run <filename>`

### Issuer Routes

* `/apikey` generates an API Key which can be retrieved with curl `curl -o apikey.json  http://localhost:3333/apikey`
* `token` uses the api key to generate a jwt.  The curl command should look like this: `export JWT=$(curl -X POST -d @apikey.json  http://localhost:3333/token)`
* `/pubkey` exists to share the public key with the JWT Verifiers.  It returns the public key in PEM format

### Protected JWT Demo Routes

* `/protected` returns "Hello World!" when called with a valid token. Otherwise it returns 409 Unauthorized



Call the `/protected` route on the second microservice using the token from the issuer. `curl -H "Authorization:$JWT" http://localhost:3334/protected`





##  JWT structure

A JWT is simply a set of base64 encoded JSON objects separated by a '.'
Each segment has a defined schema and purpose.
  * _Header_ The header is a base64 encoded json map of key/value pairs that describes the type of token and algorithm used for signing.
  * _Claims_ The claims section is a base64 encoded json structure that describes the entity for which the token has been generated and the permissions it claims to have.
  * _Signature_  The Signature is a signed hash of the base64 encodings of the other two sections using the algorithm specified in the header.

  For a more detailed understanding of these sections, refer to [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519#section-3).


## JWTs in Ochami

[Issue #11](https://github.com/OpenCHAMI/roadmap/issues/11) describes using JWTs for authorization within Ochami.
