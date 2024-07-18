# TailSTS

Federate third-party OIDC tokens for Tailscale API access tokens.

Inspired by [Octo STS](https://github.com/apps/octo-sts) and [GTFO](https://github.com/thepwagner/github-token-factory-oidc)

**You should not use this in production workloads. This is a hobby project.**

## Usage

### Workflow Overview

Define policies in `/policies`. These describe OIDC tokens TailSTS will trust and grant Tailscale access to.

Make a POST request to the server. Contained in the request should be the third-party OIDC token and the Tailscale scopes being requested. If policies specify that the OIDC token is to be trusted and is allowed to access the requested scopes, a Tailscale access token is returned.

### Policies

Policies are written in [toml](https://toml.io/en/). Below are the accepted fields

- issuer: `string`. The `iss` field of the token.
- algorithm: `string`. The `alg` field of a token.
- subject: `string`. Optional. The `sub` field of a token. If not present, `sub` is ignored.
- jwks_url: `string`. URL to the JWKS endpoint for the token issuer.
- allowed_scopes: `string[]`. The Tailscale scopes the token is allowed to be granted.

An example policy can be found in `/policies`.

### Request

Add the OIDC token as a bearer token in the `Authorization` header. The Tailscale scopes being requested should be in the body of the request.

```json
{
  "scopes": ["devices:read", "acls"]
}
```

Send the POST request to the root of the server.

### Response

The server responds in plaintext always. If the status code is 200, the response body is the Tailscale access token. If the status code is anything else, the response body is an error message.

## Running TailSTS

### Locally

0. Have Go installed. 1.22.4 was the version used in development.
1. Clone the repo.
2. Run `go run cmd/server/main.go` in the root of the repo.

Run `go run cmd/server/main.go --help` to check the available flags. You'll need to set `--ts-client-id` and `--ts-client-secret` to your Tailscale Oauth client ID and secret.

### Docker

Example `docker run` command:

`docker run -v ./policies:/policies ghcr.io/jacobmichels/tailsts:main --policies-dir /policies --ts-client-id <client-id> --ts-client-secret <client-secret>`
