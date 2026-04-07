# HinataAuth

[![Tests](https://github.com/HinataSoft/HinataAuth/actions/workflows/test.yml/badge.svg)](https://github.com/HinataSoft/HinataAuth/actions/workflows/test.yml)

A simple but capable OAuth 2.0 / OpenID Connect Authorization Server built with ASP.NET

## Overview

HinataAuth implements three OAuth 2.0 grant types:

- **Authorization Code Flow** - User authentication with redirect (for web apps)
- **Client Credentials Flow** - Machine-to-machine authentication
- **Refresh Token Flow** - Token renewal with rotation

It also provides:
- OIDC Discovery endpoint (`/.well-known/openid-configuration`)
- JSON Web Key Set endpoint (`/.well-known/jwks`)
- UserInfo endpoint (`/connect/userinfo`)
- JWT access tokens and `id_token`s signed with RSA-2048
- PKCE support (RFC 7636) with `S256` and `plain` methods
- Dynamic Client Registration (RFC 7591) and Client Management (RFC 7592)

## Intended Use

HinataAuth is designed for:

- **Development environments** - Quick OAuth 2.0 setup for testing
- **Static deployments** - Simple, self-contained auth server for small projects
- **Learning** - Clear implementation to understand OAuth 2.0 flows

> **Note**: For production deployments, consider using established solutions like Keycloak, Auth0, or IdentityServer. HinataAuth prioritizes simplicity over enterprise features.

> **Note**: The RSA signing key is persisted to `run/jwk.json` in the working directory. On first run, a new key is generated and the `run/` directory is created automatically. On subsequent runs, the existing key is loaded so that tokens survive restarts. If the file is corrupt, an ephemeral key is used without overwriting the file.

## Quick Start

```bash
# Build the project
dotnet build

# Run the server
dotnet run

# Server starts at http://localhost:5999 (Debug) or http://localhost:5000 (Release)
```

## Docker

```bash
# Pull and run the latest image
docker run -p 8080:8080 hinatasoft/hinata-auth
```

[Docker Hub](https://hub.docker.com/r/hinatasoft/hinata-auth)

## Configuration

All configuration is in `appsettings.json`:

### AuthCredentials - User/client accounts both for authorization code flow and client credentials flow

```json
"AuthCredentials": {
  "credentials": [
    { 
      "id": "user1", 
      "secret": "password", 
      "scopes": "read write",
      "claims": {
        "name": "John Doe",
        "email": "john@example.com"
      }
    }
  ]
}
```

You can configure custom claims (like `name` and `email`) that will be included in the JWT access token and returned by the UserInfo endpoint.

These credentials are shared both for authorization code flow and for client credentials flow.
Thus, `id` is both username and client-id, `secret` is both password and client-secret.

This way, one can log in somewhere as a user and, at the same time, provide the same set of credentials to some automated agent to act in his/her name.

### AuthorizationCode - OAuth client definitions

```json
"AuthorizationCode": {
  "codeExpirationMinutes": 10,
  "defaultRedirectUri": "http://localhost:3000/callback",
  "clients": [
    {
      "clientId": "my-client",
      "clientSecret": "secret",
      "scopes": "read write",
      "redirectUris": ["http://localhost:3000/callback"]
    }
  ]
}
```

### JWT - Token settings

```json
"Jwt": {
  "issuer": "http://localhost:5999",
  "audience": "MyAPI",
  "expirationMinutes": 60,
  "refreshToken": {
    "expirationDays": 7
  }
}
```

### DynamicClientRegistration - Dynamic Client Registration (RFC 7591 + 7592)

```json
"DynamicClientRegistration": {
  "enabled": true,
  "allowConfidentialClients": false,
  "allowedScopes": ["read", "write"],
  "clientStorePath": "run/clients.json"
}
```

- `enabled` — master switch for the `/connect/register` endpoint. When `false`, returns 404 and is omitted from discovery.
- `allowConfidentialClients` — when `false` (default), only public clients (`token_endpoint_auth_method: "none"`) can register. Public clients must use PKCE. Set to `true` to allow clients to request a `client_secret`.
- `allowedScopes` — scopes that dynamically registered clients may request. Registration is rejected if a scope is not in this list.
- `clientStorePath` — file path for persisting dynamic clients. Secrets are stored as SHA-256 hashes. Uses atomic writes.

Dynamic clients are limited to `authorization_code` and `refresh_token` grant types. Registered clients can be read, updated, or deleted via the management endpoint using the `registration_access_token` returned at registration.

### PathBase - Base path for redirects (optional)

```json
"PathBase": "/auth"
```

This setting affects only 302 Redirect results from `/connect/authorize` to `/<pathBase>/authorize.html`.

This is convenient when using HinataAuth behind a reverse proxy with a subpath. 

Leave empty for no prefix.

*Note:* Static HTML pages also take pathBase into consideration, however it is derived directly from the URL used.

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /connect/authorize` | Authorization endpoint (user login) |
| `POST /connect/authorize` | Authorization with credentials |
| `POST /connect/token` | Token endpoint (all grant types) |
| `GET /connect/userinfo` | UserInfo endpoint (requires valid JWT) |
| `GET /.well-known/openid-configuration` | OIDC Discovery |
| `GET /.well-known/jwks` | JSON Web Key Set |
| `POST /connect/register` | Dynamic Client Registration (RFC 7591) |
| `GET/PUT/DELETE /connect/register/{id}` | Client Management (RFC 7592) |
| `GET /health` | Health check |

## Token Claims

Access tokens include a `sub_type` claim to distinguish the authentication method:

| Flow | `sub_type` | Description |
|------|-----------|-------------|
| Authorization Code | `identity` | User-authenticated token |
| Client Credentials | `client` | Machine-to-machine token |
| Refresh Token | *(copied)* | Preserves the original `sub_type` |

### ID Token

An OIDC `id_token` is returned alongside the `access_token` for identity flows (authorization code grant and refresh token grant when the original was from authorization code). It is **not** issued for client credentials flow.

The `id_token` differs from the `access_token`:
- **Audience** (`aud`) is set to the `client_id` (not the API audience)
- Contains user identity claims (`name`, `email`, etc.)
- Contains `at_hash` (access token hash per OIDC Core §3.1.3.6)
- Does not contain `scope` or `client_id` claims

## Playground

Use `test.html` to test authorization code flow or client credentials flow.

## Testing

```bash
# Run all tests
dotnet test

# Run specific test class
dotnet test --filter "FullyQualifiedName~AuthorizationCodeFlowTests"
```

## Example: Authorization Code Token Response

After exchanging an authorization code at `/connect/token`:

```json
{
  "access_token": "eyJ...",
  "id_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "auth profile email",
  "refresh_token": "..."
}
```

## Example: Client Credentials Flow

```bash
curl -X POST http://localhost:5999/connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=my-client&client_secret=secret&scope=read"
```

Response:
```json
{
  "access_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "read",
  "refresh_token": "..."
}
```

## Project Structure

```
HinataAuth/
├── Endpoints/          # HTTP handlers (minimal APIs)
│   ├── AuthorizationEndpoint.cs
│   ├── TokenEndpoint.cs
│   ├── JwksEndpoint.cs
│   ├── DiscoveryEndpoint.cs
│   └── RegistrationEndpoint.cs
├── Services/           # Business logic
│   ├── AuthorizationCodeStore.cs
│   ├── ClientCredentialsStore.cs
│   ├── ClientStore.cs
│   └── RefreshTokenStore.cs
├── Models/             # Configuration classes
└── Program.cs          # App entry point
```

## Tech Stack

- ASP.NET 10.0
- System.IdentityModel.Tokens.Jwt
- In-memory token storage (easily replaceable)

## License

GPL3
