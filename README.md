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
- JWT access tokens signed with RSA-2048

## Intended Use

HinataAuth is designed for:

- **Development environments** - Quick OAuth 2.0 setup for testing
- **Static deployments** - Simple, self-contained auth server for small projects
- **Learning** - Clear implementation to understand OAuth 2.0 flows

> **Note**: For production deployments, consider using established solutions like Keycloak, Auth0, or IdentityServer. HinataAuth prioritizes simplicity over enterprise features.

> **Note**: JWT key (JWK) is generated fresh new at the app startup. That implies that tokens issued before a restart are no more valid.

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
| `GET /health` | Health check |

## Playground

Navigate to `testclient.html` to test client credentials flow and to `testauth.html` to test authorization code flow.

## Testing

```bash
# Run all tests
dotnet test

# Run specific test class
dotnet test --filter "FullyQualifiedName~AuthorizationCodeFlowTests"
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
│   └── DiscoveryEndpoint.cs
├── Services/           # Business logic
│   ├── AuthorizationCodeStore.cs
│   ├── ClientCredentialsStore.cs
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
