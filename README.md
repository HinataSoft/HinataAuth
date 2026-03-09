# HinataAuth

A simple but capable OAuth 2.0 / OpenID Connect Authorization Server built with ASP.NET 10.0.

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

## Quick Start

```bash
# Build the project
dotnet build

# Run the server
dotnet run

# Server starts at http://localhost:5999
```

## Configuration

All configuration is in `appsettings.json`:

### AuthCredentials - User accounts for authorization code flow

```json
"AuthCredentials": {
  "credentials": [
    { "id": "user1", "secret": "password", "scopes": "read write" }
  ]
}
```

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

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /connect/authorize` | Authorization endpoint (user login) |
| `POST /connect/authorize` | Authorization with credentials |
| `POST /connect/token` | Token endpoint (all grant types) |
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
