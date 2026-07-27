using System.Text.Json;
using HinataAuth.Models;

namespace HinataAuth.Endpoints;

public static class DiscoveryEndpoint
{
    public static void MapDiscoveryEndpoint(this WebApplication app)
    {
        app.MapGet("/.well-known/openid-configuration", Handle);
        app.MapGet("/.well-known/oauth-authorization-server", Handle);
    }

    private static IResult Handle(HttpContext context, AuthCredentialsConfig authCredentialsConfig, JwtConfig jwtConfig, DynamicClientRegistrationConfig dcrConfig)
    {
        // Use issuer from JwtConfig (already populated - either explicitly set or dynamically from server URL)
        var issuer = jwtConfig.Issuer;

        // Extract unique scopes from all credentials
        var scopes = authCredentialsConfig.Credentials
            .SelectMany(c => c.Scopes.Split(' ', StringSplitOptions.RemoveEmptyEntries))
            .Distinct()
            .OrderBy(s => s)
            .ToArray();

        // Fallback to "auth" if no scopes are configured
        var scopesSupported = scopes.Length > 0 ? scopes : new[] { "auth" };

        var tokenAuthMethods = dcrConfig.Enabled
            ? new[] { "client_secret_basic", "client_secret_post", "none" }
            : new[] { "client_secret_basic", "client_secret_post" };

        var discoveryDocument = new Dictionary<string, object>
        {
            ["issuer"] = issuer,
            ["authorization_endpoint"] = $"{issuer}/connect/authorize",
            ["token_endpoint"] = $"{issuer}/connect/token",
            ["jwks_uri"] = $"{issuer}/.well-known/jwks",
            ["response_types_supported"] = new[] { "code" },
            ["response_modes_supported"] = new[] { "query", "form_post" },
            ["grant_types_supported"] = new[] { "authorization_code", "client_credentials", "refresh_token" },
            ["subject_types_supported"] = new[] { "public" },
            ["id_token_signing_alg_values_supported"] = new[] { "RS256" },
            ["scopes_supported"] = scopesSupported,
            ["userinfo_endpoint"] = $"{issuer}/connect/userinfo",
            ["token_endpoint_auth_methods_supported"] = tokenAuthMethods,
            ["claims_supported"] = new[]
            {
                "sub", "iss", "aud", "exp", "iat", "jti",
                "scope", "client_id", "name", "email"
            },
            ["code_challenge_methods_supported"] = new[] { "S256" }
        };

        if (dcrConfig.Enabled)
        {
            discoveryDocument["registration_endpoint"] = $"{issuer}/connect/register";
        }

        return Results.Json(discoveryDocument, new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        });
    }
}
