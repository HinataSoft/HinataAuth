using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;

namespace HinataAuth.Endpoints;

public static class JwksEndpoint
{
    // Store the RSA key for JWKS
    private static RSA? _rsaKey;
    private static string? _keyId;

    public static void MapJwksEndpoint(this WebApplication app)
    {
        app.MapGet("/.well-known/jwks", Handle);
        app.MapGet("/connect/jwks", Handle);
    }

    public static void InitializeRsaKey(RSA rsaKey, string keyId)
    {
        _rsaKey = rsaKey;
        _keyId = keyId;
    }

    private static IResult Handle()
    {
        if (_rsaKey == null || _keyId == null)
        {
            return Results.Json(new { error = "JWKS not initialized" }, statusCode: 500);
        }

        var rsaParams = _rsaKey.ExportParameters(false);

        // Create JWK parameters
        var jwks = new
        {
            keys = new[]
            {
                new
                {
                    kty = "RSA",
                    use = "sig",
                    kid = _keyId,
                    alg = "RS256",
                    n = Base64UrlEncoder.Encode(rsaParams.Modulus),
                    e = Base64UrlEncoder.Encode(rsaParams.Exponent)
                }
            }
        };

        return Results.Json(jwks, new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        });
    }
}
