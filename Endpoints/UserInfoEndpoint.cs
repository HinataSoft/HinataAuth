using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;

namespace HinataAuth.Endpoints;

public static class UserInfoEndpoint
{
    // Standard JWT claims to exclude from UserInfo response
    private static readonly HashSet<string> StandardJwtClaims = new(StringComparer.OrdinalIgnoreCase)
    {
        "sub", "iss", "aud", "exp", "iat", "jti", "nbf", "scope", "client_id"
    };

    // Map ASP.NET Core claim types to standard OIDC claim names
    private static readonly Dictionary<string, string> ClaimTypeToName = new(StringComparer.OrdinalIgnoreCase)
    {
        { "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name", "name" },
        { "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", "email" },
        { "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname", "given_name" },
        { "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname", "family_name" },
    };

    // Claims that require specific scopes (per OIDC spec)
    // Note: Include both raw JWT claim types and ASP.NET Core mapped claim types
    private static readonly Dictionary<string, string> ScopeToClaim = new(StringComparer.OrdinalIgnoreCase)
    {
        { "name", "profile" },
        { "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name", "profile" },
        { "family_name", "profile" },
        { "given_name", "profile" },
        { "middle_name", "profile" },
        { "nickname", "profile" },
        { "picture", "profile" },
        { "gender", "profile" },
        { "birthdate", "profile" },
        { "zoneinfo", "profile" },
        { "locale", "profile" },
        { "updated_at", "profile" },
        { "email", "email" },
        { "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", "email" },
        { "email_verified", "email" },
        { "address", "address" },
        { "phone_number", "phone" },
        { "phone_number_verified", "phone" }
    };

    public static void MapUserInfoEndpoint(this WebApplication app)
    {
        // OIDC Core §5.3: the UserInfo endpoint must support both GET and POST
        app.MapGet("/connect/userinfo", Handle).RequireAuthorization();
        app.MapPost("/connect/userinfo", Handle).RequireAuthorization();
    }

    private static IResult Handle(HttpContext context)
    {
            // Get user from authentication
            var user = context.User;
            if (user?.Identity?.IsAuthenticated != true)
            {
                return Results.Unauthorized();
            }

            // Get granted scopes from token - check both "scope" and "scp" claim types
            var scopeClaimTypes = new[] { "scope", "scp" };
            var grantedScopes = user.Claims
                .Where(c => scopeClaimTypes.Contains(c.Type))
                .SelectMany(c => c.Value.Split(' ', StringSplitOptions.RemoveEmptyEntries))
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

            // Build response with sub and any other claims
            var response = new Dictionary<string, object>();

            var sub = user.FindFirst(JwtRegisteredClaimNames.Sub)?.Value
                   ?? user.FindFirst(ClaimTypes.NameIdentifier)?.Value;

            if (sub != null)
            {
                response["sub"] = sub;
            }

            // Add all claims (excluding standard JWT claims)
            foreach (var claim in user.Claims)
            {
                // Skip standard JWT claims
                if (StandardJwtClaims.Contains(claim.Type))
                {
                    continue;
                }

                // Skip claims that look like URLs (e.g., from external identity providers) - EXCEPT for well-known OIDC claim types
                var isWellKnownOidcClaim = claim.Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress" ||
                                          claim.Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name";
                if (claim.Type.StartsWith("http") && !isWellKnownOidcClaim)
                {
                    continue;
                }

                // Check scope-based filtering for scoped claims
                var requiredScope = (string?)null;
                if (ScopeToClaim.TryGetValue(claim.Type, out var scope))
                {
                    requiredScope = scope;
                }

                // Only include if the required scope is granted
                if (requiredScope != null && !grantedScopes.Contains(requiredScope))
                {
                    continue;
                }

                // Map claim type to standard OIDC name
                var claimName = claim.Type;
                if (ClaimTypeToName.TryGetValue(claim.Type, out var standardName))
                {
                    claimName = standardName;
                }

                response[claimName] = claim.Value;
            }

            return Results.Json(response);
    }
}
