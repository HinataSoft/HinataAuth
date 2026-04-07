using System.Security.Cryptography;
using System.Text.Json;
using HinataAuth.Models;
using HinataAuth.Services;

namespace HinataAuth.Endpoints;

public static class RegistrationEndpoint
{
    private static readonly JsonSerializerOptions SnakeCaseOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower
    };

    private static readonly HashSet<string> AllowedGrantTypes = new() { "authorization_code", "refresh_token" };
    private static readonly HashSet<string> AllowedResponseTypes = new() { "code" };
    private static readonly HashSet<string> AllowedAuthMethods = new() { "none", "client_secret_post" };

    public static void MapRegistrationEndpoint(this WebApplication app)
    {
        // POST /connect/register — RFC 7591 client registration (open, no auth)
        app.MapPost("/connect/register", async (HttpContext context) =>
        {
            var dcrConfig = context.RequestServices.GetRequiredService<DynamicClientRegistrationConfig>();
            if (!dcrConfig.Enabled)
                return Results.NotFound();

            var json = await ReadJsonBody(context);
            if (json == null)
                return InvalidClientMetadata("Invalid or missing JSON body");

            var body = json.Value;

            // Parse and validate redirect_uris (required, non-empty array of absolute URIs)
            if (!body.TryGetProperty("redirect_uris", out var redirectUrisElement)
                || redirectUrisElement.ValueKind != JsonValueKind.Array
                || redirectUrisElement.GetArrayLength() == 0)
            {
                return InvalidClientMetadata("redirect_uris is required and must be a non-empty array");
            }

            var redirectUris = new List<string>();
            foreach (var uri in redirectUrisElement.EnumerateArray())
            {
                var uriStr = uri.GetString();
                if (string.IsNullOrEmpty(uriStr) || !Uri.TryCreate(uriStr, UriKind.Absolute, out _))
                    return InvalidClientMetadata($"Invalid redirect URI: {uriStr}");
                redirectUris.Add(uriStr);
            }

            // Parse grant_types (optional, default ["authorization_code"])
            var grantTypes = new List<string> { "authorization_code" };
            if (body.TryGetProperty("grant_types", out var grantTypesElement)
                && grantTypesElement.ValueKind == JsonValueKind.Array)
            {
                grantTypes = new List<string>();
                foreach (var gt in grantTypesElement.EnumerateArray())
                {
                    var gtStr = gt.GetString();
                    if (string.IsNullOrEmpty(gtStr) || !AllowedGrantTypes.Contains(gtStr))
                        return InvalidClientMetadata($"Unsupported grant_type: {gtStr}");
                    grantTypes.Add(gtStr);
                }
            }

            // Parse response_types (optional, default ["code"])
            var responseTypes = new List<string> { "code" };
            if (body.TryGetProperty("response_types", out var responseTypesElement)
                && responseTypesElement.ValueKind == JsonValueKind.Array)
            {
                responseTypes = new List<string>();
                foreach (var rt in responseTypesElement.EnumerateArray())
                {
                    var rtStr = rt.GetString();
                    if (string.IsNullOrEmpty(rtStr) || !AllowedResponseTypes.Contains(rtStr))
                        return InvalidClientMetadata($"Unsupported response_type: {rtStr}");
                    responseTypes.Add(rtStr);
                }
            }

            // Parse token_endpoint_auth_method (optional, default depends on AllowConfidentialClients)
            var authMethod = dcrConfig.AllowConfidentialClients ? "client_secret_post" : "none";
            if (body.TryGetProperty("token_endpoint_auth_method", out var authMethodElement)
                && authMethodElement.ValueKind == JsonValueKind.String)
            {
                authMethod = authMethodElement.GetString() ?? "none";
                if (!AllowedAuthMethods.Contains(authMethod))
                    return InvalidClientMetadata($"Unsupported token_endpoint_auth_method: {authMethod}");
            }

            if (authMethod == "client_secret_post" && !dcrConfig.AllowConfidentialClients)
                return InvalidClientMetadata("Confidential clients (client_secret_post) are not allowed. Set AllowConfidentialClients to true in configuration to enable this.");

            // Parse scope (optional, space-separated string)
            var scopes = new List<string>(dcrConfig.AllowedScopes);
            if (body.TryGetProperty("scope", out var scopeElement)
                && scopeElement.ValueKind == JsonValueKind.String)
            {
                var scopeStr = scopeElement.GetString() ?? "";
                var requestedScopes = scopeStr.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                foreach (var s in requestedScopes)
                {
                    if (!dcrConfig.AllowedScopes.Contains(s))
                        return InvalidClientMetadata($"Scope not allowed: {s}");
                }
                scopes = requestedScopes.ToList();
            }

            // Parse optional fields
            string? clientName = null;
            if (body.TryGetProperty("client_name", out var clientNameElement)
                && clientNameElement.ValueKind == JsonValueKind.String)
            {
                clientName = clientNameElement.GetString();
            }

            string? clientUri = null;
            if (body.TryGetProperty("client_uri", out var clientUriElement)
                && clientUriElement.ValueKind == JsonValueKind.String)
            {
                clientUri = clientUriElement.GetString();
            }

            // Generate credentials
            var clientId = Guid.NewGuid().ToString();
            var isConfidential = authMethod != "none";
            var clientSecret = isConfidential ? GenerateRandomString(32) : null;
            var registrationAccessToken = GenerateRandomString(32);

            var jwtConfig = context.RequestServices.GetRequiredService<JwtConfig>();
            var registrationClientUri = $"{jwtConfig.Issuer}/connect/register/{clientId}";

            var registration = new ClientRegistration
            {
                ClientId = clientId,
                TokenEndpointAuthMethod = authMethod,
                GrantTypes = grantTypes,
                ResponseTypes = responseTypes,
                RedirectUris = redirectUris,
                Scopes = scopes,
                ClientName = clientName,
                ClientUri = clientUri,
                RegistrationClientUri = registrationClientUri
            };

            var clientStore = context.RequestServices.GetRequiredService<IClientStore>();
            clientStore.RegisterClient(registration, clientSecret ?? "", registrationAccessToken);

            // Build response
            var response = new Dictionary<string, object>
            {
                ["client_id"] = clientId,
                ["client_id_issued_at"] = new DateTimeOffset(registration.CreatedAt).ToUnixTimeSeconds(),
                ["registration_access_token"] = registrationAccessToken,
                ["registration_client_uri"] = registrationClientUri,
                ["redirect_uris"] = redirectUris,
                ["grant_types"] = grantTypes,
                ["response_types"] = responseTypes,
                ["token_endpoint_auth_method"] = authMethod,
                ["scope"] = string.Join(" ", scopes)
            };

            if (isConfidential)
            {
                response["client_secret"] = clientSecret!;
                response["client_secret_expires_at"] = 0;
            }

            if (clientName != null)
                response["client_name"] = clientName;

            return Results.Json(response, SnakeCaseOptions, statusCode: 201);
        });

        // GET /connect/register/{clientId} — RFC 7592 read
        app.MapGet("/connect/register/{clientId}", (HttpContext context, string clientId) =>
        {
            var dcrConfig = context.RequestServices.GetRequiredService<DynamicClientRegistrationConfig>();
            if (!dcrConfig.Enabled)
                return Results.NotFound();

            var clientStore = context.RequestServices.GetRequiredService<IClientStore>();
            var client = clientStore.GetClient(clientId);
            if (client == null)
                return Results.NotFound();

            if (!client.IsDynamic)
                return Results.Json(new { error = "forbidden", error_description = "Static clients cannot be managed" }, statusCode: 403);

            var token = ExtractBearerToken(context);
            if (string.IsNullOrEmpty(token))
                return Results.Json(new { error = "invalid_token" }, statusCode: 401);

            var dynamicClient = clientStore.GetDynamicClient(clientId, token);
            if (dynamicClient == null)
                return Results.Json(new { error = "invalid_token" }, statusCode: 401);

            var jwtConfig = context.RequestServices.GetRequiredService<JwtConfig>();
            var response = new Dictionary<string, object>
            {
                ["client_id"] = dynamicClient.ClientId,
                ["client_id_issued_at"] = new DateTimeOffset(dynamicClient.CreatedAt).ToUnixTimeSeconds(),
                ["registration_client_uri"] = $"{jwtConfig.Issuer}/connect/register/{dynamicClient.ClientId}",
                ["redirect_uris"] = dynamicClient.RedirectUris,
                ["grant_types"] = dynamicClient.GrantTypes,
                ["response_types"] = dynamicClient.ResponseTypes,
                ["token_endpoint_auth_method"] = dynamicClient.TokenEndpointAuthMethod,
                ["scope"] = string.Join(" ", dynamicClient.Scopes)
            };

            if (dynamicClient.ClientName != null)
                response["client_name"] = dynamicClient.ClientName;

            return Results.Json(response, SnakeCaseOptions);
        });

        // PUT /connect/register/{clientId} — RFC 7592 update
        app.MapPut("/connect/register/{clientId}", async (HttpContext context, string clientId) =>
        {
            var dcrConfig = context.RequestServices.GetRequiredService<DynamicClientRegistrationConfig>();
            if (!dcrConfig.Enabled)
                return Results.NotFound();

            var clientStore = context.RequestServices.GetRequiredService<IClientStore>();
            var existingClient = clientStore.GetClient(clientId);
            if (existingClient == null)
                return Results.NotFound();

            if (!existingClient.IsDynamic)
                return Results.Json(new { error = "forbidden", error_description = "Static clients cannot be managed" }, statusCode: 403);

            var token = ExtractBearerToken(context);
            if (string.IsNullOrEmpty(token))
                return Results.Json(new { error = "invalid_token" }, statusCode: 401);

            // Validate the token matches before proceeding
            var validatedClient = clientStore.GetDynamicClient(clientId, token);
            if (validatedClient == null)
                return Results.Json(new { error = "invalid_token" }, statusCode: 401);

            // Parse and validate the request body (same rules as POST)
            var json = await ReadJsonBody(context);
            if (json == null)
                return InvalidClientMetadata("Invalid or missing JSON body");

            var body = json.Value;

            // Parse and validate redirect_uris
            if (!body.TryGetProperty("redirect_uris", out var redirectUrisElement)
                || redirectUrisElement.ValueKind != JsonValueKind.Array
                || redirectUrisElement.GetArrayLength() == 0)
            {
                return InvalidClientMetadata("redirect_uris is required and must be a non-empty array");
            }

            var redirectUris = new List<string>();
            foreach (var uri in redirectUrisElement.EnumerateArray())
            {
                var uriStr = uri.GetString();
                if (string.IsNullOrEmpty(uriStr) || !Uri.TryCreate(uriStr, UriKind.Absolute, out _))
                    return InvalidClientMetadata($"Invalid redirect URI: {uriStr}");
                redirectUris.Add(uriStr);
            }

            // Parse grant_types
            var grantTypes = new List<string> { "authorization_code" };
            if (body.TryGetProperty("grant_types", out var grantTypesElement)
                && grantTypesElement.ValueKind == JsonValueKind.Array)
            {
                grantTypes = new List<string>();
                foreach (var gt in grantTypesElement.EnumerateArray())
                {
                    var gtStr = gt.GetString();
                    if (string.IsNullOrEmpty(gtStr) || !AllowedGrantTypes.Contains(gtStr))
                        return InvalidClientMetadata($"Unsupported grant_type: {gtStr}");
                    grantTypes.Add(gtStr);
                }
            }

            // Parse response_types
            var responseTypes = new List<string> { "code" };
            if (body.TryGetProperty("response_types", out var responseTypesElement)
                && responseTypesElement.ValueKind == JsonValueKind.Array)
            {
                responseTypes = new List<string>();
                foreach (var rt in responseTypesElement.EnumerateArray())
                {
                    var rtStr = rt.GetString();
                    if (string.IsNullOrEmpty(rtStr) || !AllowedResponseTypes.Contains(rtStr))
                        return InvalidClientMetadata($"Unsupported response_type: {rtStr}");
                    responseTypes.Add(rtStr);
                }
            }

            // Parse token_endpoint_auth_method
            var authMethod = dcrConfig.AllowConfidentialClients ? "client_secret_post" : "none";
            if (body.TryGetProperty("token_endpoint_auth_method", out var authMethodElement)
                && authMethodElement.ValueKind == JsonValueKind.String)
            {
                authMethod = authMethodElement.GetString() ?? "none";
                if (!AllowedAuthMethods.Contains(authMethod))
                    return InvalidClientMetadata($"Unsupported token_endpoint_auth_method: {authMethod}");
            }

            if (authMethod == "client_secret_post" && !dcrConfig.AllowConfidentialClients)
                return InvalidClientMetadata("Confidential clients (client_secret_post) are not allowed. Set AllowConfidentialClients to true in configuration to enable this.");

            // Parse scope
            var scopes = new List<string>(dcrConfig.AllowedScopes);
            if (body.TryGetProperty("scope", out var scopeElement)
                && scopeElement.ValueKind == JsonValueKind.String)
            {
                var scopeStr = scopeElement.GetString() ?? "";
                var requestedScopes = scopeStr.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                foreach (var s in requestedScopes)
                {
                    if (!dcrConfig.AllowedScopes.Contains(s))
                        return InvalidClientMetadata($"Scope not allowed: {s}");
                }
                scopes = requestedScopes.ToList();
            }

            // Parse optional fields
            string? clientName = null;
            if (body.TryGetProperty("client_name", out var clientNameElement)
                && clientNameElement.ValueKind == JsonValueKind.String)
            {
                clientName = clientNameElement.GetString();
            }

            string? clientUri = null;
            if (body.TryGetProperty("client_uri", out var clientUriElement)
                && clientUriElement.ValueKind == JsonValueKind.String)
            {
                clientUri = clientUriElement.GetString();
            }

            // Generate new credentials
            var isConfidential = authMethod != "none";
            var newClientSecret = isConfidential ? GenerateRandomString(32) : null;
            var newRegistrationAccessToken = GenerateRandomString(32);

            var jwtConfig = context.RequestServices.GetRequiredService<JwtConfig>();
            var registrationClientUri = $"{jwtConfig.Issuer}/connect/register/{clientId}";

            var updated = new ClientRegistration
            {
                ClientId = clientId,
                TokenEndpointAuthMethod = authMethod,
                GrantTypes = grantTypes,
                ResponseTypes = responseTypes,
                RedirectUris = redirectUris,
                Scopes = scopes,
                ClientName = clientName,
                ClientUri = clientUri,
                RegistrationClientUri = registrationClientUri
            };

            var result = clientStore.UpdateClient(clientId, token, updated, newClientSecret, newRegistrationAccessToken);
            if (result == null)
                return Results.Json(new { error = "invalid_token" }, statusCode: 401);

            // Build response
            var response = new Dictionary<string, object>
            {
                ["client_id"] = clientId,
                ["client_id_issued_at"] = new DateTimeOffset(result.CreatedAt).ToUnixTimeSeconds(),
                ["registration_access_token"] = newRegistrationAccessToken,
                ["registration_client_uri"] = registrationClientUri,
                ["redirect_uris"] = redirectUris,
                ["grant_types"] = grantTypes,
                ["response_types"] = responseTypes,
                ["token_endpoint_auth_method"] = authMethod,
                ["scope"] = string.Join(" ", scopes)
            };

            if (isConfidential)
            {
                response["client_secret"] = newClientSecret!;
                response["client_secret_expires_at"] = 0;
            }

            if (clientName != null)
                response["client_name"] = clientName;

            return Results.Json(response, SnakeCaseOptions);
        });

        // DELETE /connect/register/{clientId} — RFC 7592 delete
        app.MapDelete("/connect/register/{clientId}", (HttpContext context, string clientId) =>
        {
            var dcrConfig = context.RequestServices.GetRequiredService<DynamicClientRegistrationConfig>();
            if (!dcrConfig.Enabled)
                return Results.NotFound();

            var clientStore = context.RequestServices.GetRequiredService<IClientStore>();
            var existingClient = clientStore.GetClient(clientId);
            if (existingClient == null)
                return Results.NotFound();

            if (!existingClient.IsDynamic)
                return Results.Json(new { error = "forbidden", error_description = "Static clients cannot be managed" }, statusCode: 403);

            var token = ExtractBearerToken(context);
            if (string.IsNullOrEmpty(token))
                return Results.Json(new { error = "invalid_token" }, statusCode: 401);

            var deleted = clientStore.DeleteClient(clientId, token);
            if (!deleted)
                return Results.Json(new { error = "invalid_token" }, statusCode: 401);

            // Revoke all refresh tokens for this client
            var refreshTokenStore = context.RequestServices.GetRequiredService<IRefreshTokenStore>();
            refreshTokenStore.RevokeTokensByClientId(clientId);

            return Results.NoContent();
        });
    }

    private static string? ExtractBearerToken(HttpContext context)
    {
        var authHeader = context.Request.Headers["Authorization"].FirstOrDefault();
        if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            return null;

        return authHeader["Bearer ".Length..].Trim();
    }

    private static async Task<JsonElement?> ReadJsonBody(HttpContext context)
    {
        try
        {
            using var reader = new StreamReader(context.Request.Body);
            var body = await reader.ReadToEndAsync();
            return JsonSerializer.Deserialize<JsonElement>(body);
        }
        catch
        {
            return null;
        }
    }

    private static IResult InvalidClientMetadata(string description)
    {
        return Results.BadRequest(new { error = "invalid_client_metadata", error_description = description });
    }

    private static string GenerateRandomString(int byteLength)
    {
        var bytes = new byte[byteLength];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(bytes);
        return Convert.ToBase64String(bytes)
            .Replace("+", "-")
            .Replace("/", "_")
            .Replace("=", "");
    }
}
