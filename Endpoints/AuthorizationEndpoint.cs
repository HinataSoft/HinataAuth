using System.Web;
using HinataAuth.Services;

namespace HinataAuth.Endpoints;

public static class AuthorizationEndpoint
{
    public static void MapAuthorizationEndpoint(this WebApplication app)
    {
        app.MapGet("/connect/authorize", HandleGet);
        app.MapPost("/connect/authorize", HandlePost);
    }

    private static IResult HandleGet(HttpContext context, IAuthorizationCodeStore codeStore, IConfiguration configuration)
    {
        // Parse query parameters
        var query = context.Request.Query;
        var responseType = query["response_type"].ToString();
        var clientId = query["client_id"].ToString();
        var redirectUri = query["redirect_uri"].ToString();
        var scope = query["scope"].ToString();
        var state = query["state"].ToString();
        var codeChallenge = query["code_challenge"].ToString();
        var codeChallengeMethod = query["code_challenge_method"].ToString();

        // Validate required parameters
        if (string.IsNullOrEmpty(responseType) || string.IsNullOrEmpty(clientId) || string.IsNullOrEmpty(redirectUri))
        {
            return Results.BadRequest(new
            {
                error = "invalid_request",
                error_description = "Missing required parameters: response_type, client_id, redirect_uri"
            });
        }

        // Only support code response type
        if (responseType != "code")
        {
            return Results.BadRequest(new
            {
                error = "unsupported_response_type",
                error_description = "Only response_type=code is supported"
            });
        }

        // Validate client
        if (!codeStore.ValidateClient(clientId))
        {
            return Results.BadRequest(new
            {
                error = "invalid_client",
                error_description = "Unknown client_id"
            });
        }

        // Validate redirect_uri
        if (!codeStore.ValidateRedirectUri(clientId, redirectUri))
        {
            return Results.BadRequest(new
            {
                error = "invalid_request",
                error_description = "Invalid redirect_uri"
            });
        }

        // Get configured scopes
        var configuredScopes = codeStore.GetScopes(clientId);
        var requestedScopes = string.IsNullOrEmpty(scope)
            ? configuredScopes?.Split(' ', StringSplitOptions.RemoveEmptyEntries).ToList() ?? new List<string>()
            : scope.Split(' ', StringSplitOptions.RemoveEmptyEntries).ToList();

        // Validate requested scopes are within allowed scopes
        if (!string.IsNullOrEmpty(configuredScopes))
        {
            var allowedScopes = configuredScopes.Split(' ', StringSplitOptions.RemoveEmptyEntries).ToHashSet();
            requestedScopes = requestedScopes.Where(s => allowedScopes.Contains(s)).ToList();

            if (requestedScopes.Count == 0)
            {
                return Results.BadRequest(new
                {
                    error = "invalid_scope",
                    error_description = "Invalid or missing scope"
                });
            }
        }

        // Validate PKCE parameters
        if (string.IsNullOrEmpty(codeChallenge) && !string.IsNullOrEmpty(codeChallengeMethod))
        {
            return Results.BadRequest(new
            {
                error = "invalid_request",
                error_description = "code_challenge_method requires code_challenge"
            });
        }

        // Default to "plain" per RFC 7636 §4.3
        if (!string.IsNullOrEmpty(codeChallenge) && string.IsNullOrEmpty(codeChallengeMethod))
        {
            codeChallengeMethod = "plain";
        }

        if (!string.IsNullOrEmpty(codeChallengeMethod)
            && codeChallengeMethod != "S256" && codeChallengeMethod != "plain")
        {
            return Results.BadRequest(new
            {
                error = "invalid_request",
                error_description = "Unsupported code_challenge_method. Supported: S256, plain"
            });
        }

        // GET requests should always redirect to the authorization UI
        // Consent decisions must be made via POST to prevent URL-based bypass
        var pathBase = configuration["PathBase"] ?? "";
        var authorizeUrl = $"{pathBase}/authorize.html?client_id={HttpUtility.UrlEncode(clientId)}&redirect_uri={HttpUtility.UrlEncode(redirectUri)}&scope={HttpUtility.UrlEncode(string.Join(" ", requestedScopes))}&state={HttpUtility.UrlEncode(state ?? "")}&response_type={HttpUtility.UrlEncode(responseType)}";
        if (!string.IsNullOrEmpty(codeChallenge))
        {
            authorizeUrl += $"&code_challenge={HttpUtility.UrlEncode(codeChallenge)}&code_challenge_method={HttpUtility.UrlEncode(codeChallengeMethod)}";
        }
        return Results.Redirect(authorizeUrl);
    }

    private static async Task<IResult> HandlePost(HttpContext context, IAuthorizationCodeStore codeStore, IClientCredentialsStore credentialsStore)
    {
        var form = await context.Request.ReadFormAsync();

        var responseType = form["response_type"].ToString();
        var clientId = form["client_id"].ToString();
        var redirectUri = form["redirect_uri"].ToString();
        var scope = form["scope"].ToString();
        var state = form["state"].ToString();
        var consent = form["consent"].ToString();
        var username = form["username"].ToString();
        var password = form["password"].ToString();
        var codeChallenge = form["code_challenge"].ToString();
        var codeChallengeMethod = form["code_challenge_method"].ToString();

        // Validate required parameters
        if (string.IsNullOrEmpty(responseType) || string.IsNullOrEmpty(clientId) || string.IsNullOrEmpty(redirectUri))
        {
            return Results.BadRequest(new
            {
                error = "invalid_request",
                error_description = "Missing required parameters"
            });
        }

        // Validate user credentials against AuthCredentials
        if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
        {
            return Results.BadRequest(new
            {
                error = "access_denied",
                error_description = "Username and password are required"
            });
        }

        // Validate credentials against AuthCredentials
        if (!credentialsStore.ValidateUserCredentials(username, password))
        {
            return Results.BadRequest(new
            {
                error = "access_denied",
                error_description = "Invalid username or password"
            });
        }

        // Only support code response type
        if (responseType != "code")
        {
            return Results.BadRequest(new
            {
                error = "unsupported_response_type",
                error_description = "Only response_type=code is supported"
            });
        }

        // Validate client
        if (!codeStore.ValidateClient(clientId))
        {
            return Results.BadRequest(new
            {
                error = "invalid_client",
                error_description = "Unknown client_id"
            });
        }

        // Validate redirect_uri
        if (!codeStore.ValidateRedirectUri(clientId, redirectUri))
        {
            return Results.BadRequest(new
            {
                error = "invalid_request",
                error_description = "Invalid redirect_uri"
            });
        }

        // Get configured scopes
        var configuredScopes = codeStore.GetScopes(clientId);
        var requestedScopes = string.IsNullOrEmpty(scope)
            ? configuredScopes?.Split(' ', StringSplitOptions.RemoveEmptyEntries).ToList() ?? new List<string>()
            : scope.Split(' ', StringSplitOptions.RemoveEmptyEntries).ToList();

        // Validate requested scopes
        if (!string.IsNullOrEmpty(configuredScopes))
        {
            var allowedScopes = configuredScopes.Split(' ', StringSplitOptions.RemoveEmptyEntries).ToHashSet();
            requestedScopes = requestedScopes.Where(s => allowedScopes.Contains(s)).ToList();
        }

        // Validate PKCE parameters
        if (string.IsNullOrEmpty(codeChallenge) && !string.IsNullOrEmpty(codeChallengeMethod))
        {
            return Results.BadRequest(new
            {
                error = "invalid_request",
                error_description = "code_challenge_method requires code_challenge"
            });
        }

        // Default to "plain" per RFC 7636 §4.3
        if (!string.IsNullOrEmpty(codeChallenge) && string.IsNullOrEmpty(codeChallengeMethod))
        {
            codeChallengeMethod = "plain";
        }

        if (!string.IsNullOrEmpty(codeChallengeMethod)
            && codeChallengeMethod != "S256" && codeChallengeMethod != "plain")
        {
            return Results.BadRequest(new
            {
                error = "invalid_request",
                error_description = "Unsupported code_challenge_method. Supported: S256, plain"
            });
        }

        // Handle denied consent
        if (consent != "approved")
        {
            var errorUri = new UriBuilder(redirectUri);
            var queryParams = HttpUtility.ParseQueryString(errorUri.Query);
            queryParams["error"] = "access_denied";
            queryParams["error_description"] = "The resource owner denied the request";
            if (!string.IsNullOrEmpty(state))
            {
                queryParams["state"] = state;
            }
            errorUri.Query = queryParams.ToString();
            return Results.Redirect(errorUri.ToString());
        }

        // User approved - create authorization code
        // Use the authenticated username as the userId
        var userId = username;

        // Get user claims from credentials store
        var userClaims = credentialsStore.GetUserClaims(username);

        // Create authorization code with user claims
        var authCode = codeStore.CreateCode(
            clientId, redirectUri, string.Join(" ", requestedScopes), userId, userClaims,
            string.IsNullOrEmpty(codeChallenge) ? null : codeChallenge,
            string.IsNullOrEmpty(codeChallengeMethod) ? null : codeChallengeMethod);

        // Build redirect URI with authorization code
        var redirectUriBuilder = new UriBuilder(redirectUri);
        var redirectQueryParams = HttpUtility.ParseQueryString(redirectUriBuilder.Query);
        redirectQueryParams["code"] = authCode.Code;
        if (!string.IsNullOrEmpty(state))
        {
            redirectQueryParams["state"] = state;
        }
        redirectUriBuilder.Query = redirectQueryParams.ToString();

        return Results.Redirect(redirectUriBuilder.ToString());
    }
}
