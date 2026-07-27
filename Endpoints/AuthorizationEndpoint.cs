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

    /// <summary>
    /// Validates client_id and redirect_uri. Errors here MUST NOT redirect to the
    /// redirect_uri (RFC 6749 §4.1.2.1) - they are returned directly instead.
    /// Returns null when both are valid.
    /// </summary>
    private static IResult? ValidateClientAndRedirectUri(IAuthorizationCodeStore codeStore, string clientId, string redirectUri)
    {
        if (string.IsNullOrEmpty(clientId) || string.IsNullOrEmpty(redirectUri))
        {
            return Results.BadRequest(new
            {
                error = "invalid_request",
                error_description = "Missing required parameters: client_id, redirect_uri"
            });
        }

        if (!codeStore.ValidateClient(clientId))
        {
            return Results.BadRequest(new
            {
                error = "invalid_client",
                error_description = "Unknown client_id"
            });
        }

        if (!codeStore.ValidateRedirectUri(clientId, redirectUri))
        {
            return Results.BadRequest(new
            {
                error = "invalid_request",
                error_description = "Invalid redirect_uri"
            });
        }

        return null;
    }

    /// <summary>
    /// Delivers an error to the client by redirecting to the validated redirect_uri
    /// with error, error_description and state parameters (RFC 6749 §4.1.2.1).
    /// </summary>
    private static IResult ErrorRedirect(string redirectUri, string? state, string error, string description)
    {
        var uriBuilder = new UriBuilder(redirectUri);
        var queryParams = HttpUtility.ParseQueryString(uriBuilder.Query);
        queryParams["error"] = error;
        queryParams["error_description"] = description;
        if (!string.IsNullOrEmpty(state))
        {
            queryParams["state"] = state;
        }
        uriBuilder.Query = queryParams.ToString();
        return Results.Redirect(uriBuilder.ToString());
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
        var nonce = query["nonce"].ToString();
        var codeChallenge = query["code_challenge"].ToString();
        var codeChallengeMethod = query["code_challenge_method"].ToString();

        // Client and redirect_uri first - their errors must not redirect
        var validationError = ValidateClientAndRedirectUri(codeStore, clientId, redirectUri);
        if (validationError != null)
        {
            return validationError;
        }

        // From here on, errors are delivered by redirect to the validated redirect_uri
        if (string.IsNullOrEmpty(responseType))
        {
            return ErrorRedirect(redirectUri, state, "invalid_request", "Missing required parameter: response_type");
        }

        // Only support code response type
        if (responseType != "code")
        {
            return ErrorRedirect(redirectUri, state, "unsupported_response_type", "Only response_type=code is supported");
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
                return ErrorRedirect(redirectUri, state, "invalid_scope", "Invalid or missing scope");
            }
        }

        // Validate PKCE parameters
        if (string.IsNullOrEmpty(codeChallenge) && !string.IsNullOrEmpty(codeChallengeMethod))
        {
            return ErrorRedirect(redirectUri, state, "invalid_request", "code_challenge_method requires code_challenge");
        }

        // Default to "plain" per RFC 7636 §4.3
        if (!string.IsNullOrEmpty(codeChallenge) && string.IsNullOrEmpty(codeChallengeMethod))
        {
            codeChallengeMethod = "plain";
        }

        if (!string.IsNullOrEmpty(codeChallengeMethod)
            && codeChallengeMethod != "S256" && codeChallengeMethod != "plain")
        {
            return ErrorRedirect(redirectUri, state, "invalid_request", "Unsupported code_challenge_method. Supported: S256, plain");
        }

        // GET requests should always redirect to the authorization UI
        // Consent decisions must be made via POST to prevent URL-based bypass
        var pathBase = configuration["PathBase"] ?? "";
        var authorizeUrl = $"{pathBase}/authorize.html?client_id={HttpUtility.UrlEncode(clientId)}&redirect_uri={HttpUtility.UrlEncode(redirectUri)}&scope={HttpUtility.UrlEncode(string.Join(" ", requestedScopes))}&state={HttpUtility.UrlEncode(state ?? "")}&response_type={HttpUtility.UrlEncode(responseType)}";
        if (!string.IsNullOrEmpty(nonce))
        {
            authorizeUrl += $"&nonce={HttpUtility.UrlEncode(nonce)}";
        }
        if (!string.IsNullOrEmpty(codeChallenge))
        {
            authorizeUrl += $"&code_challenge={HttpUtility.UrlEncode(codeChallenge)}&code_challenge_method={HttpUtility.UrlEncode(codeChallengeMethod)}";
        }
        return Results.Redirect(authorizeUrl);
    }

    private static async Task<IResult> HandlePost(HttpContext context, IAuthorizationCodeStore codeStore, IClientCredentialsStore credentialsStore, IConfiguration configuration)
    {
        var form = await context.Request.ReadFormAsync();

        var responseType = form["response_type"].ToString();
        var clientId = form["client_id"].ToString();
        var redirectUri = form["redirect_uri"].ToString();
        var scope = form["scope"].ToString();
        var state = form["state"].ToString();
        var nonce = form["nonce"].ToString();
        var consent = form["consent"].ToString();
        var username = form["username"].ToString();
        var password = form["password"].ToString();
        var codeChallenge = form["code_challenge"].ToString();
        var codeChallengeMethod = form["code_challenge_method"].ToString();

        // Build authorize.html redirect URL for error cases (form submissions can't display JSON)
        IResult RedirectBackWithError(string error)
        {
            var pathBase = configuration["PathBase"] ?? "";
            var qs = HttpUtility.ParseQueryString(string.Empty);
            qs["client_id"] = clientId;
            qs["redirect_uri"] = redirectUri;
            qs["scope"] = scope;
            qs["state"] = state;
            qs["response_type"] = responseType;
            if (!string.IsNullOrEmpty(nonce))
            {
                qs["nonce"] = nonce;
            }
            if (!string.IsNullOrEmpty(codeChallenge))
            {
                qs["code_challenge"] = codeChallenge;
                qs["code_challenge_method"] = codeChallengeMethod;
            }
            qs["error"] = error;
            return Results.Redirect($"{pathBase}/authorize.html?{qs}");
        }

        // Client and redirect_uri first - their errors must not redirect
        var validationError = ValidateClientAndRedirectUri(codeStore, clientId, redirectUri);
        if (validationError != null)
        {
            return validationError;
        }

        // Protocol errors are delivered by redirect to the validated redirect_uri
        if (string.IsNullOrEmpty(responseType))
        {
            return ErrorRedirect(redirectUri, state, "invalid_request", "Missing required parameter: response_type");
        }

        // Only support code response type
        if (responseType != "code")
        {
            return ErrorRedirect(redirectUri, state, "unsupported_response_type", "Only response_type=code is supported");
        }

        // Validate PKCE parameters
        if (string.IsNullOrEmpty(codeChallenge) && !string.IsNullOrEmpty(codeChallengeMethod))
        {
            return ErrorRedirect(redirectUri, state, "invalid_request", "code_challenge_method requires code_challenge");
        }

        // Default to "plain" per RFC 7636 §4.3
        if (!string.IsNullOrEmpty(codeChallenge) && string.IsNullOrEmpty(codeChallengeMethod))
        {
            codeChallengeMethod = "plain";
        }

        if (!string.IsNullOrEmpty(codeChallengeMethod)
            && codeChallengeMethod != "S256" && codeChallengeMethod != "plain")
        {
            return ErrorRedirect(redirectUri, state, "invalid_request", "Unsupported code_challenge_method. Supported: S256, plain");
        }

        // Validate user credentials against AuthCredentials; these errors go back
        // to the login page rather than to the client
        if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
        {
            return RedirectBackWithError("Username and password are required");
        }

        if (!credentialsStore.ValidateUserCredentials(username, password))
        {
            return RedirectBackWithError("Invalid username or password");
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
            string.IsNullOrEmpty(codeChallengeMethod) ? null : codeChallengeMethod,
            string.IsNullOrEmpty(nonce) ? null : nonce);

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
