using HinataAuth.Models;

namespace HinataAuth.Services;

public class AuthorizationCode
{
    public string Code { get; set; } = string.Empty;
    public string ClientId { get; set; } = string.Empty;
    public string RedirectUri { get; set; } = string.Empty;
    public string Scope { get; set; } = string.Empty;
    public string? UserId { get; set; }
    public Dictionary<string, string> UserClaims { get; set; } = new();
    public DateTime ExpiresAt { get; set; }
    public bool Used { get; set; }
    public string? CodeChallenge { get; set; }
    public string? CodeChallengeMethod { get; set; }
    public string? Nonce { get; set; }
}

public interface IAuthorizationCodeStore
{
    AuthorizationCode CreateCode(string clientId, string redirectUri, string scope, string? userId, Dictionary<string, string>? userClaims = null, string? codeChallenge = null, string? codeChallengeMethod = null, string? nonce = null);
    AuthorizationCode? ConsumeCode(string code, string clientId, string redirectUri);
    bool ValidateClient(string clientId, string? clientSecret = null);
    string? GetScopes(string clientId);
    bool ValidateRedirectUri(string clientId, string redirectUri);
}

public class AuthorizationCodeStore : IAuthorizationCodeStore
{
    private readonly AuthorizationCodeConfig _config;
    private readonly IClientStore _clientStore;
    private readonly Dictionary<string, AuthorizationCode> _codes = new();
    private readonly object _lock = new();

    public AuthorizationCodeStore(AuthorizationCodeConfig config, IClientStore clientStore)
    {
        _config = config;
        _clientStore = clientStore;
    }

    public AuthorizationCode CreateCode(string clientId, string redirectUri, string scope, string? userId, Dictionary<string, string>? userClaims = null, string? codeChallenge = null, string? codeChallengeMethod = null, string? nonce = null)
    {
        var code = new AuthorizationCode
        {
            Code = GenerateCode(),
            ClientId = clientId,
            RedirectUri = redirectUri,
            Scope = scope,
            UserId = userId,
            UserClaims = userClaims ?? new Dictionary<string, string>(),
            ExpiresAt = DateTime.UtcNow.AddMinutes(_config.CodeExpirationMinutes),
            Used = false,
            CodeChallenge = codeChallenge,
            CodeChallengeMethod = codeChallengeMethod,
            Nonce = nonce
        };

        lock (_lock)
        {
            _codes[code.Code] = code;
        }

        return code;
    }

    public AuthorizationCode? ConsumeCode(string code, string clientId, string redirectUri)
    {
        lock (_lock)
        {
            if (!_codes.TryGetValue(code, out var authCode))
            {
                return null;
            }

            // Check if expired
            if (authCode.ExpiresAt < DateTime.UtcNow)
            {
                _codes.Remove(code);
                return null;
            }

            // Check if already used
            if (authCode.Used)
            {
                // Revoke any tokens derived from this code if possible
                _codes.Remove(code);
                return null;
            }

            // Validate client_id and redirect_uri
            if (authCode.ClientId != clientId || authCode.RedirectUri != redirectUri)
            {
                return null;
            }

            // Mark as used
            authCode.Used = true;
            _codes.Remove(code);

            return authCode;
        }
    }

    public bool ValidateClient(string clientId, string? clientSecret = null)
    {
        // When no secret is provided (e.g. authorize endpoint checking existence),
        // just verify the client is registered rather than validating credentials.
        if (clientSecret == null)
            return _clientStore.GetClient(clientId) != null;

        return _clientStore.ValidateClient(clientId, clientSecret);
    }

    public string? GetScopes(string clientId)
    {
        var scopes = _clientStore.GetScopes(clientId);
        return scopes == null ? null : string.Join(" ", scopes);
    }

    public bool ValidateRedirectUri(string clientId, string redirectUri)
    {
        return _clientStore.ValidateRedirectUri(clientId, redirectUri);
    }

    private static string GenerateCode()
    {
        // Generate a cryptographically secure code
        var bytes = new byte[32];
        using var rng = System.Security.Cryptography.RandomNumberGenerator.Create();
        rng.GetBytes(bytes);
        return Convert.ToBase64String(bytes)
            .Replace("+", "-")
            .Replace("/", "_")
            .Replace("=", "");
    }
}
