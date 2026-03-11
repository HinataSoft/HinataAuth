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
}

public interface IAuthorizationCodeStore
{
    AuthorizationCode CreateCode(string clientId, string redirectUri, string scope, string? userId, Dictionary<string, string>? userClaims = null);
    AuthorizationCode? ConsumeCode(string code, string clientId, string redirectUri);
    bool ValidateClient(string clientId, string? clientSecret = null);
    string? GetScopes(string clientId);
    bool ValidateRedirectUri(string clientId, string redirectUri);
}

public class AuthorizationCodeStore : IAuthorizationCodeStore
{
    private readonly AuthorizationCodeConfig _config;
    private readonly Dictionary<string, AuthorizationCode> _codes = new();
    private readonly object _lock = new();

    public AuthorizationCodeStore(AuthorizationCodeConfig config)
    {
        _config = config;
    }

    public AuthorizationCode CreateCode(string clientId, string redirectUri, string scope, string? userId, Dictionary<string, string>? userClaims = null)
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
            Used = false
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
        var client = _config.Clients.FirstOrDefault(c => c.ClientId == clientId);
        if (client == null)
        {
            return false;
        }

        // If clientSecret is provided, validate it
        if (!string.IsNullOrEmpty(clientSecret))
        {
            return client.ClientSecret == clientSecret;
        }

        return true;
    }

    public string? GetScopes(string clientId)
    {
        var client = _config.Clients.FirstOrDefault(c => c.ClientId == clientId);
        return client?.Scopes;
    }

    public bool ValidateRedirectUri(string clientId, string redirectUri)
    {
        var client = _config.Clients.FirstOrDefault(c => c.ClientId == clientId);
        if (client == null)
        {
            return false;
        }

        // If no redirect URIs configured, use default
        if (client.RedirectUris.Count == 0 && !string.IsNullOrEmpty(_config.DefaultRedirectUri))
        {
            return redirectUri == _config.DefaultRedirectUri;
        }

        return client.RedirectUris.Contains(redirectUri);
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
