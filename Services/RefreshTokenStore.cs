using HinataAuth.Models;

namespace HinataAuth.Services;

public interface IRefreshTokenStore
{
    RefreshToken CreateToken(string clientId, string? userId, string scope, Dictionary<string, string>? userClaims = null);
    RefreshToken? ConsumeToken(string token, string clientId);
    bool RevokeToken(string token, string clientId);
    RefreshToken? GetToken(string token);
    void RevokeTokensByClientId(string clientId);
}

public class RefreshTokenStore : IRefreshTokenStore
{
    private readonly RefreshTokenConfig _config;
    private readonly Dictionary<string, RefreshToken> _tokens = new();
    private readonly object _lock = new();

    public RefreshTokenStore(RefreshTokenConfig config)
    {
        _config = config;
    }

    public RefreshToken CreateToken(string clientId, string? userId, string scope, Dictionary<string, string>? userClaims = null)
    {
        var token = new RefreshToken
        {
            Token = GenerateToken(),
            ClientId = clientId,
            UserId = userId,
            Scope = scope,
            UserClaims = userClaims ?? new Dictionary<string, string>(),
            ExpiresAt = DateTime.UtcNow.AddDays(_config.ExpirationDays),
            Used = false,
            Revoked = false,
            CreatedAt = DateTime.UtcNow
        };

        lock (_lock)
        {
            _tokens[token.Token] = token;
        }

        return token;
    }

    public RefreshToken? ConsumeToken(string token, string clientId)
    {
        lock (_lock)
        {
            if (!_tokens.TryGetValue(token, out var refreshToken))
            {
                return null;
            }

            // Check if expired
            if (refreshToken.ExpiresAt < DateTime.UtcNow)
            {
                _tokens.Remove(token);
                return null;
            }

            // Check if already used
            if (refreshToken.Used)
            {
                _tokens.Remove(token);
                return null;
            }

            // Check if revoked
            if (refreshToken.Revoked)
            {
                _tokens.Remove(token);
                return null;
            }

            // Validate client_id
            if (refreshToken.ClientId != clientId)
            {
                return null;
            }

            // Mark as used and remove (one-time use)
            refreshToken.Used = true;
            _tokens.Remove(token);

            return refreshToken;
        }
    }

    public bool RevokeToken(string token, string clientId)
    {
        lock (_lock)
        {
            if (!_tokens.TryGetValue(token, out var refreshToken))
            {
                return false;
            }

            // Validate client_id
            if (refreshToken.ClientId != clientId)
            {
                return false;
            }

            // Mark as revoked and remove
            refreshToken.Revoked = true;
            _tokens.Remove(token);

            return true;
        }
    }

    public RefreshToken? GetToken(string token)
    {
        lock (_lock)
        {
            return _tokens.TryGetValue(token, out var refreshToken) ? refreshToken : null;
        }
    }

    public void RevokeTokensByClientId(string clientId)
    {
        lock (_lock)
        {
            var tokensToRemove = _tokens
                .Where(kvp => kvp.Value.ClientId == clientId)
                .Select(kvp => kvp.Key)
                .ToList();

            foreach (var token in tokensToRemove)
            {
                _tokens.Remove(token);
            }
        }
    }

    private static string GenerateToken()
    {
        // Generate a cryptographically secure token
        var bytes = new byte[32];
        using var rng = System.Security.Cryptography.RandomNumberGenerator.Create();
        rng.GetBytes(bytes);
        return Convert.ToBase64String(bytes)
            .Replace("+", "-")
            .Replace("/", "_")
            .Replace("=", "");
    }
}
