namespace HinataAuth.Models;

public class JwtConfig
{
    public string Issuer { get; set; } = string.Empty;
    public string Audience { get; set; } = string.Empty;
    public int ExpirationMinutes { get; set; } = 60;
    
    // RSA Key configuration for JWKS
    public string KeyId { get; set; } = "hinata-auth-signing-key";
    
    // Path to the JWK file for persisting the RSA signing key
    public string JwkPath { get; set; } = "run/jwk.json";

    // Refresh token configuration
    public RefreshTokenConfig RefreshToken { get; set; } = new();
}
