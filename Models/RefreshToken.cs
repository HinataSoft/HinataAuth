namespace HinataAuth.Models;

public class RefreshToken
{
    public string Token { get; set; } = string.Empty;
    public string ClientId { get; set; } = string.Empty;
    public string? UserId { get; set; }
    public string Scope { get; set; } = string.Empty;
    public DateTime ExpiresAt { get; set; }
    public bool Used { get; set; }
    public bool Revoked { get; set; }
    public DateTime CreatedAt { get; set; }
}
