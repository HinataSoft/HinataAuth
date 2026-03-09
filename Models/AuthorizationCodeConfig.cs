namespace HinataAuth.Models;

public class AuthorizationCodeConfig
{
    public List<AuthorizationCodeClient> Clients { get; set; } = new();
    public int CodeExpirationMinutes { get; set; } = 10;
    public string? DefaultRedirectUri { get; set; }
}

public class AuthorizationCodeClient
{
    public string ClientId { get; set; } = string.Empty;
    public string ClientSecret { get; set; } = string.Empty;
    public string Scopes { get; set; } = string.Empty;
    public List<string> RedirectUris { get; set; } = new();
}
