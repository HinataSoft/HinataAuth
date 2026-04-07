namespace HinataAuth.Models;

public class ClientRegistration
{
    public string ClientId { get; set; } = string.Empty;
    public string? ClientSecretHash { get; set; }
    public string TokenEndpointAuthMethod { get; set; } = "client_secret_post";
    public List<string> GrantTypes { get; set; } = new();
    public List<string> ResponseTypes { get; set; } = new() { "code" };
    public List<string> RedirectUris { get; set; } = new();
    public List<string> Scopes { get; set; } = new();
    public string? ClientName { get; set; }
    public string? ClientUri { get; set; }
    public bool IsDynamic { get; set; }
    public DateTime CreatedAt { get; set; }
    public string? RegistrationAccessTokenHash { get; set; }
    public string? RegistrationClientUri { get; set; }
}
