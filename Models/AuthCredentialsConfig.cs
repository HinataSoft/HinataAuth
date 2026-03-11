namespace HinataAuth.Models;

public class AuthCredentialsConfig
{
    public List<AuthCredential> Credentials { get; set; } = new();
}

public class AuthCredential
{
    public string Id { get; set; } = string.Empty;
    public string Secret { get; set; } = string.Empty;
    public string Scopes { get; set; } = string.Empty;
    public Dictionary<string, string> Claims { get; set; } = new();
}
