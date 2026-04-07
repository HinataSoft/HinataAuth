namespace HinataAuth.Models;

public class DynamicClientRegistrationConfig
{
    public bool Enabled { get; set; } = false;
    public bool AllowConfidentialClients { get; set; } = false;
    public List<string> AllowedScopes { get; set; } = new();
    public string ClientStorePath { get; set; } = "run/clients.json";
}
