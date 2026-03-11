using HinataAuth.Models;

namespace HinataAuth.Services;

public interface IClientCredentialsStore
{
    bool ValidateClientCredentials(string clientId, string clientSecret);
    bool ValidateUserCredentials(string username, string password);
    string? GetScopes(string clientId);
    Dictionary<string, string> GetUserClaims(string userId);
}

public class ClientCredentialsStore : IClientCredentialsStore
{
    private readonly AuthCredentialsConfig _config;

    public ClientCredentialsStore(AuthCredentialsConfig config)
    {
        _config = config;
    }

    public bool ValidateClientCredentials(string clientId, string clientSecret)
        => ValidateCredentials(clientId, clientSecret);

    public bool ValidateUserCredentials(string username, string password)
        => ValidateCredentials(username, password);

    private bool ValidateCredentials(string id, string secret)
    {
        return _config.Credentials.Any(c => 
            c.Id == id && c.Secret == secret);
    }

    public string? GetScopes(string clientId)
    {
        var client = _config.Credentials.FirstOrDefault(c => c.Id == clientId);
        return client?.Scopes;
    }

    public Dictionary<string, string> GetUserClaims(string userId)
    {
        var credential = _config.Credentials.FirstOrDefault(c => c.Id == userId);
        return credential?.Claims ?? new Dictionary<string, string>();
    }
}
