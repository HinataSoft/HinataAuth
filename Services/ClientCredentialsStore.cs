using HinataAuth.Models;

namespace HinataAuth.Services;

public interface IClientCredentialsStore
{
    bool ValidateClientCredentials(string clientId, string clientSecret);
    bool ValidateUserCredentials(string username, string password);
    string? GetScopes(string clientId);
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
}
