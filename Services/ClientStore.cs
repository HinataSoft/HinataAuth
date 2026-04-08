using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using HinataAuth.Models;

namespace HinataAuth.Services;

public interface IClientStore
{
    ClientRegistration? GetClient(string clientId);
    bool ValidateClient(string clientId, string? clientSecret);
    bool ValidateRedirectUri(string clientId, string redirectUri);
    List<string>? GetScopes(string clientId);
    ClientRegistration RegisterClient(ClientRegistration registration, string plaintextSecret, string plaintextRegistrationAccessToken);
    ClientRegistration? GetDynamicClient(string clientId, string registrationAccessToken);
    ClientRegistration? UpdateClient(string clientId, string registrationAccessToken, ClientRegistration updated, string? newPlaintextSecret, string newPlaintextRegistrationAccessToken);
    bool DeleteClient(string clientId, string registrationAccessToken);
}

public class ClientStore : IClientStore
{
    private readonly ConcurrentDictionary<string, ClientRegistration> _clients = new();
    private readonly string _storePath;
    private readonly object _writeLock = new();

    public ClientStore(AuthorizationCodeConfig authCodeConfig, DynamicClientRegistrationConfig dcrConfig)
    {
        _storePath = dcrConfig.ClientStorePath;

        // Load static clients from AuthorizationCode config
        foreach (var client in authCodeConfig.Clients)
        {
            var redirectUris = new List<string>(client.RedirectUris);
            if (redirectUris.Count == 0 && !string.IsNullOrEmpty(authCodeConfig.DefaultRedirectUri))
            {
                redirectUris.Add(authCodeConfig.DefaultRedirectUri);
            }

            var isPublic = string.IsNullOrEmpty(client.ClientSecret);
            var registration = new ClientRegistration
            {
                ClientId = client.ClientId,
                ClientSecretHash = isPublic ? null : HashSecret(client.ClientSecret),
                TokenEndpointAuthMethod = isPublic ? "none" : "client_secret_post",
                GrantTypes = new List<string> { "authorization_code", "refresh_token" },
                ResponseTypes = new List<string> { "code" },
                RedirectUris = redirectUris,
                Scopes = client.Scopes.Split(' ', StringSplitOptions.RemoveEmptyEntries).ToList(),
                IsDynamic = false,
                CreatedAt = DateTime.UtcNow
            };
            _clients[client.ClientId] = registration;
        }

        // Load dynamic clients from file
        LoadDynamicClients();
    }

    public ClientRegistration? GetClient(string clientId)
    {
        return _clients.TryGetValue(clientId, out var client) ? client : null;
    }

    public bool ValidateClient(string clientId, string? clientSecret)
    {
        if (!_clients.TryGetValue(clientId, out var client))
            return false;

        if (client.TokenEndpointAuthMethod == "none")
        {
            // Public client: succeed without secret, fail if secret provided
            return clientSecret == null;
        }

        // Confidential client: require and validate secret
        if (clientSecret == null)
            return false;

        var hash = HashSecret(clientSecret);
        return CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(hash),
            Encoding.UTF8.GetBytes(client.ClientSecretHash ?? ""));
    }

    public bool ValidateRedirectUri(string clientId, string redirectUri)
    {
        if (!_clients.TryGetValue(clientId, out var client))
            return false;

        return client.RedirectUris.Contains(redirectUri);
    }

    public List<string>? GetScopes(string clientId)
    {
        if (!_clients.TryGetValue(clientId, out var client))
            return null;

        return client.Scopes;
    }

    public ClientRegistration RegisterClient(ClientRegistration registration, string plaintextSecret, string plaintextRegistrationAccessToken)
    {
        registration.ClientSecretHash = string.IsNullOrEmpty(plaintextSecret) ? null : HashSecret(plaintextSecret);
        registration.RegistrationAccessTokenHash = HashSecret(plaintextRegistrationAccessToken);
        registration.IsDynamic = true;
        registration.CreatedAt = DateTime.UtcNow;

        lock (_writeLock)
        {
            _clients[registration.ClientId] = registration;
            PersistDynamicClientsUnsafe();
        }

        return registration;
    }

    public ClientRegistration? GetDynamicClient(string clientId, string registrationAccessToken)
    {
        if (!_clients.TryGetValue(clientId, out var client))
            return null;

        if (!client.IsDynamic)
            return null;

        if (!ValidateRegistrationAccessToken(client, registrationAccessToken))
            return null;

        return client;
    }

    public ClientRegistration? UpdateClient(string clientId, string registrationAccessToken, ClientRegistration updated, string? newPlaintextSecret, string newPlaintextRegistrationAccessToken)
    {
        if (!_clients.TryGetValue(clientId, out var existing))
            return null;

        if (!existing.IsDynamic)
            return null;

        if (!ValidateRegistrationAccessToken(existing, registrationAccessToken))
            return null;

        updated.ClientId = clientId;
        updated.IsDynamic = true;
        updated.CreatedAt = existing.CreatedAt;
        updated.ClientSecretHash = string.IsNullOrEmpty(newPlaintextSecret) ? null : HashSecret(newPlaintextSecret);
        updated.RegistrationAccessTokenHash = HashSecret(newPlaintextRegistrationAccessToken);

        lock (_writeLock)
        {
            _clients[clientId] = updated;
            PersistDynamicClientsUnsafe();
        }

        return updated;
    }

    public bool DeleteClient(string clientId, string registrationAccessToken)
    {
        if (!_clients.TryGetValue(clientId, out var client))
            return false;

        if (!client.IsDynamic)
            return false;

        if (!ValidateRegistrationAccessToken(client, registrationAccessToken))
            return false;

        lock (_writeLock)
        {
            _clients.TryRemove(clientId, out _);
            PersistDynamicClientsUnsafe();
        }

        return true;
    }

    private bool ValidateRegistrationAccessToken(ClientRegistration client, string token)
    {
        if (string.IsNullOrEmpty(client.RegistrationAccessTokenHash))
            return false;

        var hash = HashSecret(token);
        return CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(hash),
            Encoding.UTF8.GetBytes(client.RegistrationAccessTokenHash));
    }

    private void LoadDynamicClients()
    {
        if (!File.Exists(_storePath))
            return;

        try
        {
            var json = File.ReadAllText(_storePath);
            var stored = JsonSerializer.Deserialize<StoredClientList>(json, JsonOptions);
            if (stored?.Clients == null)
                return;

            foreach (var sc in stored.Clients)
            {
                var registration = new ClientRegistration
                {
                    ClientId = sc.ClientId,
                    ClientSecretHash = sc.ClientSecretHash,
                    TokenEndpointAuthMethod = sc.TokenEndpointAuthMethod,
                    GrantTypes = sc.GrantTypes,
                    ResponseTypes = sc.ResponseTypes,
                    RedirectUris = sc.RedirectUris,
                    Scopes = sc.Scopes,
                    ClientName = sc.ClientName,
                    ClientUri = sc.ClientUri,
                    IsDynamic = true,
                    CreatedAt = sc.CreatedAt,
                    RegistrationAccessTokenHash = sc.RegistrationAccessTokenHash
                };
                _clients[sc.ClientId] = registration;
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Warning: could not load dynamic clients from {_storePath}: {ex.Message}");
        }
    }

    private void PersistDynamicClientsUnsafe()
    {
        var dynamicClients = _clients.Values
            .Where(c => c.IsDynamic)
            .Select(c => new StoredClient
            {
                ClientId = c.ClientId,
                ClientSecretHash = c.ClientSecretHash,
                RegistrationAccessTokenHash = c.RegistrationAccessTokenHash,
                ClientName = c.ClientName,
                ClientUri = c.ClientUri,
                RedirectUris = c.RedirectUris,
                GrantTypes = c.GrantTypes,
                ResponseTypes = c.ResponseTypes,
                TokenEndpointAuthMethod = c.TokenEndpointAuthMethod,
                Scopes = c.Scopes,
                CreatedAt = c.CreatedAt
            })
            .ToList();

        var stored = new StoredClientList { Clients = dynamicClients };
        var json = JsonSerializer.Serialize(stored, JsonOptions);

        var dir = Path.GetDirectoryName(_storePath);
        if (dir != null) Directory.CreateDirectory(dir);

        var tempPath = _storePath + ".tmp";
        File.WriteAllText(tempPath, json);
        File.Move(tempPath, _storePath, overwrite: true);
    }

    internal static string HashSecret(string secret)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(secret));
        return Convert.ToBase64String(hash);
    }

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    private class StoredClientList
    {
        public List<StoredClient> Clients { get; set; } = new();
    }

    private class StoredClient
    {
        public string ClientId { get; set; } = string.Empty;
        public string? ClientSecretHash { get; set; }
        public string? RegistrationAccessTokenHash { get; set; }
        public string? ClientName { get; set; }
        public string? ClientUri { get; set; }
        public List<string> RedirectUris { get; set; } = new();
        public List<string> GrantTypes { get; set; } = new();
        public List<string> ResponseTypes { get; set; } = new();
        public string TokenEndpointAuthMethod { get; set; } = "client_secret_post";
        public List<string> Scopes { get; set; } = new();
        public DateTime CreatedAt { get; set; }
    }
}
