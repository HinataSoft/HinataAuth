using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Web;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace HinataAuth.Tests;

[Collection("SharedTestCollection")]
public class DynamicClientRegistrationTests
{
    private readonly SharedTestFixture _fixture;
    private readonly HttpClient _client;

    public DynamicClientRegistrationTests(SharedTestFixture fixture)
    {
        _fixture = fixture;
        _client = _fixture.Factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });
    }

    // ==================== Registration Tests ====================

    [Fact]
    public async Task Register_ConfidentialClient_Returns201WithSecretAndManagementUri()
    {
        var reg = await RegisterTestClient("confidential-test");

        Assert.True(reg.TryGetProperty("client_id", out var clientId));
        Assert.False(string.IsNullOrEmpty(clientId.GetString()));

        Assert.True(reg.TryGetProperty("client_secret", out var clientSecret));
        Assert.False(string.IsNullOrEmpty(clientSecret.GetString()));

        Assert.True(reg.TryGetProperty("registration_access_token", out var rat));
        Assert.False(string.IsNullOrEmpty(rat.GetString()));

        Assert.True(reg.TryGetProperty("registration_client_uri", out var regUri));
        Assert.Contains($"/connect/register/{clientId.GetString()}", regUri.GetString());

        Assert.True(reg.TryGetProperty("client_id_issued_at", out var issuedAt));
        Assert.True(issuedAt.GetInt64() > 0);

        Assert.True(reg.TryGetProperty("client_secret_expires_at", out var secretExpires));
        Assert.Equal(0, secretExpires.GetInt32());

        Assert.Equal("client_secret_post", reg.GetProperty("token_endpoint_auth_method").GetString());
        Assert.Equal("profile email", reg.GetProperty("scope").GetString());
    }

    [Fact]
    public async Task Register_PublicClient_Returns201WithoutSecret()
    {
        var request = new
        {
            client_name = "public-test",
            redirect_uris = new[] { "http://localhost:9999/callback" },
            grant_types = new[] { "authorization_code" },
            response_types = new[] { "code" },
            token_endpoint_auth_method = "none",
            scope = "profile email"
        };
        var response = await PostRegistration(request);
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);

        var reg = await ParseJson(response);

        Assert.True(reg.TryGetProperty("client_id", out _));
        Assert.False(reg.TryGetProperty("client_secret", out _));
        Assert.Equal("none", reg.GetProperty("token_endpoint_auth_method").GetString());
    }

    [Fact]
    public async Task Register_MissingRedirectUris_ReturnsBadRequest()
    {
        var request = new
        {
            client_name = "no-redirect"
        };
        var response = await PostRegistration(request);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);

        var body = await ParseJson(response);
        Assert.Equal("invalid_client_metadata", body.GetProperty("error").GetString());
    }

    [Fact]
    public async Task Register_EmptyRedirectUris_ReturnsBadRequest()
    {
        var request = new
        {
            client_name = "empty-redirect",
            redirect_uris = Array.Empty<string>()
        };
        var response = await PostRegistration(request);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);

        var body = await ParseJson(response);
        Assert.Equal("invalid_client_metadata", body.GetProperty("error").GetString());
    }

    [Fact]
    public async Task Register_InvalidGrantType_ReturnsBadRequest()
    {
        var request = new
        {
            client_name = "bad-grant",
            redirect_uris = new[] { "http://localhost:9999/callback" },
            grant_types = new[] { "client_credentials" }
        };
        var response = await PostRegistration(request);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);

        var body = await ParseJson(response);
        Assert.Equal("invalid_client_metadata", body.GetProperty("error").GetString());
    }

    [Fact]
    public async Task Register_ScopeOutsideAllowlist_ReturnsBadRequest()
    {
        var request = new
        {
            client_name = "bad-scope",
            redirect_uris = new[] { "http://localhost:9999/callback" },
            scope = "admin secret"
        };
        var response = await PostRegistration(request);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);

        var body = await ParseJson(response);
        Assert.Equal("invalid_client_metadata", body.GetProperty("error").GetString());
    }

    [Fact]
    public async Task Register_InvalidAuthMethod_ReturnsBadRequest()
    {
        var request = new
        {
            client_name = "bad-auth",
            redirect_uris = new[] { "http://localhost:9999/callback" },
            token_endpoint_auth_method = "private_key_jwt"
        };
        var response = await PostRegistration(request);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);

        var body = await ParseJson(response);
        Assert.Equal("invalid_client_metadata", body.GetProperty("error").GetString());
    }

    [Fact]
    public async Task Register_ClientSecretBasic_Accepted()
    {
        var request = new
        {
            client_name = "basic-auth-client",
            redirect_uris = new[] { "http://localhost:9999/callback" },
            token_endpoint_auth_method = "client_secret_basic"
        };
        var response = await PostRegistration(request);
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);

        var reg = await ParseJson(response);
        Assert.Equal("client_secret_basic", reg.GetProperty("token_endpoint_auth_method").GetString());
        Assert.False(string.IsNullOrEmpty(reg.GetProperty("client_secret").GetString()));
    }

    [Fact]
    public async Task Register_DefaultsApplied_WhenFieldsOmitted()
    {
        var request = new
        {
            redirect_uris = new[] { "http://localhost:9999/callback" }
        };
        var response = await PostRegistration(request);
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);

        var reg = await ParseJson(response);

        // Default grant_types: ["authorization_code"]
        var grantTypes = reg.GetProperty("grant_types");
        Assert.Equal(1, grantTypes.GetArrayLength());
        Assert.Equal("authorization_code", grantTypes[0].GetString());

        // Default response_types: ["code"]
        var responseTypes = reg.GetProperty("response_types");
        Assert.Equal(1, responseTypes.GetArrayLength());
        Assert.Equal("code", responseTypes[0].GetString());

        // Default auth method: "client_secret_post"
        Assert.Equal("client_secret_post", reg.GetProperty("token_endpoint_auth_method").GetString());

        // Default scope: all allowed scopes
        var scope = reg.GetProperty("scope").GetString();
        Assert.Contains("auth", scope);
        Assert.Contains("profile", scope);
        Assert.Contains("email", scope);
    }

    // ==================== Management Tests ====================

    [Fact]
    public async Task Management_Get_ReturnsClientConfig()
    {
        var reg = await RegisterTestClient("get-test");
        var clientId = reg.GetProperty("client_id").GetString()!;
        var token = reg.GetProperty("registration_access_token").GetString()!;

        var request = new HttpRequestMessage(HttpMethod.Get, $"/connect/register/{clientId}");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        var response = await _client.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await ParseJson(response);

        Assert.Equal(clientId, body.GetProperty("client_id").GetString());
        Assert.True(body.TryGetProperty("client_id_issued_at", out _));
        Assert.True(body.TryGetProperty("redirect_uris", out _));
        Assert.True(body.TryGetProperty("grant_types", out _));
        Assert.True(body.TryGetProperty("scope", out _));
        Assert.Equal("get-test", body.GetProperty("client_name").GetString());

        // Should NOT contain secret or registration_access_token
        Assert.False(body.TryGetProperty("client_secret", out _));
        Assert.False(body.TryGetProperty("registration_access_token", out _));
    }

    [Fact]
    public async Task Management_Get_InvalidToken_Returns401()
    {
        var reg = await RegisterTestClient("invalid-token-test");
        var clientId = reg.GetProperty("client_id").GetString()!;

        var request = new HttpRequestMessage(HttpMethod.Get, $"/connect/register/{clientId}");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "totally-wrong-token");
        var response = await _client.SendAsync(request);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Management_Get_MissingToken_Returns401()
    {
        var reg = await RegisterTestClient("missing-token-test");
        var clientId = reg.GetProperty("client_id").GetString()!;

        var request = new HttpRequestMessage(HttpMethod.Get, $"/connect/register/{clientId}");
        // No Authorization header
        var response = await _client.SendAsync(request);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Management_Update_ReplacesClientAndRotatesToken()
    {
        var reg = await RegisterTestClient("update-test");
        var clientId = reg.GetProperty("client_id").GetString()!;
        var oldToken = reg.GetProperty("registration_access_token").GetString()!;

        // PUT with new data
        var updateBody = new
        {
            client_name = "updated-name",
            redirect_uris = new[] { "http://localhost:8888/new-callback" },
            grant_types = new[] { "authorization_code" },
            response_types = new[] { "code" },
            token_endpoint_auth_method = "client_secret_post",
            scope = "profile"
        };
        var json = JsonSerializer.Serialize(updateBody, new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower });
        var putRequest = new HttpRequestMessage(HttpMethod.Put, $"/connect/register/{clientId}")
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        };
        putRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", oldToken);
        var putResponse = await _client.SendAsync(putRequest);

        Assert.Equal(HttpStatusCode.OK, putResponse.StatusCode);
        var updated = await ParseJson(putResponse);

        // Verify update took effect
        Assert.Equal("updated-name", updated.GetProperty("client_name").GetString());
        Assert.Equal("profile", updated.GetProperty("scope").GetString());

        var newToken = updated.GetProperty("registration_access_token").GetString()!;
        Assert.NotEqual(oldToken, newToken);

        // Verify old token is invalidated — GET with old token should fail
        var getOldRequest = new HttpRequestMessage(HttpMethod.Get, $"/connect/register/{clientId}");
        getOldRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", oldToken);
        var getOldResponse = await _client.SendAsync(getOldRequest);
        Assert.Equal(HttpStatusCode.Unauthorized, getOldResponse.StatusCode);

        // Verify new token works
        var getNewRequest = new HttpRequestMessage(HttpMethod.Get, $"/connect/register/{clientId}");
        getNewRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", newToken);
        var getNewResponse = await _client.SendAsync(getNewRequest);
        Assert.Equal(HttpStatusCode.OK, getNewResponse.StatusCode);
    }

    [Fact]
    public async Task Management_Delete_Returns204AndRemovesClient()
    {
        var reg = await RegisterTestClient("delete-test");
        var clientId = reg.GetProperty("client_id").GetString()!;
        var token = reg.GetProperty("registration_access_token").GetString()!;

        // DELETE
        var deleteRequest = new HttpRequestMessage(HttpMethod.Delete, $"/connect/register/{clientId}");
        deleteRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        var deleteResponse = await _client.SendAsync(deleteRequest);
        Assert.Equal(HttpStatusCode.NoContent, deleteResponse.StatusCode);

        // Verify GET returns 404
        var getRequest = new HttpRequestMessage(HttpMethod.Get, $"/connect/register/{clientId}");
        getRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        var getResponse = await _client.SendAsync(getRequest);
        Assert.Equal(HttpStatusCode.NotFound, getResponse.StatusCode);
    }

    [Fact]
    public async Task Management_StaticClient_Returns403()
    {
        // "auth-client" is a static client defined in appsettings.Test.json
        var request = new HttpRequestMessage(HttpMethod.Get, "/connect/register/auth-client");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "some-token");
        var response = await _client.SendAsync(request);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    #region Discovery

    [Fact]
    public async Task Discovery_IncludesRegistrationEndpoint_WhenDcrEnabled()
    {
        var response = await _client.GetAsync("/.well-known/openid-configuration");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var json = await ParseJson(response);
        Assert.True(json.TryGetProperty("registration_endpoint", out var regEndpoint));
        Assert.Contains("/connect/register", regEndpoint.GetString()!);
    }

    [Fact]
    public async Task Discovery_IncludesNoneInAuthMethods_WhenDcrEnabled()
    {
        var response = await _client.GetAsync("/.well-known/openid-configuration");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var json = await ParseJson(response);
        var authMethods = json.GetProperty("token_endpoint_auth_methods_supported")
            .EnumerateArray()
            .Select(e => e.GetString())
            .ToList();
        Assert.Contains("none", authMethods);
        Assert.Contains("client_secret_post", authMethods);
    }

    #endregion

    #region Full Flow Integration

    [Fact]
    public async Task FullFlow_RegisterThenAuthorizeAndGetTokens()
    {
        // Step 1: Register a confidential dynamic client
        var reg = await RegisterTestClient("Full Flow Client");
        var clientId = reg.GetProperty("client_id").GetString()!;
        var clientSecret = reg.GetProperty("client_secret").GetString()!;
        var redirectUri = "http://localhost:9999/callback";

        // Step 2: Start authorization code flow
        var authorizeUri = $"/connect/authorize?response_type=code&client_id={clientId}&redirect_uri={Uri.EscapeDataString(redirectUri)}&scope=profile%20email";
        var authorizeResponse = await _client.GetAsync(authorizeUri);
        Assert.Equal(HttpStatusCode.Redirect, authorizeResponse.StatusCode);

        // Step 3: POST consent (approve)
        var formData = new FormUrlEncodedContent(new[]
        {
            new KeyValuePair<string, string>("response_type", "code"),
            new KeyValuePair<string, string>("client_id", clientId),
            new KeyValuePair<string, string>("redirect_uri", redirectUri),
            new KeyValuePair<string, string>("scope", "profile email"),
            new KeyValuePair<string, string>("consent", "approved"),
            new KeyValuePair<string, string>("username", "test-subject"),
            new KeyValuePair<string, string>("password", "test-secret")
        });
        var consentResponse = await _client.PostAsync("/connect/authorize", formData);
        Assert.Equal(HttpStatusCode.Redirect, consentResponse.StatusCode);

        // Extract authorization code from redirect
        var location = consentResponse.Headers.Location!;
        var query = HttpUtility.ParseQueryString(location.Query);
        var code = query["code"]!;
        Assert.False(string.IsNullOrEmpty(code));

        // Step 4: Exchange code for tokens
        var tokenForm = new FormUrlEncodedContent(new[]
        {
            new KeyValuePair<string, string>("grant_type", "authorization_code"),
            new KeyValuePair<string, string>("code", code),
            new KeyValuePair<string, string>("client_id", clientId),
            new KeyValuePair<string, string>("client_secret", clientSecret),
            new KeyValuePair<string, string>("redirect_uri", redirectUri)
        });
        var tokenResponse = await _client.PostAsync("/connect/token", tokenForm);
        Assert.Equal(HttpStatusCode.OK, tokenResponse.StatusCode);

        var tokenJson = await ParseJson(tokenResponse);
        Assert.True(tokenJson.TryGetProperty("access_token", out _));
        Assert.True(tokenJson.TryGetProperty("id_token", out _));
        Assert.True(tokenJson.TryGetProperty("refresh_token", out _));
        Assert.Equal("Bearer", tokenJson.GetProperty("token_type").GetString());
    }

    [Fact]
    public async Task FullFlow_PublicClientWithPKCE_RegisterThenAuthorize()
    {
        // Register a public client
        var regRequest = new
        {
            client_name = "PKCE Public Client",
            redirect_uris = new[] { "http://localhost:9998/callback" },
            grant_types = new[] { "authorization_code", "refresh_token" },
            token_endpoint_auth_method = "none",
            scope = "profile email"
        };
        var regResponse = await PostRegistration(regRequest);
        Assert.Equal(HttpStatusCode.Created, regResponse.StatusCode);
        var reg = await ParseJson(regResponse);
        var clientId = reg.GetProperty("client_id").GetString()!;
        var redirectUri = "http://localhost:9998/callback";

        // Generate PKCE challenge
        var codeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        using var sha256 = SHA256.Create();
        var challengeBytes = sha256.ComputeHash(Encoding.ASCII.GetBytes(codeVerifier));
        var codeChallenge = Convert.ToBase64String(challengeBytes)
            .Replace("+", "-").Replace("/", "_").Replace("=", "");

        // Authorize with PKCE
        var formData = new FormUrlEncodedContent(new[]
        {
            new KeyValuePair<string, string>("response_type", "code"),
            new KeyValuePair<string, string>("client_id", clientId),
            new KeyValuePair<string, string>("redirect_uri", redirectUri),
            new KeyValuePair<string, string>("scope", "profile email"),
            new KeyValuePair<string, string>("consent", "approved"),
            new KeyValuePair<string, string>("username", "test-subject"),
            new KeyValuePair<string, string>("password", "test-secret"),
            new KeyValuePair<string, string>("code_challenge", codeChallenge),
            new KeyValuePair<string, string>("code_challenge_method", "S256")
        });
        var consentResponse = await _client.PostAsync("/connect/authorize", formData);
        Assert.Equal(HttpStatusCode.Redirect, consentResponse.StatusCode);

        var location = consentResponse.Headers.Location!;
        var query = HttpUtility.ParseQueryString(location.Query);
        var code = query["code"]!;

        // Exchange code — no client_secret, use code_verifier
        var tokenForm = new FormUrlEncodedContent(new[]
        {
            new KeyValuePair<string, string>("grant_type", "authorization_code"),
            new KeyValuePair<string, string>("code", code),
            new KeyValuePair<string, string>("client_id", clientId),
            new KeyValuePair<string, string>("redirect_uri", redirectUri),
            new KeyValuePair<string, string>("code_verifier", codeVerifier)
        });
        var tokenResponse = await _client.PostAsync("/connect/token", tokenForm);
        Assert.Equal(HttpStatusCode.OK, tokenResponse.StatusCode);

        var tokenJson = await ParseJson(tokenResponse);
        Assert.True(tokenJson.TryGetProperty("access_token", out _));
        Assert.True(tokenJson.TryGetProperty("id_token", out _));
    }

    #endregion

    // ==================== Helpers ====================

    private async Task<HttpResponseMessage> PostRegistration(object request)
    {
        var json = JsonSerializer.Serialize(request, new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower });
        var content = new StringContent(json, Encoding.UTF8, "application/json");
        return await _client.PostAsync("/connect/register", content);
    }

    private static async Task<JsonElement> ParseJson(HttpResponseMessage response)
    {
        var body = await response.Content.ReadAsStringAsync();
        return JsonSerializer.Deserialize<JsonElement>(body);
    }

    private async Task<JsonElement> RegisterTestClient(string clientName, string authMethod = "client_secret_post")
    {
        var request = new
        {
            client_name = clientName,
            redirect_uris = new[] { "http://localhost:9999/callback" },
            grant_types = new[] { "authorization_code", "refresh_token" },
            response_types = new[] { "code" },
            token_endpoint_auth_method = authMethod,
            scope = "profile email"
        };
        var response = await PostRegistration(request);
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        return await ParseJson(response);
    }
}
