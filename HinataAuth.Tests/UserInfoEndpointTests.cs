using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace HinataAuth.Tests;

[Collection("SharedTestCollection")]
public class UserInfoEndpointTests : IClassFixture<CustomWebApplicationFactory<Program>>
{
    private readonly SharedTestFixture _fixture;
    private readonly HttpClient _client;

    private const string TestClientId = "auth-client";
    private const string TestClientSecret = "auth-secret";
    private const string TestRedirectUri = "http://localhost:3000/callback";
    private const string TestScope = "auth profile email";
    private const string TestUsername = "test-subject";
    private const string TestPassword = "test-secret";

    public UserInfoEndpointTests(SharedTestFixture fixture)
    {
        _fixture = fixture;
        _client = _fixture.Factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });
    }

    private async Task<string> GetAccessTokenAsync()
    {
        // Get authorization code
        var authorizeContent = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            { "response_type", "code" },
            { "client_id", TestClientId },
            { "redirect_uri", TestRedirectUri },
            { "scope", TestScope },
            { "consent", "approved" },
            { "username", TestUsername },
            { "password", TestPassword }
        });

        var authorizeResponse = await _client.PostAsync("/connect/authorize", authorizeContent);
        var location = authorizeResponse.Headers.Location?.ToString();
        var uri = new Uri(location!.StartsWith("http") ? location : "http://localhost" + location);
        var queryParams = System.Web.HttpUtility.ParseQueryString(uri.Query);
        var code = queryParams["code"]!;

        // Exchange for token
        var tokenRequest = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            { "grant_type", "authorization_code" },
            { "code", code },
            { "redirect_uri", TestRedirectUri },
            { "client_id", TestClientId },
            { "client_secret", TestClientSecret }
        });

        var tokenResponse = await _client.PostAsync("/connect/token", tokenRequest);
        var tokenContent = await tokenResponse.Content.ReadAsStringAsync();
        var tokenJson = JsonSerializer.Deserialize<JsonElement>(tokenContent);

        return tokenJson.GetProperty("access_token").GetString()!;
    }

    [Fact]
    public async Task UserInfo_NoToken_ReturnsUnauthorized()
    {
        // Act
        var response = await _client.GetAsync("/connect/userinfo");

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task UserInfo_NoToken_401IncludesWwwAuthenticate()
    {
        // Act
        var response = await _client.GetAsync("/connect/userinfo");

        // Assert - RFC 6750 §3: 401 must carry WWW-Authenticate: Bearer
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Contains(response.Headers.WwwAuthenticate, h => h.Scheme == "Bearer");
    }

    [Fact]
    public async Task UserInfo_Post_ValidToken_ReturnsUserInfo()
    {
        // Arrange - OIDC Core §5.3 requires POST support
        var accessToken = await GetAccessTokenAsync();
        var request = new HttpRequestMessage(HttpMethod.Post, "/connect/userinfo")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>())
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

        // Act
        var response = await _client.SendAsync(request);

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var content = await response.Content.ReadAsStringAsync();
        var userInfo = JsonSerializer.Deserialize<JsonElement>(content);

        Assert.Equal(TestUsername, userInfo.GetProperty("sub").GetString());
    }

    [Fact]
    public async Task UserInfo_ValidToken_ReturnsUserInfo()
    {
        // Arrange
        var accessToken = await GetAccessTokenAsync();
        _client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

        // Act
        var response = await _client.GetAsync("/connect/userinfo");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var content = await response.Content.ReadAsStringAsync();
        var userInfo = JsonSerializer.Deserialize<JsonElement>(content);

        Assert.Equal(TestUsername, userInfo.GetProperty("sub").GetString());
    }

    [Fact]
    public async Task UserInfo_ValidToken_ReturnsCustomClaims()
    {
        // Arrange
        var accessToken = await GetAccessTokenAsync();
        _client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

        // Act
        var response = await _client.GetAsync("/connect/userinfo");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var content = await response.Content.ReadAsStringAsync();
        var userInfo = JsonSerializer.Deserialize<JsonElement>(content);

        // Verify custom claims from configuration
        Assert.True(userInfo.TryGetProperty("name", out var name), $"No 'name' claim. Response: {content}");
        Assert.Equal("Test User", name.GetString());

        Assert.True(userInfo.TryGetProperty("email", out var email), $"No 'email' claim. Response: {content}");
        Assert.Equal("test@example.com", email.GetString());
    }

    [Fact]
    public async Task Discovery_IncludesUserInfoEndpoint()
    {
        // Act
        var response = await _client.GetAsync("/.well-known/openid-configuration");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var content = await response.Content.ReadAsStringAsync();
        var discovery = JsonSerializer.Deserialize<JsonElement>(content);

        Assert.True(discovery.TryGetProperty("userinfo_endpoint", out var userinfoEndpoint));
        Assert.Equal("HinataAuth/connect/userinfo", userinfoEndpoint.GetString());
    }
}
