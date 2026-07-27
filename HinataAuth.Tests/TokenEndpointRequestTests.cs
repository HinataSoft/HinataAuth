using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace HinataAuth.Tests;

/// <summary>
/// Tests for token endpoint request parsing: client_secret_basic authentication
/// (RFC 6749 §2.3.1) and the non-standard JSON request body extension.
/// </summary>
[Collection("SharedTestCollection")]
public class TokenEndpointRequestTests
{
    private const string TestClientId = "test-subject";
    private const string TestClientSecret = "test-secret";

    private readonly HttpClient _client;

    public TokenEndpointRequestTests(SharedTestFixture fixture)
    {
        _client = fixture.Factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });
    }

    private static AuthenticationHeaderValue BasicHeader(string clientId, string clientSecret) =>
        new("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes($"{clientId}:{clientSecret}")));

    private static async Task<JsonElement> ParseJson(HttpResponseMessage response)
    {
        var content = await response.Content.ReadAsStringAsync();
        return JsonSerializer.Deserialize<JsonElement>(content);
    }

    [Fact]
    public async Task BasicAuth_ClientCredentials_ValidCredentials_ReturnsToken()
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "/connect/token")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                { "grant_type", "client_credentials" },
                { "scope", "auth" }
            })
        };
        request.Headers.Authorization = BasicHeader(TestClientId, TestClientSecret);

        var response = await _client.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var tokenResponse = await ParseJson(response);
        Assert.False(string.IsNullOrEmpty(tokenResponse.GetProperty("access_token").GetString()));
        Assert.Equal("auth", tokenResponse.GetProperty("scope").GetString());
    }

    [Fact]
    public async Task BasicAuth_UrlEncodedCredentials_AreDecoded()
    {
        // Per RFC 6749 §2.3.1 both id and secret are form-urlencoded before base64 encoding
        var request = new HttpRequestMessage(HttpMethod.Post, "/connect/token")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                { "grant_type", "client_credentials" }
            })
        };
        request.Headers.Authorization = BasicHeader("test%2Dsubject", "test%2Dsecret");

        var response = await _client.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task BasicAuth_InvalidSecret_Returns401WithWwwAuthenticate()
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "/connect/token")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                { "grant_type", "client_credentials" }
            })
        };
        request.Headers.Authorization = BasicHeader(TestClientId, "wrong-secret");

        var response = await _client.SendAsync(request);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Contains(response.Headers.WwwAuthenticate, h => h.Scheme == "Basic");
        var error = await ParseJson(response);
        Assert.Equal("invalid_client", error.GetProperty("error").GetString());
    }

    [Fact]
    public async Task BasicAuth_MalformedHeader_Returns401()
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "/connect/token")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                { "grant_type", "client_credentials" }
            })
        };
        // Not valid base64
        request.Headers.Authorization = new AuthenticationHeaderValue("Basic", "!!!not-base64!!!");

        var response = await _client.SendAsync(request);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        var error = await ParseJson(response);
        Assert.Equal("invalid_client", error.GetProperty("error").GetString());
    }

    [Fact]
    public async Task BasicAuth_CredentialsAlsoInBody_ReturnsInvalidRequest()
    {
        // RFC 6749 §2.3: client MUST NOT use more than one authentication method
        var request = new HttpRequestMessage(HttpMethod.Post, "/connect/token")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                { "grant_type", "client_credentials" },
                { "client_id", TestClientId },
                { "client_secret", TestClientSecret }
            })
        };
        request.Headers.Authorization = BasicHeader(TestClientId, TestClientSecret);

        var response = await _client.SendAsync(request);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var error = await ParseJson(response);
        Assert.Equal("invalid_request", error.GetProperty("error").GetString());
    }

    [Fact]
    public async Task JsonBody_ClientCredentials_ValidCredentials_ReturnsToken()
    {
        var json = JsonSerializer.Serialize(new
        {
            grant_type = "client_credentials",
            client_id = TestClientId,
            client_secret = TestClientSecret,
            scope = "auth"
        });
        var content = new StringContent(json, Encoding.UTF8, "application/json");

        var response = await _client.PostAsync("/connect/token", content);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var tokenResponse = await ParseJson(response);
        Assert.False(string.IsNullOrEmpty(tokenResponse.GetProperty("access_token").GetString()));
        Assert.Equal("auth", tokenResponse.GetProperty("scope").GetString());
    }

    [Fact]
    public async Task JsonBody_WithBasicAuth_ReturnsToken()
    {
        var json = JsonSerializer.Serialize(new
        {
            grant_type = "client_credentials",
            scope = "auth"
        });
        var request = new HttpRequestMessage(HttpMethod.Post, "/connect/token")
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        };
        request.Headers.Authorization = BasicHeader(TestClientId, TestClientSecret);

        var response = await _client.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var tokenResponse = await ParseJson(response);
        Assert.False(string.IsNullOrEmpty(tokenResponse.GetProperty("access_token").GetString()));
    }

    [Fact]
    public async Task JsonBody_MalformedJson_ReturnsInvalidRequest()
    {
        var content = new StringContent("{not valid json", Encoding.UTF8, "application/json");

        var response = await _client.PostAsync("/connect/token", content);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var error = await ParseJson(response);
        Assert.Equal("invalid_request", error.GetProperty("error").GetString());
    }

    [Fact]
    public async Task Discovery_AuthMethods_IncludeClientSecretBasic()
    {
        var response = await _client.GetAsync("/.well-known/openid-configuration");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var json = await ParseJson(response);
        var authMethods = json.GetProperty("token_endpoint_auth_methods_supported")
            .EnumerateArray()
            .Select(e => e.GetString())
            .ToList();
        Assert.Contains("client_secret_basic", authMethods);
    }
}
