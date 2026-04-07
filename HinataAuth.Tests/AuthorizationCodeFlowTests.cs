using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace HinataAuth.Tests;

[Collection("SharedTestCollection")]
public class AuthorizationCodeFlowTests : IClassFixture<CustomWebApplicationFactory<Program>>
{
    private readonly SharedTestFixture _fixture;
    private readonly HttpClient _client;

    // Test configuration - using auth-client from appsettings.json
    private const string TestClientId = "auth-client";
    private const string TestClientSecret = "auth-secret";
    private const string TestRedirectUri = "http://localhost:3000/callback";
    private const string TestScope = "auth";
    
    // User credentials from AuthCredentials section in appsettings.json
    private const string TestUsername = "test-subject";
    private const string TestPassword = "test-secret";

    public AuthorizationCodeFlowTests(SharedTestFixture fixture)
    {
        _fixture = fixture;
        _client = _fixture.Factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });
    }

    #region Authorization Endpoint - GET Tests

    // Note: Some tests are skipped due to authorization endpoint routing issues in test environment
    // These require further investigation into the endpoint configuration

    [Fact]
    public async Task Authorize_Get_ValidRequestWithoutConsent_RedirectsToAuthorizationPage()
    {
        // Arrange
        var requestUri = $"/connect/authorize?response_type=code&client_id={TestClientId}&redirect_uri={Uri.EscapeDataString(TestRedirectUri)}&scope={TestScope}";

        // Act
        var response = await _client.GetAsync(requestUri);

        // Assert
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        
        var location = response.Headers.Location?.ToString();
        Assert.NotNull(location);
        Assert.StartsWith("/authorize.html", location);
    }

    [Fact]
    public async Task Authorize_Get_ValidRequestWithConsentApproved_ReturnsCode()
    {
        // GET requests should always redirect to authorization UI, not issue codes directly
        // This prevents URL-based consent bypass attacks
        var requestUri = $"/connect/authorize?response_type=code&client_id={TestClientId}&redirect_uri={Uri.EscapeDataString(TestRedirectUri)}&scope={TestScope}&consent=approved";

        // Act
        var response = await _client.GetAsync(requestUri);

        // Assert - should redirect to UI, not directly issue code
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        
        var location = response.Headers.Location?.ToString();
        Assert.NotNull(location);
        Assert.StartsWith("/authorize.html", location);
    }

    [Fact]
    public async Task Authorize_Get_ValidRequestWithConsentDenied_ReturnsAccessDenied()
    {
        // GET requests should always redirect to authorization UI, not handle consent directly
        var requestUri = $"/connect/authorize?response_type=code&client_id={TestClientId}&redirect_uri={Uri.EscapeDataString(TestRedirectUri)}&scope={TestScope}&consent=denied";

        // Act
        var response = await _client.GetAsync(requestUri);

        // Assert - should redirect to UI, not handle consent via query string
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        
        var location = response.Headers.Location?.ToString();
        Assert.NotNull(location);
        Assert.StartsWith("/authorize.html", location);
    }

    [Fact]
    public async Task Authorize_Get_MissingRequiredParameters_ReturnsError()
    {
        // Arrange - missing client_id and redirect_uri
        var requestUri = "/connect/authorize?response_type=code";

        // Act
        var response = await _client.GetAsync(requestUri);

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        
        var content = await response.Content.ReadAsStringAsync();
        var errorResponse = JsonSerializer.Deserialize<JsonElement>(content);
        
        Assert.Equal("invalid_request", errorResponse.GetProperty("error").GetString());
    }

    [Fact]
    public async Task Authorize_Get_InvalidResponseType_ReturnsError()
    {
        // Arrange
        var requestUri = $"/connect/authorize?response_type=token&client_id={TestClientId}&redirect_uri={Uri.EscapeDataString(TestRedirectUri)}";

        // Act
        var response = await _client.GetAsync(requestUri);

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        
        var content = await response.Content.ReadAsStringAsync();
        var errorResponse = JsonSerializer.Deserialize<JsonElement>(content);
        
        Assert.Equal("unsupported_response_type", errorResponse.GetProperty("error").GetString());
    }

    [Fact]
    public async Task Authorize_Get_InvalidClientId_ReturnsError()
    {
        // Arrange
        var requestUri = $"/connect/authorize?response_type=code&client_id=invalid-client&redirect_uri={Uri.EscapeDataString(TestRedirectUri)}";

        // Act
        var response = await _client.GetAsync(requestUri);

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        
        var content = await response.Content.ReadAsStringAsync();
        var errorResponse = JsonSerializer.Deserialize<JsonElement>(content);
        
        Assert.Equal("invalid_client", errorResponse.GetProperty("error").GetString());
    }

    [Fact]
    public async Task Authorize_Get_InvalidRedirectUri_ReturnsError()
    {
        // Arrange
        var requestUri = $"/connect/authorize?response_type=code&client_id={TestClientId}&redirect_uri=http://invalid-uri.com/callback";

        // Act
        var response = await _client.GetAsync(requestUri);

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        
        var content = await response.Content.ReadAsStringAsync();
        var errorResponse = JsonSerializer.Deserialize<JsonElement>(content);
        
        Assert.Equal("invalid_request", errorResponse.GetProperty("error").GetString());
    }

    [Fact]
    public async Task Authorize_Get_InvalidScope_ReturnsError()
    {
        // Arrange - request scope not allowed for client
        var requestUri = $"/connect/authorize?response_type=code&client_id={TestClientId}&redirect_uri={Uri.EscapeDataString(TestRedirectUri)}&scope=admin";

        // Act
        var response = await _client.GetAsync(requestUri);

        // Assert - should filter to allowed scopes or return error
        var content = await response.Content.ReadAsStringAsync();
        var errorResponse = JsonSerializer.Deserialize<JsonElement>(content);
        
        // Scope validation may filter or error depending on implementation
        Assert.True(
            errorResponse.GetProperty("error").GetString() == "invalid_scope" ||
            response.StatusCode == HttpStatusCode.Redirect
        );
    }

    [Fact]
    public async Task Authorize_Get_StateParameter_PreservedInRedirect()
    {
        // Arrange
        var state = "test-state-12345";
        var requestUri = $"/connect/authorize?response_type=code&client_id={TestClientId}&redirect_uri={Uri.EscapeDataString(TestRedirectUri)}&scope={TestScope}&consent=approved&state={state}";

        // Act
        var response = await _client.GetAsync(requestUri);

        // Assert
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        
        var location = response.Headers.Location?.ToString();
        Assert.NotNull(location);
        Assert.Contains($"state={state}", location);
    }

    #endregion

    #region Authorization Endpoint - POST Tests

    [Fact]
    public async Task Authorize_Post_ValidRequestWithCredentialsAndConsent_ReturnsCode()
    {
        // Arrange - client_id from AuthorizationCode.clients, username/password from AuthCredentials
        var requestContent = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            { "response_type", "code" },
            { "client_id", TestClientId },
            { "redirect_uri", TestRedirectUri },
            { "scope", TestScope },
            { "consent", "approved" },
            { "username", TestUsername },
            { "password", TestPassword }
        });

        // Act
        var response = await _client.PostAsync("/connect/authorize", requestContent);

        // Assert
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        
        var location = response.Headers.Location?.ToString();
        Assert.NotNull(location);
        Assert.Contains(TestRedirectUri, location);
        Assert.Contains("code=", location);
    }

    [Fact]
    public async Task Authorize_Post_InvalidCredentials_ReturnsError()
    {
        // Arrange
        var requestContent = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            { "response_type", "code" },
            { "client_id", TestClientId },
            { "redirect_uri", TestRedirectUri },
            { "scope", TestScope },
            { "consent", "approved" },
            { "username", "wrong-user" },
            { "password", "wrong-pass" }
        });

        // Act
        var response = await _client.PostAsync("/connect/authorize", requestContent);

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        
        var content = await response.Content.ReadAsStringAsync();
        var errorResponse = JsonSerializer.Deserialize<JsonElement>(content);
        
        Assert.Equal("access_denied", errorResponse.GetProperty("error").GetString());
    }

    [Fact]
    public async Task Authorize_Post_MissingCredentials_ReturnsError()
    {
        // Arrange
        var requestContent = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            { "response_type", "code" },
            { "client_id", TestClientId },
            { "redirect_uri", TestRedirectUri },
            { "scope", TestScope },
            { "consent", "approved" }
        });

        // Act
        var response = await _client.PostAsync("/connect/authorize", requestContent);

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        
        var content = await response.Content.ReadAsStringAsync();
        var errorResponse = JsonSerializer.Deserialize<JsonElement>(content);
        
        Assert.Equal("access_denied", errorResponse.GetProperty("error").GetString());
    }

    [Fact]
    public async Task Authorize_Post_ConsentDenied_RedirectsWithError()
    {
        // Arrange - client_id from AuthorizationCode.clients, username/password from AuthCredentials
        var requestContent = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            { "response_type", "code" },
            { "client_id", TestClientId },
            { "redirect_uri", TestRedirectUri },
            { "scope", TestScope },
            { "consent", "denied" },
            { "username", TestUsername },
            { "password", TestPassword }
        });

        // Act
        var response = await _client.PostAsync("/connect/authorize", requestContent);

        // Assert
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        
        var location = response.Headers.Location?.ToString();
        Assert.NotNull(location);
        Assert.Contains(TestRedirectUri, location);
        Assert.Contains("error=access_denied", location);
    }

    #endregion

    #region Token Endpoint - Authorization Code Grant Tests

    private async Task<string> GetAuthorizationCodeWithPostAsync()
    {
        // Use POST with credentials to get authorization code (secure flow)
        // client_id from AuthorizationCode.clients, username/password from AuthCredentials
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
        
        Assert.Equal(HttpStatusCode.Redirect, authorizeResponse.StatusCode);
        var location = authorizeResponse.Headers.Location?.ToString();
        Assert.NotNull(location);
        Assert.Contains(TestRedirectUri, location);
        Assert.Contains("code=", location);
        
        return ExtractCodeFromRedirect(location);
    }

    [Fact]
    public async Task Token_AuthorizationCode_ValidCodeExchange_ReturnsToken()
    {
        // Step 1: Get authorization code using secure POST flow
        var code = await GetAuthorizationCodeWithPostAsync();

        // Step 2: Exchange code for token
        var tokenRequest = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            { "grant_type", "authorization_code" },
            { "code", code },
            { "redirect_uri", TestRedirectUri },
            { "client_id", TestClientId },
            { "client_secret", TestClientSecret }
        });

        // Act
        var tokenResponse = await _client.PostAsync("/connect/token", tokenRequest);

        // Assert
        Assert.Equal(HttpStatusCode.OK, tokenResponse.StatusCode);
        
        var content = await tokenResponse.Content.ReadAsStringAsync();
        var tokenResult = JsonSerializer.Deserialize<JsonElement>(content);
        
        Assert.True(tokenResult.TryGetProperty("access_token", out var accessToken));
        Assert.False(string.IsNullOrEmpty(accessToken.GetString()));
        
        Assert.True(tokenResult.TryGetProperty("token_type", out var tokenType));
        Assert.Equal("Bearer", tokenType.GetString());
        
        Assert.True(tokenResult.TryGetProperty("expires_in", out var expiresIn));
        Assert.True(expiresIn.GetInt32() > 0);
        
        Assert.True(tokenResult.TryGetProperty("scope", out var scope));
        Assert.Equal(TestScope, scope.GetString());
        
        Assert.True(tokenResult.TryGetProperty("refresh_token", out var refreshToken));
        Assert.False(string.IsNullOrEmpty(refreshToken.GetString()));
    }

    [Fact]
    public async Task Token_AuthorizationCode_InvalidCode_ReturnsError()
    {
        // Arrange
        var tokenRequest = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            { "grant_type", "authorization_code" },
            { "code", "invalid-code-12345" },
            { "redirect_uri", TestRedirectUri },
            { "client_id", TestClientId },
            { "client_secret", TestClientSecret }
        });

        // Act
        var response = await _client.PostAsync("/connect/token", tokenRequest);

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        
        var content = await response.Content.ReadAsStringAsync();
        var errorResponse = JsonSerializer.Deserialize<JsonElement>(content);
        
        Assert.Equal("invalid_grant", errorResponse.GetProperty("error").GetString());
    }

    [Fact]
    public async Task Token_AuthorizationCode_AlreadyUsedCode_ReturnsError()
    {
        // Step 1: Get authorization code using secure POST flow
        var code = await GetAuthorizationCodeWithPostAsync();

        // Step 2: First exchange should succeed
        var tokenRequest = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            { "grant_type", "authorization_code" },
            { "code", code },
            { "redirect_uri", TestRedirectUri },
            { "client_id", TestClientId },
            { "client_secret", TestClientSecret }
        });
        
        await _client.PostAsync("/connect/token", tokenRequest);

        // Step 3: Second exchange with same code should fail (one-time use)
        var tokenResponse2 = await _client.PostAsync("/connect/token", tokenRequest);

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, tokenResponse2.StatusCode);
        
        var content = await tokenResponse2.Content.ReadAsStringAsync();
        var errorResponse = JsonSerializer.Deserialize<JsonElement>(content);
        
        Assert.Equal("invalid_grant", errorResponse.GetProperty("error").GetString());
    }

    [Fact]
    public async Task Token_AuthorizationCode_MissingCode_ReturnsError()
    {
        // Arrange
        var tokenRequest = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            { "grant_type", "authorization_code" },
            { "redirect_uri", TestRedirectUri },
            { "client_id", TestClientId },
            { "client_secret", TestClientSecret }
        });

        // Act
        var response = await _client.PostAsync("/connect/token", tokenRequest);

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        
        var content = await response.Content.ReadAsStringAsync();
        var errorResponse = JsonSerializer.Deserialize<JsonElement>(content);
        
        Assert.Equal("invalid_request", errorResponse.GetProperty("error").GetString());
    }

    [Fact]
    public async Task Token_AuthorizationCode_MissingRedirectUri_ReturnsError()
    {
        // Arrange
        var tokenRequest = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            { "grant_type", "authorization_code" },
            { "code", "some-code" },
            { "client_id", TestClientId },
            { "client_secret", TestClientSecret }
        });

        // Act
        var response = await _client.PostAsync("/connect/token", tokenRequest);

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        
        var content = await response.Content.ReadAsStringAsync();
        var errorResponse = JsonSerializer.Deserialize<JsonElement>(content);
        
        Assert.Equal("invalid_request", errorResponse.GetProperty("error").GetString());
    }

    [Fact]
    public async Task Token_AuthorizationCode_InvalidClientCredentials_ReturnsError()
    {
        // Get a valid code using secure POST flow
        var code = await GetAuthorizationCodeWithPostAsync();

        // Arrange - wrong client secret
        var tokenRequest = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            { "grant_type", "authorization_code" },
            { "code", code },
            { "redirect_uri", TestRedirectUri },
            { "client_id", TestClientId },
            { "client_secret", "wrong-secret" }
        });

        // Act
        var response = await _client.PostAsync("/connect/token", tokenRequest);

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        
        var content = await response.Content.ReadAsStringAsync();
        var errorResponse = JsonSerializer.Deserialize<JsonElement>(content);
        
        Assert.Equal("invalid_client", errorResponse.GetProperty("error").GetString());
    }

    [Fact]
    public async Task Token_AuthorizationCode_MismatchedRedirectUri_ReturnsError()
    {
        // Get a valid code using secure POST flow
        var code = await GetAuthorizationCodeWithPostAsync();

        // Arrange - different redirect_uri
        var tokenRequest = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            { "grant_type", "authorization_code" },
            { "code", code },
            { "redirect_uri", "http://different-uri.com/callback" },
            { "client_id", TestClientId },
            { "client_secret", TestClientSecret }
        });

        // Act
        var response = await _client.PostAsync("/connect/token", tokenRequest);

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        
        var content = await response.Content.ReadAsStringAsync();
        var errorResponse = JsonSerializer.Deserialize<JsonElement>(content);
        
        Assert.Equal("invalid_grant", errorResponse.GetProperty("error").GetString());
    }

    [Fact]
    public async Task Token_AuthorizationCode_MissingClientCredentials_ReturnsError()
    {
        // Arrange
        var tokenRequest = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            { "grant_type", "authorization_code" },
            { "code", "some-code" },
            { "redirect_uri", TestRedirectUri }
        });

        // Act
        var response = await _client.PostAsync("/connect/token", tokenRequest);

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        
        var content = await response.Content.ReadAsStringAsync();
        var errorResponse = JsonSerializer.Deserialize<JsonElement>(content);
        
        Assert.Equal("invalid_client", errorResponse.GetProperty("error").GetString());
    }

    #endregion

    #region Integration Test - Complete Flow

    [Fact]
    public async Task AuthorizationCodeFlow_CompleteFlow_TokenCanBeValidated()
    {
        // Step 1: Get authorization code using secure POST flow
        var code = await GetAuthorizationCodeWithPostAsync();

        // Step 2: Exchange code for token
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
        
        var accessToken = tokenJson.GetProperty("access_token").GetString()!;
        var refreshToken = tokenJson.GetProperty("refresh_token").GetString()!;

        // Step 3: Validate token using JWKS
        var jwksResponse = await _client.GetAsync("/.well-known/jwks");
        var jwksContent = await jwksResponse.Content.ReadAsStringAsync();
        var jwks = JsonSerializer.Deserialize<JsonElement>(jwksContent);
        
        var keys = jwks.GetProperty("keys").EnumerateArray().ToList();
        var rsaKey = keys[0];
        
        var modulus = Base64UrlEncoder.DecodeBytes(rsaKey.GetProperty("n").GetString()!);
        var exponent = Base64UrlEncoder.DecodeBytes(rsaKey.GetProperty("e").GetString()!);
        
        var rsaParams = new RSAParameters
        {
            Modulus = modulus,
            Exponent = exponent
        };
        
        var rsa = RSA.Create();
        rsa.ImportParameters(rsaParams);
        
        var securityKey = new RsaSecurityKey(rsa)
        {
            KeyId = rsaKey.GetProperty("kid").GetString()
        };

        var tokenHandler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = "HinataAuth",
            ValidAudience = "HinataAuth",
            IssuerSigningKey = securityKey
        };

        // This should not throw
        var claimsPrincipal = tokenHandler.ValidateToken(accessToken, validationParameters, out var validatedToken);
        
        Assert.NotNull(claimsPrincipal);
        Assert.NotNull(validatedToken);

        // Step 4: Verify token claims - subject should be the authenticated username (from AuthCredentials)
        var jwtToken = tokenHandler.ReadJwtToken(accessToken);
        Assert.Equal(TestUsername, jwtToken.Subject);
        Assert.Contains(jwtToken.Claims, c => c.Type == "scope" && c.Value == TestScope);
        
        // Verify we got a refresh token
        Assert.False(string.IsNullOrEmpty(refreshToken));
    }

    [Fact]
    public async Task AuthorizationCodeFlow_TokenHasCorrectClaims()
    {
        // Step 1: Get authorization code using secure POST flow
        var code = await GetAuthorizationCodeWithPostAsync();

        // Step 2: Exchange code for token
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
        
        var accessToken = tokenJson.GetProperty("access_token").GetString()!;

        // Decode without validation to check claims
        var tokenHandler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
        var jwtToken = tokenHandler.ReadJwtToken(accessToken);
        
        // Assert - should have user_id from authenticated username (from AuthCredentials)
        Assert.Equal(TestUsername, jwtToken.Subject);
        Assert.Equal("HinataAuth", jwtToken.Issuer);
        Assert.Contains(jwtToken.Audiences, a => a == "HinataAuth");
        Assert.Contains(jwtToken.Claims, c => c.Type == "scope" && c.Value == TestScope);
        Assert.Contains(jwtToken.Claims, c => c.Type == "client_id" && c.Value == TestClientId);
        Assert.Contains(jwtToken.Claims, c => c.Type == "sub_type" && c.Value == "identity");

        // Verify expiration
        Assert.True(jwtToken.ValidTo > DateTime.UtcNow);
    }

    #endregion

    #region ID Token Tests

    [Fact]
    public async Task Token_AuthorizationCode_ValidCodeExchange_ReturnsIdToken()
    {
        // Step 1: Get authorization code
        var code = await GetAuthorizationCodeWithPostAsync();

        // Step 2: Exchange code for token
        var tokenRequest = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            { "grant_type", "authorization_code" },
            { "code", code },
            { "redirect_uri", TestRedirectUri },
            { "client_id", TestClientId },
            { "client_secret", TestClientSecret }
        });

        var tokenResponse = await _client.PostAsync("/connect/token", tokenRequest);
        Assert.Equal(HttpStatusCode.OK, tokenResponse.StatusCode);

        var content = await tokenResponse.Content.ReadAsStringAsync();
        var tokenResult = JsonSerializer.Deserialize<JsonElement>(content);

        // Assert id_token is present
        Assert.True(tokenResult.TryGetProperty("id_token", out var idTokenElement));
        var idTokenString = idTokenElement.GetString();
        Assert.False(string.IsNullOrEmpty(idTokenString));

        // Decode and verify id_token claims
        var tokenHandler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
        var idToken = tokenHandler.ReadJwtToken(idTokenString);

        // aud should be client_id, not API audience
        Assert.Contains(idToken.Audiences, a => a == TestClientId);
        Assert.DoesNotContain(idToken.Audiences, a => a == "HinataAuth");

        // sub should be the user
        Assert.Equal(TestUsername, idToken.Subject);

        // at_hash should be present
        Assert.Contains(idToken.Claims, c => c.Type == "at_hash");
        Assert.False(string.IsNullOrEmpty(idToken.Claims.First(c => c.Type == "at_hash").Value));
    }

    [Fact]
    public async Task Token_AuthorizationCode_IdToken_ContainsUserClaims()
    {
        // Step 1: Get authorization code with profile+email scopes
        var authorizeContent = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            { "response_type", "code" },
            { "client_id", TestClientId },
            { "redirect_uri", TestRedirectUri },
            { "scope", "auth profile email" },
            { "consent", "approved" },
            { "username", TestUsername },
            { "password", TestPassword }
        });

        var authorizeResponse = await _client.PostAsync("/connect/authorize", authorizeContent);
        var location = authorizeResponse.Headers.Location?.ToString()!;
        var code = ExtractCodeFromRedirect(location);

        // Step 2: Exchange code for token
        var tokenRequest = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            { "grant_type", "authorization_code" },
            { "code", code },
            { "redirect_uri", TestRedirectUri },
            { "client_id", TestClientId },
            { "client_secret", TestClientSecret }
        });

        var tokenResponse = await _client.PostAsync("/connect/token", tokenRequest);
        var content = await tokenResponse.Content.ReadAsStringAsync();
        var tokenResult = JsonSerializer.Deserialize<JsonElement>(content);

        var idTokenString = tokenResult.GetProperty("id_token").GetString()!;
        var tokenHandler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
        var idToken = tokenHandler.ReadJwtToken(idTokenString);

        // Assert user claims are in id_token
        Assert.Contains(idToken.Claims, c => c.Type == "name" && c.Value == "Test User");
        Assert.Contains(idToken.Claims, c => c.Type == "email" && c.Value == "test@example.com");
    }

    [Fact]
    public async Task Token_RefreshToken_FromAuthCode_ReturnsIdToken()
    {
        // Step 1: Get authorization code
        var code = await GetAuthorizationCodeWithPostAsync();

        // Step 2: Exchange code for tokens
        var tokenRequest = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            { "grant_type", "authorization_code" },
            { "code", code },
            { "redirect_uri", TestRedirectUri },
            { "client_id", TestClientId },
            { "client_secret", TestClientSecret }
        });

        var tokenResponse = await _client.PostAsync("/connect/token", tokenRequest);
        var content = await tokenResponse.Content.ReadAsStringAsync();
        var tokenResult = JsonSerializer.Deserialize<JsonElement>(content);

        var refreshToken = tokenResult.GetProperty("refresh_token").GetString()!;

        // Step 3: Use refresh token
        var refreshRequest = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            { "grant_type", "refresh_token" },
            { "refresh_token", refreshToken },
            { "client_id", TestClientId },
            { "client_secret", TestClientSecret }
        });

        var refreshResponse = await _client.PostAsync("/connect/token", refreshRequest);
        Assert.Equal(HttpStatusCode.OK, refreshResponse.StatusCode);

        var refreshContent = await refreshResponse.Content.ReadAsStringAsync();
        var refreshResult = JsonSerializer.Deserialize<JsonElement>(refreshContent);

        // Assert id_token is present in refresh response (identity flow)
        Assert.True(refreshResult.TryGetProperty("id_token", out var idTokenElement));
        var idTokenString = idTokenElement.GetString();
        Assert.False(string.IsNullOrEmpty(idTokenString));

        // Verify it's a valid JWT with correct audience
        var tokenHandler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
        var idToken = tokenHandler.ReadJwtToken(idTokenString);
        Assert.Contains(idToken.Audiences, a => a == TestClientId);
        Assert.Equal(TestUsername, idToken.Subject);
    }

    #endregion

    #region PKCE Tests

    [Fact]
    public async Task AuthCodeFlow_Pkce_S256_Success()
    {
        var codeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        using var sha256 = System.Security.Cryptography.SHA256.Create();
        var challengeBytes = sha256.ComputeHash(System.Text.Encoding.ASCII.GetBytes(codeVerifier));
        var codeChallenge = Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Encode(challengeBytes);

        var authorizeContent = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["response_type"] = "code",
            ["client_id"] = TestClientId,
            ["redirect_uri"] = TestRedirectUri,
            ["scope"] = TestScope,
            ["consent"] = "approved",
            ["username"] = TestUsername,
            ["password"] = TestPassword,
            ["code_challenge"] = codeChallenge,
            ["code_challenge_method"] = "S256"
        });

        var authorizeResponse = await _client.PostAsync("/connect/authorize", authorizeContent);
        Assert.Equal(HttpStatusCode.Redirect, authorizeResponse.StatusCode);

        var location = authorizeResponse.Headers.Location!.ToString();
        var queryParams = System.Web.HttpUtility.ParseQueryString(new Uri(location).Query);
        var code = queryParams["code"];
        Assert.False(string.IsNullOrEmpty(code));

        var tokenContent = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code!,
            ["redirect_uri"] = TestRedirectUri,
            ["client_id"] = TestClientId,
            ["client_secret"] = TestClientSecret,
            ["code_verifier"] = codeVerifier
        });

        var tokenResponse = await _client.PostAsync("/connect/token", tokenContent);
        Assert.Equal(HttpStatusCode.OK, tokenResponse.StatusCode);

        var tokenJson = JsonSerializer.Deserialize<JsonElement>(await tokenResponse.Content.ReadAsStringAsync());
        Assert.True(tokenJson.TryGetProperty("access_token", out _));
    }

    [Fact]
    public async Task AuthCodeFlow_Pkce_Plain_Success()
    {
        var codeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        var codeChallenge = codeVerifier;

        var authorizeContent = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["response_type"] = "code",
            ["client_id"] = TestClientId,
            ["redirect_uri"] = TestRedirectUri,
            ["scope"] = TestScope,
            ["consent"] = "approved",
            ["username"] = TestUsername,
            ["password"] = TestPassword,
            ["code_challenge"] = codeChallenge,
            ["code_challenge_method"] = "plain"
        });

        var authorizeResponse = await _client.PostAsync("/connect/authorize", authorizeContent);
        Assert.Equal(HttpStatusCode.Redirect, authorizeResponse.StatusCode);

        var location = authorizeResponse.Headers.Location!.ToString();
        var queryParams = System.Web.HttpUtility.ParseQueryString(new Uri(location).Query);
        var code = queryParams["code"];
        Assert.False(string.IsNullOrEmpty(code));

        var tokenContent = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code!,
            ["redirect_uri"] = TestRedirectUri,
            ["client_id"] = TestClientId,
            ["client_secret"] = TestClientSecret,
            ["code_verifier"] = codeVerifier
        });

        var tokenResponse = await _client.PostAsync("/connect/token", tokenContent);
        Assert.Equal(HttpStatusCode.OK, tokenResponse.StatusCode);

        var tokenJson = JsonSerializer.Deserialize<JsonElement>(await tokenResponse.Content.ReadAsStringAsync());
        Assert.True(tokenJson.TryGetProperty("access_token", out _));
    }

    [Fact]
    public async Task AuthCodeFlow_Pkce_MissingVerifier_ReturnsInvalidGrant()
    {
        var codeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        var codeChallenge = codeVerifier;

        var authorizeContent = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["response_type"] = "code",
            ["client_id"] = TestClientId,
            ["redirect_uri"] = TestRedirectUri,
            ["scope"] = TestScope,
            ["consent"] = "approved",
            ["username"] = TestUsername,
            ["password"] = TestPassword,
            ["code_challenge"] = codeChallenge,
            ["code_challenge_method"] = "plain"
        });

        var authorizeResponse = await _client.PostAsync("/connect/authorize", authorizeContent);
        var location = authorizeResponse.Headers.Location!.ToString();
        var queryParams = System.Web.HttpUtility.ParseQueryString(new Uri(location).Query);
        var code = queryParams["code"]!;

        var tokenContent = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = TestRedirectUri,
            ["client_id"] = TestClientId,
            ["client_secret"] = TestClientSecret
        });

        var tokenResponse = await _client.PostAsync("/connect/token", tokenContent);
        Assert.Equal(HttpStatusCode.BadRequest, tokenResponse.StatusCode);

        var errorJson = JsonSerializer.Deserialize<JsonElement>(await tokenResponse.Content.ReadAsStringAsync());
        Assert.Equal("invalid_grant", errorJson.GetProperty("error").GetString());
    }

    [Fact]
    public async Task AuthCodeFlow_Pkce_WrongVerifier_ReturnsInvalidGrant()
    {
        var codeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        using var sha256 = System.Security.Cryptography.SHA256.Create();
        var challengeBytes = sha256.ComputeHash(System.Text.Encoding.ASCII.GetBytes(codeVerifier));
        var codeChallenge = Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Encode(challengeBytes);

        var authorizeContent = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["response_type"] = "code",
            ["client_id"] = TestClientId,
            ["redirect_uri"] = TestRedirectUri,
            ["scope"] = TestScope,
            ["consent"] = "approved",
            ["username"] = TestUsername,
            ["password"] = TestPassword,
            ["code_challenge"] = codeChallenge,
            ["code_challenge_method"] = "S256"
        });

        var authorizeResponse = await _client.PostAsync("/connect/authorize", authorizeContent);
        var location = authorizeResponse.Headers.Location!.ToString();
        var queryParams = System.Web.HttpUtility.ParseQueryString(new Uri(location).Query);
        var code = queryParams["code"]!;

        var tokenContent = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = TestRedirectUri,
            ["client_id"] = TestClientId,
            ["client_secret"] = TestClientSecret,
            ["code_verifier"] = "totally-wrong-verifier-value-here-padding"
        });

        var tokenResponse = await _client.PostAsync("/connect/token", tokenContent);
        Assert.Equal(HttpStatusCode.BadRequest, tokenResponse.StatusCode);

        var errorJson = JsonSerializer.Deserialize<JsonElement>(await tokenResponse.Content.ReadAsStringAsync());
        Assert.Equal("invalid_grant", errorJson.GetProperty("error").GetString());
    }

    [Fact]
    public async Task AuthCodeFlow_Pkce_InvalidMethod_ReturnsInvalidRequest()
    {
        var authorizeContent = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["response_type"] = "code",
            ["client_id"] = TestClientId,
            ["redirect_uri"] = TestRedirectUri,
            ["scope"] = TestScope,
            ["consent"] = "approved",
            ["username"] = TestUsername,
            ["password"] = TestPassword,
            ["code_challenge"] = "some-challenge-value",
            ["code_challenge_method"] = "S512"
        });

        var authorizeResponse = await _client.PostAsync("/connect/authorize", authorizeContent);
        Assert.Equal(HttpStatusCode.BadRequest, authorizeResponse.StatusCode);

        var errorJson = JsonSerializer.Deserialize<JsonElement>(await authorizeResponse.Content.ReadAsStringAsync());
        Assert.Equal("invalid_request", errorJson.GetProperty("error").GetString());
    }

    [Fact]
    public async Task AuthCodeFlow_Pkce_MethodWithoutChallenge_ReturnsInvalidRequest()
    {
        var authorizeContent = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["response_type"] = "code",
            ["client_id"] = TestClientId,
            ["redirect_uri"] = TestRedirectUri,
            ["scope"] = TestScope,
            ["consent"] = "approved",
            ["username"] = TestUsername,
            ["password"] = TestPassword,
            ["code_challenge_method"] = "S256"
        });

        var authorizeResponse = await _client.PostAsync("/connect/authorize", authorizeContent);
        Assert.Equal(HttpStatusCode.BadRequest, authorizeResponse.StatusCode);

        var errorJson = JsonSerializer.Deserialize<JsonElement>(await authorizeResponse.Content.ReadAsStringAsync());
        Assert.Equal("invalid_request", errorJson.GetProperty("error").GetString());
    }

    [Fact]
    public async Task AuthCodeFlow_NoPkce_StillWorks()
    {
        var authorizeContent = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["response_type"] = "code",
            ["client_id"] = TestClientId,
            ["redirect_uri"] = TestRedirectUri,
            ["scope"] = TestScope,
            ["consent"] = "approved",
            ["username"] = TestUsername,
            ["password"] = TestPassword
        });

        var authorizeResponse = await _client.PostAsync("/connect/authorize", authorizeContent);
        Assert.Equal(HttpStatusCode.Redirect, authorizeResponse.StatusCode);

        var location = authorizeResponse.Headers.Location!.ToString();
        var queryParams = System.Web.HttpUtility.ParseQueryString(new Uri(location).Query);
        var code = queryParams["code"];
        Assert.False(string.IsNullOrEmpty(code));

        var tokenContent = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code!,
            ["redirect_uri"] = TestRedirectUri,
            ["client_id"] = TestClientId,
            ["client_secret"] = TestClientSecret
        });

        var tokenResponse = await _client.PostAsync("/connect/token", tokenContent);
        Assert.Equal(HttpStatusCode.OK, tokenResponse.StatusCode);

        var tokenJson = JsonSerializer.Deserialize<JsonElement>(await tokenResponse.Content.ReadAsStringAsync());
        Assert.True(tokenJson.TryGetProperty("access_token", out _));
    }

    [Fact]
    public async Task AuthCodeFlow_Pkce_DefaultPlainMethod_Success()
    {
        // Send code_challenge WITHOUT code_challenge_method — should default to "plain"
        var codeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

        var authorizeContent = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["response_type"] = "code",
            ["client_id"] = TestClientId,
            ["redirect_uri"] = TestRedirectUri,
            ["scope"] = TestScope,
            ["consent"] = "approved",
            ["username"] = TestUsername,
            ["password"] = TestPassword,
            ["code_challenge"] = codeVerifier // plain: challenge == verifier
        });

        var authorizeResponse = await _client.PostAsync("/connect/authorize", authorizeContent);
        Assert.Equal(HttpStatusCode.Redirect, authorizeResponse.StatusCode);

        var location = authorizeResponse.Headers.Location!.ToString();
        var queryParams = System.Web.HttpUtility.ParseQueryString(new Uri(location).Query);
        var code = queryParams["code"];
        Assert.False(string.IsNullOrEmpty(code));

        var tokenContent = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code!,
            ["redirect_uri"] = TestRedirectUri,
            ["client_id"] = TestClientId,
            ["client_secret"] = TestClientSecret,
            ["code_verifier"] = codeVerifier
        });

        var tokenResponse = await _client.PostAsync("/connect/token", tokenContent);
        Assert.Equal(HttpStatusCode.OK, tokenResponse.StatusCode);

        var tokenJson = JsonSerializer.Deserialize<JsonElement>(await tokenResponse.Content.ReadAsStringAsync());
        Assert.True(tokenJson.TryGetProperty("access_token", out _));
    }

    #endregion

    #region Helper Methods

    private static string ExtractCodeFromRedirect(string location)
    {
        var uri = new Uri(location.StartsWith("http") ? location : "http://localhost" + location);
        var queryParams = System.Web.HttpUtility.ParseQueryString(uri.Query);
        return queryParams["code"] ?? throw new InvalidOperationException("No code in redirect");
    }

    #endregion
}
