using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Web;
using HinataAuth.Models;
using HinataAuth.Services;
using Microsoft.IdentityModel.Tokens;

namespace HinataAuth.Endpoints;

public static class TokenEndpoint
{
    public static void MapTokenEndpoint(this WebApplication app, SigningCredentials creds, JwtConfig jwtConfig)
    {
        app.MapPost("/connect/token", async (HttpContext context) =>
        {
            var credentialsStore = context.RequestServices.GetRequiredService<IClientCredentialsStore>();
            var codeStore = context.RequestServices.GetRequiredService<IAuthorizationCodeStore>();
            var refreshTokenStore = context.RequestServices.GetRequiredService<IRefreshTokenStore>();
            var jwtConfigSvc = context.RequestServices.GetRequiredService<JwtConfig>();
            var credsSvc = context.RequestServices.GetRequiredService<SigningCredentials>();
            
            // Read the body
            using var reader = new StreamReader(context.Request.Body);
            var body = await reader.ReadToEndAsync();
            
            // Parse form data
            var formData = HttpUtility.ParseQueryString(body);
            
            var grantType = formData["grant_type"] ?? "";
            var clientId = formData["client_id"] ?? "";
            var clientSecret = formData["client_secret"] ?? "";

            // Handle authorization_code grant type
            if (grantType == "authorization_code")
            {
                var result = HandleAuthorizationCodeGrant(codeStore, refreshTokenStore, jwtConfigSvc, credsSvc, formData, clientId, clientSecret);
                return result;
            }
            // Handle client_credentials grant type
            else if (grantType == "client_credentials")
            {
                var result = HandleClientCredentialGrant(credentialsStore, refreshTokenStore, jwtConfigSvc, credsSvc, formData, clientId, clientSecret);
                return result;
            }
            // Handle refresh_token grant type
            else if (grantType == "refresh_token")
            {
                var result = HandleRefreshTokenGrant(refreshTokenStore, jwtConfigSvc, credsSvc, formData, clientId, clientSecret);
                return result;
            }
            
            return Results.BadRequest(new
            {
                error = "unsupported_grant_type",
                error_description = "Only client_credentials, authorization_code, and refresh_token grant types are supported"
            });
        });
    }

    private static IResult HandleAuthorizationCodeGrant(IAuthorizationCodeStore codeStore, IRefreshTokenStore refreshTokenStore, JwtConfig jwtConfig, SigningCredentials creds, System.Collections.Specialized.NameValueCollection formData, string clientId, string clientSecret)
    {
        var code = formData["code"] ?? "";
        var redirectUri = formData["redirect_uri"] ?? "";

        // Validate required parameters
        if (string.IsNullOrEmpty(code) || string.IsNullOrEmpty(redirectUri))
        {
            return Results.BadRequest(new
            {
                error = "invalid_request",
                error_description = "Missing required parameters: code, redirect_uri"
            });
        }

        // Validate client credentials
        if (string.IsNullOrEmpty(clientId) || string.IsNullOrEmpty(clientSecret))
        {
            return Results.BadRequest(new
            {
                error = "invalid_client",
                error_description = "Client credentials required"
            });
        }

        // Consume the authorization code
        var authCode = codeStore.ConsumeCode(code, clientId, redirectUri);
        if (authCode == null)
        {
            return Results.BadRequest(new
            {
                error = "invalid_grant",
                error_description = "Invalid, expired, or already used authorization code"
            });
        }

        // Validate client credentials
        if (!codeStore.ValidateClient(clientId, clientSecret))
        {
            return Results.BadRequest(new
            {
                error = "invalid_client",
                error_description = "Invalid client credentials"
            });
        }

        // Get scopes from the authorization code
        var scopes = authCode.Scope.Split(' ', StringSplitOptions.RemoveEmptyEntries).ToList();
        var scopeString = string.Join(" ", scopes);

        // Create claims - include user_id from the authorization code
        var claims = new List<Claim>
            {
                new(JwtRegisteredClaimNames.Sub, authCode.UserId ?? clientId),
                new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new("client_id", clientId),
                new("sub_type", "identity")
            };

        // Add scope claims
        foreach (var scope in scopes)
        {
            claims.Add(new Claim("scope", scope));
        }

        // Add user claims from authorization code
        foreach (var claim in authCode.UserClaims)
        {
            claims.Add(new Claim(claim.Key, claim.Value));
        }

        // Create token
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.AddMinutes(jwtConfig.ExpirationMinutes),
            Issuer = jwtConfig.Issuer,
            Audience = jwtConfig.Audience,
            SigningCredentials = creds
        };

        var tokenHandler = new JwtSecurityTokenHandler();
        var token = tokenHandler.CreateToken(tokenDescriptor);
        var accessToken = tokenHandler.WriteToken(token);

        // Create refresh token (with rotation - new token each time)
        var refreshUserClaims = new Dictionary<string, string>(authCode.UserClaims)
        {
            ["sub_type"] = "identity"
        };
        var refreshToken = refreshTokenStore.CreateToken(clientId, authCode.UserId, scopeString, refreshUserClaims);

        // Generate id_token for identity flows (OIDC)
        var idToken = GenerateIdToken(
            authCode.UserId ?? clientId,
            clientId,
            authCode.UserClaims,
            accessToken,
            jwtConfig,
            creds);

        Console.WriteLine("Issued a token: " + accessToken);

        return Results.Ok(new
        {
            access_token = accessToken,
            id_token = idToken,
            token_type = "Bearer",
            expires_in = jwtConfig.ExpirationMinutes * 60,
            scope = scopeString,
            refresh_token = refreshToken.Token
        });
    }

    private static IResult HandleClientCredentialGrant(IClientCredentialsStore credentialsStore, IRefreshTokenStore refreshTokenStore, JwtConfig jwtConfig, SigningCredentials creds, System.Collections.Specialized.NameValueCollection formData, string clientId, string clientSecret)
    {
        // Validate client credentials
        if (!credentialsStore.ValidateClientCredentials(clientId, clientSecret))
        {
            return Results.BadRequest(new
            {
                error = "invalid_client",
                error_description = "Invalid client credentials"
            });
        }

        // Get configured scopes
        var requestedScope = formData["scope"] ?? "";
        var configuredScopes = credentialsStore.GetScopes(clientId);
        var clientScopes = string.IsNullOrEmpty(requestedScope)
            ? configuredScopes?.Split(' ', StringSplitOptions.RemoveEmptyEntries).ToList() ?? new List<string>()
            : requestedScope.Split(' ', StringSplitOptions.RemoveEmptyEntries).ToList();

        // If client has configured scopes, validate requested scopes are within those
        if (!string.IsNullOrEmpty(configuredScopes))
        {
            var allowedScopes = configuredScopes.Split(' ', StringSplitOptions.RemoveEmptyEntries).ToHashSet();
            clientScopes = clientScopes.Where(s => allowedScopes.Contains(s)).ToList();

            if (clientScopes.Count == 0 && !string.IsNullOrEmpty(requestedScope))
            {
                return Results.BadRequest(new
                {
                    error = "invalid_scope",
                    error_description = "Requested scope is not allowed for this client"
                });
            }
        }

        var scopeString = string.Join(" ", clientScopes);

        // Create claims
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, clientId),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new("client_id", clientId),
            new("sub_type", "client")
        };

        // Add scope claims
        foreach (var scopeItem in clientScopes)
        {
            claims.Add(new Claim("scope", scopeItem));
        }

        // Create token
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.AddMinutes(jwtConfig.ExpirationMinutes),
            Issuer = jwtConfig.Issuer,
            Audience = jwtConfig.Audience,
            SigningCredentials = creds
        };

        var tokenHandler = new JwtSecurityTokenHandler();
        var token = tokenHandler.CreateToken(tokenDescriptor);
        var accessToken = tokenHandler.WriteToken(token);

        // Create refresh token (with rotation - new token each time)
        var refreshToken = refreshTokenStore.CreateToken(clientId, null, scopeString, new Dictionary<string, string> { ["sub_type"] = "client" });

        return Results.Ok(new
        {
            access_token = accessToken,
            token_type = "Bearer",
            expires_in = jwtConfig.ExpirationMinutes * 60,
            scope = scopeString,
            refresh_token = refreshToken.Token
        });
    }

    private static string GenerateIdToken(
        string subject,
        string clientId,
        Dictionary<string, string> userClaims,
        string accessToken,
        JwtConfig jwtConfig,
        SigningCredentials creds)
    {
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, subject),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new("at_hash", ComputeAtHash(accessToken))
        };

        // Add user claims (name, email, etc.)
        foreach (var claim in userClaims)
        {
            // Skip internal claims that don't belong in id_token
            if (claim.Key == "sub_type")
                continue;
            claims.Add(new Claim(claim.Key, claim.Value));
        }

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.AddMinutes(jwtConfig.ExpirationMinutes),
            Issuer = jwtConfig.Issuer,
            Audience = clientId, // id_token audience is the client_id per OIDC spec
            SigningCredentials = creds
        };

        var tokenHandler = new JwtSecurityTokenHandler();
        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }

    private static string ComputeAtHash(string accessToken)
    {
        // at_hash = base64url(left half of SHA-256(access_token)) per OIDC Core §3.1.3.6
        var hash = SHA256.HashData(System.Text.Encoding.ASCII.GetBytes(accessToken));
        var leftHalf = hash[..(hash.Length / 2)];
        return Base64UrlEncoder.Encode(leftHalf);
    }

    private static IResult HandleRefreshTokenGrant(IRefreshTokenStore refreshTokenStore, JwtConfig jwtConfig, SigningCredentials creds, System.Collections.Specialized.NameValueCollection formData, string clientId, string clientSecret)
    {
        // Validate client credentials
        if (string.IsNullOrEmpty(clientId) || string.IsNullOrEmpty(clientSecret))
        {
            return Results.BadRequest(new
            {
                error = "invalid_client",
                error_description = "Client credentials required"
            });
        }

        // Get the refresh token
        var refreshTokenValue = formData["refresh_token"] ?? "";
        if (string.IsNullOrEmpty(refreshTokenValue))
        {
            return Results.BadRequest(new
            {
                error = "invalid_request",
                error_description = "Missing required parameter: refresh_token"
            });
        }

        // Consume the refresh token (validates and removes it - one-time use)
        var refreshToken = refreshTokenStore.ConsumeToken(refreshTokenValue, clientId);
        if (refreshToken == null)
        {
            return Results.BadRequest(new
            {
                error = "invalid_grant",
                error_description = "Invalid, expired, or already used refresh token"
            });
        }

        // Get scopes from the original refresh token
        var scopes = refreshToken.Scope.Split(' ', StringSplitOptions.RemoveEmptyEntries).ToList();
        var scopeString = string.Join(" ", scopes);

        // Create claims - use the subject from the original token (userId or clientId)
        var subject = refreshToken.UserId ?? clientId;
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, subject),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new("client_id", clientId)
        };

        // Add scope claims
        foreach (var scope in scopes)
        {
            claims.Add(new Claim("scope", scope));
        }

        // Add user claims from refresh token
        foreach (var claim in refreshToken.UserClaims)
        {
            claims.Add(new Claim(claim.Key, claim.Value));
        }

        // Create new access token
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.AddMinutes(jwtConfig.ExpirationMinutes),
            Issuer = jwtConfig.Issuer,
            Audience = jwtConfig.Audience,
            SigningCredentials = creds
        };

        var tokenHandler = new JwtSecurityTokenHandler();
        var token = tokenHandler.CreateToken(tokenDescriptor);
        var accessToken = tokenHandler.WriteToken(token);

        // Issue a new refresh token (refresh token rotation for security)
        var newRefreshToken = refreshTokenStore.CreateToken(clientId, refreshToken.UserId, scopeString, refreshToken.UserClaims);

        // Generate id_token for identity flows (originated from authorization code)
        var isIdentityFlow = refreshToken.UserClaims.TryGetValue("sub_type", out var subType) && subType == "identity";
        if (isIdentityFlow)
        {
            var idToken = GenerateIdToken(subject, clientId, refreshToken.UserClaims, accessToken, jwtConfig, creds);
            return Results.Ok(new
            {
                access_token = accessToken,
                id_token = idToken,
                token_type = "Bearer",
                expires_in = jwtConfig.ExpirationMinutes * 60,
                scope = scopeString,
                refresh_token = newRefreshToken.Token
            });
        }

        return Results.Ok(new
        {
            access_token = accessToken,
            token_type = "Bearer",
            expires_in = jwtConfig.ExpirationMinutes * 60,
            scope = scopeString,
            refresh_token = newRefreshToken.Token
        });
    }
}
