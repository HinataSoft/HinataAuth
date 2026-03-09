using System.Security.Cryptography;

using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

using HinataAuth.Endpoints;
using HinataAuth.Models;
using HinataAuth.Services;

namespace HinataAuth;

public class Program
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        // Load configuration
        var authCredentialsConfig = builder.Configuration.GetSection("AuthCredentials").Get<AuthCredentialsConfig>() 
            ?? new AuthCredentialsConfig();
        var authorizationCodeConfig = builder.Configuration.GetSection("AuthorizationCode").Get<AuthorizationCodeConfig>() 
            ?? new AuthorizationCodeConfig();
        var jwtConfig = builder.Configuration.GetSection("Jwt").Get<JwtConfig>() 
            ?? new JwtConfig();
        var refreshTokenConfig = jwtConfig.RefreshToken ?? new RefreshTokenConfig();

        // Generate RSA key for JWT signing and JWKS
        var rsaKey = RSA.Create(2048);
        var rsaSecurityKey = new RsaSecurityKey(rsaKey)
        {
            KeyId = jwtConfig.KeyId
        };
        var creds = new SigningCredentials(rsaSecurityKey, SecurityAlgorithms.RsaSha256);

        // Register services
        builder.Services.AddSingleton(authCredentialsConfig);
        builder.Services.AddSingleton(authorizationCodeConfig);
        builder.Services.AddSingleton(jwtConfig);
        builder.Services.AddSingleton(refreshTokenConfig);
        builder.Services.AddSingleton<IClientCredentialsStore, ClientCredentialsStore>();
        builder.Services.AddSingleton<IAuthorizationCodeStore, AuthorizationCodeStore>();
        builder.Services.AddSingleton<IRefreshTokenStore, RefreshTokenStore>();
        builder.Services.AddSingleton(creds);

        // Initialize JWKS endpoint with RSA key
        JwksEndpoint.InitializeRsaKey(rsaKey, jwtConfig.KeyId);

        // Configure JWT Authentication
        builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(options =>
            {
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = jwtConfig.Issuer,
                    ValidAudience = jwtConfig.Audience,
                    IssuerSigningKey = rsaSecurityKey
                };
            });

        builder.Services.AddAuthorization();

        builder.Services.AddCors(options =>
        {
            options.AddPolicy("AllowAll", policy =>
            {
                policy.AllowAnyOrigin()
                      .AllowAnyMethod()
                      .AllowAnyHeader();
            });
        });

        var app = builder.Build();

        // Set issuer to first server URL if not explicitly configured in appsettings.json
        if (string.IsNullOrEmpty(jwtConfig.Issuer))
        {
            var serverUrl = app.Urls.First();
            // Convert to URL format (remove any path)
            var uri = new Uri(serverUrl);
            jwtConfig.Issuer = $"{uri.Scheme}://{uri.Host}:{uri.Port}";
        }

        // Enable request form parsing for token and authorization endpoints
        // This must run before routing to ensure body is available to endpoints
        app.Use(async (context, next) =>
        {
            if (context.Request.Method == "POST" 
                && context.Request.ContentType?.Contains("application/x-www-form-urlencoded") == true)
            {
                // Enable buffering for all form POSTs to allow re-reading
                context.Request.EnableBuffering();
                context.Request.Body.Position = 0;
            }
            await next();
        });

        app.UseRouting();
        app.UseStaticFiles();
        app.UseCors("AllowAll");
        app.UseAuthentication();
        app.UseAuthorization();

        // Map endpoints
        app.MapAuthorizationEndpoint();
        app.MapTokenEndpoint(creds, jwtConfig);
        app.MapJwksEndpoint();
        app.MapDiscoveryEndpoint();
        app.MapHealthEndpoint();

        app.Run();
    }
}
