using System.Security.Cryptography;
using System.Text.Json;

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

        // Load or generate RSA key for JWT signing and JWKS
        var (rsaKey, keyId) = LoadOrCreateRsaKey("jwk.json");
        var rsaSecurityKey = new RsaSecurityKey(rsaKey)
        {
            KeyId = keyId
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
        app.UseDefaultFiles(new DefaultFilesOptions() {
            DefaultFileNames = [ "test.html" ],
        });
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
        app.MapUserInfoEndpoint();

        app.Run();
    }

    private static (RSA Key, string KeyId) LoadOrCreateRsaKey(string filePath)
    {
        if (File.Exists(filePath))
        {
            try
            {
                var json = File.ReadAllText(filePath);
                var jwk = JsonSerializer.Deserialize<JsonElement>(json);

                var kid = jwk.GetProperty("kid").GetString()!;
                var rsaParams = new RSAParameters
                {
                    Modulus = Base64UrlEncoder.DecodeBytes(jwk.GetProperty("n").GetString()!),
                    Exponent = Base64UrlEncoder.DecodeBytes(jwk.GetProperty("e").GetString()!),
                    D = Base64UrlEncoder.DecodeBytes(jwk.GetProperty("d").GetString()!),
                    P = Base64UrlEncoder.DecodeBytes(jwk.GetProperty("p").GetString()!),
                    Q = Base64UrlEncoder.DecodeBytes(jwk.GetProperty("q").GetString()!),
                    DP = Base64UrlEncoder.DecodeBytes(jwk.GetProperty("dp").GetString()!),
                    DQ = Base64UrlEncoder.DecodeBytes(jwk.GetProperty("dq").GetString()!),
                    InverseQ = Base64UrlEncoder.DecodeBytes(jwk.GetProperty("qi").GetString()!)
                };

                var rsa = RSA.Create();
                rsa.ImportParameters(rsaParams);
                Console.WriteLine($"Loaded RSA signing key from {filePath} (kid: {kid})");
                return (rsa, kid);
            }
            catch (Exception ex)
            {
                var ephemeralKid = Guid.NewGuid().ToString();
                Console.Error.WriteLine($"Error reading {filePath}, using ephemeral key (kid: {ephemeralKid}): {ex.Message}");
                return (RSA.Create(2048), ephemeralKid);
            }
        }

        var newKey = RSA.Create(2048);
        var newKid = Guid.NewGuid().ToString();

        try
        {
            var p = newKey.ExportParameters(true);
            var jwkObj = new
            {
                kty = "RSA",
                kid = newKid,
                n = Base64UrlEncoder.Encode(p.Modulus!),
                e = Base64UrlEncoder.Encode(p.Exponent!),
                d = Base64UrlEncoder.Encode(p.D!),
                p = Base64UrlEncoder.Encode(p.P!),
                q = Base64UrlEncoder.Encode(p.Q!),
                dp = Base64UrlEncoder.Encode(p.DP!),
                dq = Base64UrlEncoder.Encode(p.DQ!),
                qi = Base64UrlEncoder.Encode(p.InverseQ!)
            };

            var jsonText = JsonSerializer.Serialize(jwkObj, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(filePath, jsonText);
            Console.WriteLine($"Created new RSA signing key and saved to {filePath} (kid: {newKid})");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Warning: could not write {filePath}, key is ephemeral: {ex.Message}");
        }

        return (newKey, newKid);
    }
}
