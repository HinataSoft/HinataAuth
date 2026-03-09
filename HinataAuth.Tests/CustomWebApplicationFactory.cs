using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace HinataAuth.Tests;

/// <summary>
/// Custom factory - uses test appsettings.Test.json
/// </summary>
public class CustomWebApplicationFactory<TProgram> : WebApplicationFactory<TProgram> where TProgram : class
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        var testAppBasePath = AppContext.BaseDirectory;

        // Set environment to Test
        builder.UseEnvironment("Test");

        // Configure app to load test config from the test output directory
        builder.UseContentRoot(testAppBasePath);

        // Explicitly add test configuration
        builder.ConfigureAppConfiguration((context, config) =>
        {
            config.AddJsonFile(Path.Combine(testAppBasePath, "appsettings.Test.json"), optional: false, reloadOnChange: false);
        });
    }
}

/// <summary>
/// Shared fixture that both test classes use to ensure they share the same WebApplication instance
/// </summary>
public class SharedTestFixture : IDisposable
{
    public CustomWebApplicationFactory<Program> Factory { get; }

    public SharedTestFixture()
    {
        Factory = new CustomWebApplicationFactory<Program>();
    }

    public void Dispose()
    {
        Factory.Dispose();
    }
}

/// <summary>
/// Collection fixture to share the same test server across both test classes
/// </summary>
[CollectionDefinition("SharedTestCollection")]
public class SharedTestCollection : ICollectionFixture<SharedTestFixture>
{
}