using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using AspNetCoreJwtBearerDPoP.Abstractions;

namespace AspNetCoreJwtBearerDPoP.Tests;

public sealed class JwtBearerDPoPExtensionsTests
{
    [Fact]
    public void AddJwtBearerDPoP_WhenBuilderNull_Throws()
    {
        Assert.Throws<ArgumentNullException>(() =>
            JwtBearerDPoPExtensions.AddJwtBearerDPoP(null!));
    }

    [Fact]
    public void AddJwtBearerDPoP_WhenConfigureOptionsNull_Throws()
    {
        var services = new ServiceCollection();
        AuthenticationBuilder builder = services.AddAuthentication();

        Assert.Throws<ArgumentNullException>(() =>
            builder.AddJwtBearerDPoP(configureOptions: null!));
    }

    [Fact]
    public async Task AddJwtBearerDPoP_Parameterless_RegistersDefaultSchemeAndPostConfigure()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddAuthentication().AddJwtBearerDPoP();

        await using ServiceProvider provider = services.BuildServiceProvider();
        IAuthenticationSchemeProvider schemes = provider.GetRequiredService<IAuthenticationSchemeProvider>();
        AuthenticationScheme? scheme = await schemes.GetSchemeAsync(JwtBearerDPoPDefaults.AuthenticationScheme);

        Assert.NotNull(scheme);
        Assert.Equal(typeof(JwtBearerDPoPHandler), scheme.HandlerType);

        IEnumerable<IPostConfigureOptions<JwtBearerDPoPOptions>> postConfigure =
            provider.GetServices<IPostConfigureOptions<JwtBearerDPoPOptions>>();
        Assert.Contains(postConfigure, p => p is JwtBearerDPoPPostConfigureOptions);

        IOptionsMonitor<JwtBearerDPoPOptions> options =
            provider.GetRequiredService<IOptionsMonitor<JwtBearerDPoPOptions>>();
        Assert.Equal(JwtBearerDPoPDefaults.PublicKeyClaimName, options.Get(JwtBearerDPoPDefaults.AuthenticationScheme).PublicKeyClaimName);
    }

    [Fact]
    public void AddJwtBearerDPoP_WithConfigure_AppliesOptions()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddAuthentication().AddJwtBearerDPoP(options =>
        {
            options.ValidateHtm = true;
            options.ValidateHtu = true;
            options.PublicKeyClaimName = "custom_jwk";
        });

        using ServiceProvider provider = services.BuildServiceProvider();
        JwtBearerDPoPOptions options = provider
            .GetRequiredService<IOptionsMonitor<JwtBearerDPoPOptions>>()
            .Get(JwtBearerDPoPDefaults.AuthenticationScheme);

        Assert.True(options.ValidateHtm);
        Assert.True(options.ValidateHtu);
        Assert.Equal("custom_jwk", options.PublicKeyClaimName);
    }

    [Fact]
    public async Task AddJwtBearerDPoP_WithCustomSchemeAndDisplayName_RegistersScheme()
    {
        const string schemeName = "CustomDPoP";
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddAuthentication().AddJwtBearerDPoP(schemeName, "DPoP Auth", _ => { });

        await using ServiceProvider provider = services.BuildServiceProvider();
        AuthenticationScheme? scheme = await provider
            .GetRequiredService<IAuthenticationSchemeProvider>()
            .GetSchemeAsync(schemeName);

        Assert.NotNull(scheme);
        Assert.Equal("DPoP Auth", scheme.DisplayName);
        Assert.Equal(typeof(JwtBearerDPoPHandler), scheme.HandlerType);
    }

    [Fact]
    public void AddJwtBearerDPoP_CalledTwice_RegistersPostConfigureOnce()
    {
        var services = new ServiceCollection();
        services.AddAuthentication()
            .AddJwtBearerDPoP()
            .AddJwtBearerDPoP("Other", _ => { });

        using ServiceProvider provider = services.BuildServiceProvider();
        IPostConfigureOptions<JwtBearerDPoPOptions>[] postConfigure =
            [.. provider.GetServices<IPostConfigureOptions<JwtBearerDPoPOptions>>()];

        Assert.Single(postConfigure.OfType<JwtBearerDPoPPostConfigureOptions>());
    }
}
