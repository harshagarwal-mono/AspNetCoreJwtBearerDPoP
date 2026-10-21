using Microsoft.IdentityModel.Tokens;

namespace AspNetCoreJwtBearerDPoP.Tests;

public sealed class JwtBearerDPoPPostConfigureOptionsTests
{
    private readonly JwtBearerDPoPPostConfigureOptions _sut = new();

    [Fact]
    public void PostConfigure_WhenOptionsNull_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => _sut.PostConfigure("scheme", null!));
    }

    [Fact]
    public void PostConfigure_WhenEventsNull_AssignsDefaultEvents()
    {
        var options = new JwtBearerDPoPOptions { Events = null! };

        _sut.PostConfigure(JwtBearerDPoPDefaults.AuthenticationScheme, options);

        Assert.NotNull(options.Events);
    }

    [Fact]
    public void PostConfigure_WhenTokenValidationParametersNull_AssignsDefaults()
    {
        var options = new JwtBearerDPoPOptions { TokenValidationParameters = null! };

        _sut.PostConfigure(null, options);

        Assert.NotNull(options.TokenValidationParameters);
        Assert.True(options.TokenValidationParameters.ValidateIssuerSigningKey);
        Assert.True(options.TokenValidationParameters.ValidateIssuer);
        Assert.False(options.TokenValidationParameters.ValidateAudience);
        Assert.True(options.TokenValidationParameters.ValidateLifetime);
        Assert.Equal(TimeSpan.FromMinutes(1), options.TokenValidationParameters.ClockSkew);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void PostConfigure_WhenPublicKeyClaimNameBlank_UsesDefault(string? claimName)
    {
        var options = new JwtBearerDPoPOptions { PublicKeyClaimName = claimName! };

        _sut.PostConfigure("s", options);

        Assert.Equal(JwtBearerDPoPDefaults.PublicKeyClaimName, options.PublicKeyClaimName);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void PostConfigure_WhenAccessTokenHashClaimNameBlank_UsesDefault(string? claimName)
    {
        var options = new JwtBearerDPoPOptions { AccessTokenHashClaimName = claimName! };

        _sut.PostConfigure("s", options);

        Assert.Equal(JwtBearerDPoPDefaults.AccessTokenHashClaimName, options.AccessTokenHashClaimName);
    }

    [Fact]
    public void PostConfigure_WhenHeaderAndQueryListsEmpty_FillsDefaults()
    {
        var options = new JwtBearerDPoPOptions();
        options.AccessTokenHeaderNames.Clear();
        options.AccessTokenQueryNames.Clear();
        options.DPoPHeaderNames.Clear();
        options.DPoPQueryNames.Clear();

        _sut.PostConfigure("s", options);

        Assert.Equal(JwtBearerDPoPDefaults.AccessTokenHeaderNames, options.AccessTokenHeaderNames);
        Assert.Equal(JwtBearerDPoPDefaults.AccessTokenQueryNames, options.AccessTokenQueryNames);
        Assert.Equal(JwtBearerDPoPDefaults.DPoPHeaderNames, options.DPoPHeaderNames);
        Assert.Equal(JwtBearerDPoPDefaults.DPoPQueryNames, options.DPoPQueryNames);
    }

    [Fact]
    public void PostConfigure_WhenListsAlreadyPopulated_DoesNotOverwrite()
    {
        var options = new JwtBearerDPoPOptions();
        options.AccessTokenHeaderNames.Clear();
        options.AccessTokenHeaderNames.Add("X-Access");
        options.AccessTokenQueryNames.Clear();
        options.AccessTokenQueryNames.Add("access_token");
        options.DPoPHeaderNames.Clear();
        options.DPoPHeaderNames.Add("X-DPoP");
        options.DPoPQueryNames.Clear();
        options.DPoPQueryNames.Add("dpop_proof");
        options.PublicKeyClaimName = "cnf_jwk";
        options.AccessTokenHashClaimName = "token_hash";
        options.Events = new JwtBearerDPoPEvents();
        options.TokenValidationParameters = new TokenValidationParameters { ValidateAudience = true };

        _sut.PostConfigure("s", options);

        Assert.Equal(["X-Access"], options.AccessTokenHeaderNames);
        Assert.Equal(["access_token"], options.AccessTokenQueryNames);
        Assert.Equal(["X-DPoP"], options.DPoPHeaderNames);
        Assert.Equal(["dpop_proof"], options.DPoPQueryNames);
        Assert.Equal("cnf_jwk", options.PublicKeyClaimName);
        Assert.Equal("token_hash", options.AccessTokenHashClaimName);
        Assert.True(options.TokenValidationParameters.ValidateAudience);
    }
}
