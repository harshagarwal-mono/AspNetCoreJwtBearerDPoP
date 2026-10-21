using AspNetCoreJwtBearerDPoP.Abstractions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace AspNetCoreJwtBearerDPoP.Tests;

public sealed class JwtBearerDPoPEventsTests
{
    private static AuthenticationScheme CreateScheme()
    {
        return new(JwtBearerDPoPDefaults.AuthenticationScheme, displayName: null, typeof(JwtBearerDPoPHandler));
    }

    [Fact]
    public async Task MessageReceived_InvokesOnMessageReceived()
    {
        bool invoked = false;
        var events = new JwtBearerDPoPEvents
        {
            OnMessageReceived = context =>
            {
                invoked = true;
                context.Token = "from-event";
                return Task.CompletedTask;
            },
        };
        var httpContext = new DefaultHttpContext();
        var messageContext = new JwtBearerDPoPMessageReceivedContext(httpContext, CreateScheme(), new JwtBearerDPoPOptions());

        await events.MessageReceived(messageContext);

        Assert.True(invoked);
        Assert.Equal("from-event", messageContext.Token);
    }

    [Fact]
    public async Task ResolveAccessTokenSigningKeys_InvokesOnResolveAccessTokenSigningKeys()
    {
        bool invoked = false;
        var events = new JwtBearerDPoPEvents
        {
            OnResolveAccessTokenSigningKeys = context =>
            {
                invoked = true;
                context.SigningKeys = [];
                return Task.CompletedTask;
            },
        };
        var resolveContext = new JwtBearerDPoPResolveSigningKeysContext(
            new DefaultHttpContext(),
            CreateScheme(),
            new JwtBearerDPoPOptions());

        await events.ResolveAccessTokenSigningKeys(resolveContext);

        Assert.True(invoked);
        Assert.NotNull(resolveContext.SigningKeys);
    }

    [Fact]
    public async Task TokenValidated_InvokesOnTokenValidated()
    {
        bool invoked = false;
        var events = new JwtBearerDPoPEvents
        {
            OnTokenValidated = context =>
            {
                invoked = true;
                context.Fail("rejected");
                return Task.CompletedTask;
            },
        };
        var validatedContext = new JwtBearerDPoPTokenValidatedContext(
            new DefaultHttpContext(),
            CreateScheme(),
            new JwtBearerDPoPOptions())
        {
            AccessToken = "a",
            DPoP = "d",
            Principal = new System.Security.Claims.ClaimsPrincipal(),
        };

        await events.TokenValidated(validatedContext);

        Assert.True(invoked);
        Assert.NotNull(validatedContext.Result);
        Assert.False(validatedContext.Result.Succeeded);
    }

    [Fact]
    public void Defaults_ExposeExpectedConstantValues()
    {
        Assert.Equal("JwtBearerDPoP", JwtBearerDPoPDefaults.AuthenticationScheme);
        Assert.Equal("jwk", JwtBearerDPoPDefaults.PublicKeyClaimName);
        Assert.Equal("ath", JwtBearerDPoPDefaults.AccessTokenHashClaimName);
        Assert.Equal(["token"], JwtBearerDPoPDefaults.AccessTokenHeaderNames);
        Assert.Equal(["token"], JwtBearerDPoPDefaults.AccessTokenQueryNames);
        Assert.Equal(["DPoP"], JwtBearerDPoPDefaults.DPoPHeaderNames);
        Assert.Equal(["DPoP"], JwtBearerDPoPDefaults.DPoPQueryNames);
    }
}
