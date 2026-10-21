using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Encodings.Web;
using AspNetCoreJwtBearerDPoP.Tests.TestHelpers;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.IdentityModel.Tokens;

namespace AspNetCoreJwtBearerDPoP.Tests;

public sealed class JwtBearerDPoPHandlerTests
{
    private readonly SymmetricSecurityKey _issuerKey;
    private readonly SigningCredentials _issuerCredentials;
    private readonly ECDsa _clientEcdsa;
    private readonly string _publicJwk;

    public JwtBearerDPoPHandlerTests()
    {
        (_issuerKey, _issuerCredentials) = DPoPTestTokenFactory.CreateIssuerSigning();
        (_clientEcdsa, _publicJwk, _) = DPoPTestTokenFactory.CreateClientKeyPair();
    }

    [Fact]
    public async Task Authenticate_WhenNoCredentials_ReturnsNoResult()
    {
        AuthenticateResult result = await AuthenticateAsync(CreateOptions(), new DefaultHttpContext());

        Assert.False(result.Succeeded);
        Assert.True(result.None);
    }

    [Fact]
    public async Task Authenticate_WhenOnlyAccessToken_ReturnsNoResult()
    {
        var context = new DefaultHttpContext();
        context.Request.Headers["token"] = "access-only";

        AuthenticateResult result = await AuthenticateAsync(CreateOptions(), context);

        Assert.True(result.None);
    }

    [Fact]
    public async Task Authenticate_WhenOnlyDPoP_ReturnsNoResult()
    {
        var context = new DefaultHttpContext();
        context.Request.Headers["DPoP"] = "dpop-only";

        AuthenticateResult result = await AuthenticateAsync(CreateOptions(), context);

        Assert.True(result.None);
    }

    [Fact]
    public async Task Authenticate_WhenValidHeaderCredentials_ReturnsSuccess()
    {
        string accessToken = DPoPTestTokenFactory.CreateAccessToken(_issuerCredentials, _publicJwk);
        string dPoP = DPoPTestTokenFactory.CreateDPoP(accessToken, _clientEcdsa);
        var context = new DefaultHttpContext();
        context.Request.Headers["token"] = $"  {accessToken}  ";
        context.Request.Headers["DPoP"] = $"  {dPoP}  ";

        AuthenticateResult result = await AuthenticateAsync(CreateOptions(), context);

        Assert.True(result.Succeeded);
        Assert.NotNull(result.Ticket);
        Assert.Equal(JwtBearerDPoPDefaults.AuthenticationScheme, result.Ticket.AuthenticationScheme);
        Assert.Equal("user-1", result.Principal.FindFirst(ClaimTypes.NameIdentifier)?.Value);
    }

    [Fact]
    public async Task Authenticate_WhenValidQueryCredentials_ReturnsSuccess()
    {
        string accessToken = DPoPTestTokenFactory.CreateAccessToken(_issuerCredentials, _publicJwk);
        string dPoP = DPoPTestTokenFactory.CreateDPoP(accessToken, _clientEcdsa);
        var context = new DefaultHttpContext();
        context.Request.QueryString = QueryString.Create(new Dictionary<string, string?>
        {
            ["token"] = accessToken,
            ["DPoP"] = dPoP,
        });

        AuthenticateResult result = await AuthenticateAsync(CreateOptions(), context);

        Assert.True(result.Succeeded);
    }

    [Fact]
    public async Task Authenticate_PrefersHeaderOverQuery()
    {
        string accessToken = DPoPTestTokenFactory.CreateAccessToken(_issuerCredentials, _publicJwk);
        string dPoP = DPoPTestTokenFactory.CreateDPoP(accessToken, _clientEcdsa);
        string capturedToken = string.Empty;
        JwtBearerDPoPOptions options = CreateOptions();
        options.Events = new JwtBearerDPoPEvents
        {
            OnMessageReceived = ctx =>
            {
                capturedToken = ctx.Token ?? string.Empty;
                return Task.CompletedTask;
            },
        };

        var context = new DefaultHttpContext();
        context.Request.Headers["token"] = accessToken;
        context.Request.Headers["DPoP"] = dPoP;
        context.Request.QueryString = QueryString.Create(new Dictionary<string, string?>
        {
            ["token"] = "query-token",
            ["DPoP"] = "query-dpop",
        });

        AuthenticateResult result = await AuthenticateAsync(options, context);

        Assert.True(result.Succeeded);
        Assert.Equal(accessToken, capturedToken);
    }

    [Fact]
    public async Task Authenticate_WhenWhitespaceHeader_FallsBackToQuery()
    {
        string accessToken = DPoPTestTokenFactory.CreateAccessToken(_issuerCredentials, _publicJwk);
        string dPoP = DPoPTestTokenFactory.CreateDPoP(accessToken, _clientEcdsa);
        var context = new DefaultHttpContext();
        context.Request.Headers["token"] = "   ";
        context.Request.Headers["DPoP"] = "   ";
        context.Request.QueryString = QueryString.Create(new Dictionary<string, string?>
        {
            ["token"] = accessToken,
            ["DPoP"] = dPoP,
        });

        AuthenticateResult result = await AuthenticateAsync(CreateOptions(), context);

        Assert.True(result.Succeeded);
    }

    [Fact]
    public async Task Authenticate_WhenInvalidTokens_ReturnsFail()
    {
        var context = new DefaultHttpContext();
        context.Request.Headers["token"] = "not.a.jwt";
        context.Request.Headers["DPoP"] = "also.not.a.jwt";

        AuthenticateResult result = await AuthenticateAsync(CreateOptions(), context);

        Assert.False(result.Succeeded);
        Assert.False(result.None);
        Assert.Equal("Access token or DPoP proof is invalid.", result.Failure?.Message);
    }

    [Fact]
    public async Task Authenticate_WhenMessageReceivedSetsResult_ReturnsEarly()
    {
        JwtBearerDPoPOptions options = CreateOptions();
        options.Events = new JwtBearerDPoPEvents
        {
            OnMessageReceived = ctx =>
            {
                ctx.Fail("blocked-early");
                return Task.CompletedTask;
            },
        };
        var context = new DefaultHttpContext();
        context.Request.Headers["token"] = "ignored";
        context.Request.Headers["DPoP"] = "ignored";

        AuthenticateResult result = await AuthenticateAsync(options, context);

        Assert.False(result.Succeeded);
        Assert.Equal("blocked-early", result.Failure?.Message);
    }

    [Fact]
    public async Task Authenticate_WhenMessageReceivedOverridesCredentials_UsesOverrides()
    {
        string accessToken = DPoPTestTokenFactory.CreateAccessToken(_issuerCredentials, _publicJwk);
        string dPoP = DPoPTestTokenFactory.CreateDPoP(accessToken, _clientEcdsa);
        JwtBearerDPoPOptions options = CreateOptions();
        options.Events = new JwtBearerDPoPEvents
        {
            OnMessageReceived = ctx =>
            {
                ctx.Token = accessToken;
                ctx.DPoP = dPoP;
                return Task.CompletedTask;
            },
        };

        AuthenticateResult result = await AuthenticateAsync(options, new DefaultHttpContext());

        Assert.True(result.Succeeded);
    }

    [Fact]
    public async Task Authenticate_WhenResolveSigningKeysProvidesKeys_ValidatesSuccessfully()
    {
        string accessToken = DPoPTestTokenFactory.CreateAccessToken(_issuerCredentials, _publicJwk);
        string dPoP = DPoPTestTokenFactory.CreateDPoP(accessToken, _clientEcdsa);
        JwtBearerDPoPOptions options = CreateOptions();
        // Deliberately wrong default key so ResolveSigningKeys must supply the real one.
        options.TokenValidationParameters.IssuerSigningKey = new SymmetricSecurityKey(RandomNumberGenerator.GetBytes(32));
        options.Events = new JwtBearerDPoPEvents
        {
            OnResolveAccessTokenSigningKeys = ctx =>
            {
                ctx.SigningKeys = [_issuerKey];
                return Task.CompletedTask;
            },
        };

        var context = new DefaultHttpContext();
        context.Request.Headers["token"] = accessToken;
        context.Request.Headers["DPoP"] = dPoP;

        AuthenticateResult result = await AuthenticateAsync(options, context);

        Assert.True(result.Succeeded);
    }

    [Fact]
    public async Task Authenticate_WhenTokenValidatedFails_ReturnsFailure()
    {
        string accessToken = DPoPTestTokenFactory.CreateAccessToken(_issuerCredentials, _publicJwk);
        string dPoP = DPoPTestTokenFactory.CreateDPoP(accessToken, _clientEcdsa);
        JwtBearerDPoPOptions options = CreateOptions();
        options.Events = new JwtBearerDPoPEvents
        {
            OnTokenValidated = ctx =>
            {
                ctx.Fail("post-validation-reject");
                return Task.CompletedTask;
            },
        };

        var context = new DefaultHttpContext();
        context.Request.Headers["token"] = accessToken;
        context.Request.Headers["DPoP"] = dPoP;

        AuthenticateResult result = await AuthenticateAsync(options, context);

        Assert.False(result.Succeeded);
        Assert.Equal("post-validation-reject", result.Failure?.Message);
    }

    [Fact]
    public async Task Authenticate_WhenValidateHtmAndHtuEnabled_AndClaimsMatch_Succeeds()
    {
        string accessToken = DPoPTestTokenFactory.CreateAccessToken(_issuerCredentials, _publicJwk);
        string dPoP = DPoPTestTokenFactory.CreateDPoP(
            accessToken,
            _clientEcdsa,
            htm: "GET",
            htu: "https://example.com/ws");
        JwtBearerDPoPOptions options = CreateOptions();
        options.ValidateHtm = true;
        options.ValidateHtu = true;

        var context = new DefaultHttpContext();
        context.Request.Method = "GET";
        context.Request.Scheme = "https";
        context.Request.Host = new HostString("example.com");
        context.Request.Path = "/ws";
        context.Request.Headers["token"] = accessToken;
        context.Request.Headers["DPoP"] = dPoP;

        AuthenticateResult result = await AuthenticateAsync(options, context);

        Assert.True(result.Succeeded);
    }

    [Fact]
    public async Task Authenticate_WhenValidateHtmEnabled_AndClaimMismatch_Fails()
    {
        string accessToken = DPoPTestTokenFactory.CreateAccessToken(_issuerCredentials, _publicJwk);
        string dPoP = DPoPTestTokenFactory.CreateDPoP(accessToken, _clientEcdsa, htm: "POST");
        JwtBearerDPoPOptions options = CreateOptions();
        options.ValidateHtm = true;

        var context = new DefaultHttpContext();
        context.Request.Method = "GET";
        context.Request.Headers["token"] = accessToken;
        context.Request.Headers["DPoP"] = dPoP;

        AuthenticateResult result = await AuthenticateAsync(options, context);

        Assert.False(result.Succeeded);
        Assert.False(result.None);
    }

    [Fact]
    public async Task Authenticate_WhenValidateHtuEnabled_AndClaimMismatch_Fails()
    {
        string accessToken = DPoPTestTokenFactory.CreateAccessToken(_issuerCredentials, _publicJwk);
        string dPoP = DPoPTestTokenFactory.CreateDPoP(
            accessToken,
            _clientEcdsa,
            htu: "https://example.com/other");
        JwtBearerDPoPOptions options = CreateOptions();
        options.ValidateHtu = true;

        var context = new DefaultHttpContext();
        context.Request.Scheme = "https";
        context.Request.Host = new HostString("example.com");
        context.Request.Path = "/ws";
        context.Request.Headers["token"] = accessToken;
        context.Request.Headers["DPoP"] = dPoP;

        AuthenticateResult result = await AuthenticateAsync(options, context);

        Assert.False(result.Succeeded);
        Assert.False(result.None);
    }

    [Fact]
    public async Task Authenticate_WithCustomHeaderNames_ReadsFromConfiguredHeaders()
    {
        string accessToken = DPoPTestTokenFactory.CreateAccessToken(_issuerCredentials, _publicJwk);
        string dPoP = DPoPTestTokenFactory.CreateDPoP(accessToken, _clientEcdsa);
        JwtBearerDPoPOptions options = CreateOptions();
        options.AccessTokenHeaderNames.Clear();
        options.AccessTokenHeaderNames.Add("X-Access-Token");
        options.DPoPHeaderNames.Clear();
        options.DPoPHeaderNames.Add("X-DPoP");

        var context = new DefaultHttpContext();
        context.Request.Headers["X-Access-Token"] = accessToken;
        context.Request.Headers["X-DPoP"] = dPoP;

        AuthenticateResult result = await AuthenticateAsync(options, context);

        Assert.True(result.Succeeded);
    }

    [Fact]
    public async Task Authenticate_TriesHeaderNamesInOrder()
    {
        string accessToken = DPoPTestTokenFactory.CreateAccessToken(_issuerCredentials, _publicJwk);
        string dPoP = DPoPTestTokenFactory.CreateDPoP(accessToken, _clientEcdsa);
        JwtBearerDPoPOptions options = CreateOptions();
        options.AccessTokenHeaderNames.Clear();
        options.AccessTokenHeaderNames.Add("first");
        options.AccessTokenHeaderNames.Add("second");
        options.DPoPHeaderNames.Clear();
        options.DPoPHeaderNames.Add("DPoP");

        var context = new DefaultHttpContext();
        context.Request.Headers["second"] = accessToken;
        context.Request.Headers["DPoP"] = dPoP;

        AuthenticateResult result = await AuthenticateAsync(options, context);

        Assert.True(result.Succeeded);
    }

    [Fact]
    public async Task Authenticate_WhenRequireDPoPIsFalse_AcceptsAccessTokenWithoutProof()
    {
        string accessToken = DPoPTestTokenFactory.CreateAccessToken(_issuerCredentials, _publicJwk);
        JwtBearerDPoPOptions options = CreateOptions();
        options.RequireDPoP = false;

        var context = new DefaultHttpContext();
        context.Request.Headers["token"] = accessToken;

        AuthenticateResult result = await AuthenticateAsync(options, context);

        Assert.True(result.Succeeded);
        Assert.Equal("user-1", result.Principal.FindFirst(ClaimTypes.NameIdentifier)?.Value);
    }

    [Fact]
    public async Task Authenticate_WhenRequireDPoPIsFalse_IgnoresProof()
    {
        string accessToken = DPoPTestTokenFactory.CreateAccessToken(_issuerCredentials, _publicJwk);
        JwtBearerDPoPOptions options = CreateOptions();
        options.RequireDPoP = false;

        var context = new DefaultHttpContext();
        context.Request.Headers["token"] = accessToken;
        context.Request.Headers["DPoP"] = "not.a.proof";

        AuthenticateResult result = await AuthenticateAsync(options, context);

        Assert.True(result.Succeeded);
    }

    [Fact]
    public async Task Authenticate_WhenRequireDPoPIsFalse_AndAccessTokenInvalid_Fails()
    {
        JwtBearerDPoPOptions options = CreateOptions();
        options.RequireDPoP = false;

        var context = new DefaultHttpContext();
        context.Request.Headers["token"] = "not.a.jwt";

        AuthenticateResult result = await AuthenticateAsync(options, context);

        Assert.False(result.Succeeded);
        Assert.False(result.None);
        Assert.Equal("Access token is invalid.", result.Failure?.Message);
    }

    [Fact]
    public async Task Authenticate_WhenTokenStoreContainsAccessToken_Succeeds()
    {
        string accessToken = DPoPTestTokenFactory.CreateAccessToken(_issuerCredentials, _publicJwk);
        string dPoP = DPoPTestTokenFactory.CreateDPoP(accessToken, _clientEcdsa);
        string? seen = null;
        var context = new DefaultHttpContext();
        context.Request.Headers["token"] = $"  {accessToken}  ";
        context.Request.Headers["DPoP"] = dPoP;

        AuthenticateResult result = await AuthenticateAsync(
            CreateOptions(),
            context,
            new DelegateTokenStore(token =>
            {
                seen = token;
                return true;
            }));

        Assert.True(result.Succeeded);
        Assert.Equal(accessToken, seen);
    }

    [Fact]
    public async Task Authenticate_WhenTokenStoreDoesNotContainAccessToken_Fails()
    {
        string accessToken = DPoPTestTokenFactory.CreateAccessToken(_issuerCredentials, _publicJwk);
        string dPoP = DPoPTestTokenFactory.CreateDPoP(accessToken, _clientEcdsa);
        var context = new DefaultHttpContext();
        context.Request.Headers["token"] = accessToken;
        context.Request.Headers["DPoP"] = dPoP;

        AuthenticateResult result = await AuthenticateAsync(
            CreateOptions(),
            context,
            new DelegateTokenStore(_ => false));

        Assert.False(result.Succeeded);
        Assert.False(result.None);
        Assert.Equal("Access token is not present in the token store.", result.Failure?.Message);
    }

    [Fact]
    public async Task Authenticate_WhenTokenStoreThrows_Fails()
    {
        string accessToken = DPoPTestTokenFactory.CreateAccessToken(_issuerCredentials, _publicJwk);
        string dPoP = DPoPTestTokenFactory.CreateDPoP(accessToken, _clientEcdsa);
        var context = new DefaultHttpContext();
        context.Request.Headers["token"] = accessToken;
        context.Request.Headers["DPoP"] = dPoP;

        AuthenticateResult result = await AuthenticateAsync(
            CreateOptions(),
            context,
            new DelegateTokenStore(_ => throw new InvalidOperationException("redis down")));

        Assert.False(result.Succeeded);
        Assert.False(result.None);
        Assert.Equal("Access token is not present in the token store.", result.Failure?.Message);
    }

    [Fact]
    public async Task Authenticate_WhenTokenStoreRejects_DoesNotResolveSigningKeys()
    {
        bool resolved = false;
        string accessToken = DPoPTestTokenFactory.CreateAccessToken(_issuerCredentials, _publicJwk);
        string dPoP = DPoPTestTokenFactory.CreateDPoP(accessToken, _clientEcdsa);
        JwtBearerDPoPOptions options = CreateOptions();
        options.Events = new JwtBearerDPoPEvents
        {
            OnResolveAccessTokenSigningKeys = _ =>
            {
                resolved = true;
                return Task.CompletedTask;
            },
        };

        var context = new DefaultHttpContext();
        context.Request.Headers["token"] = accessToken;
        context.Request.Headers["DPoP"] = dPoP;

        AuthenticateResult result = await AuthenticateAsync(options, context, new DelegateTokenStore(_ => false));

        Assert.False(resolved);
        Assert.Equal("Access token is not present in the token store.", result.Failure?.Message);
    }

    [Fact]
    public async Task Authenticate_WhenRequireDPoPIsFalse_AndTokenStoreRejects_Fails()
    {
        string accessToken = DPoPTestTokenFactory.CreateAccessToken(_issuerCredentials, _publicJwk);
        JwtBearerDPoPOptions options = CreateOptions();
        options.RequireDPoP = false;

        var context = new DefaultHttpContext();
        context.Request.Headers["token"] = accessToken;

        AuthenticateResult result = await AuthenticateAsync(options, context, new DelegateTokenStore(_ => false));

        Assert.Equal("Access token is not present in the token store.", result.Failure?.Message);
    }

    private JwtBearerDPoPOptions CreateOptions()
    {
        return new JwtBearerDPoPOptions
        {
            TokenValidationParameters = DPoPTestTokenFactory.CreateAccessTokenValidationParameters(_issuerKey),
        };
    }

    private static async Task<AuthenticateResult> AuthenticateAsync(
        JwtBearerDPoPOptions options,
        HttpContext context,
        ITokenStore? tokenStore = null)
    {
        var services = new ServiceCollection();
        if (tokenStore is not null)
        {
            services.AddSingleton(tokenStore);
        }

        await using ServiceProvider provider = services.BuildServiceProvider();
        context.RequestServices = provider;

        var handler = new JwtBearerDPoPHandler(
            new TestOptionsMonitor<JwtBearerDPoPOptions>(options),
            NullLoggerFactory.Instance,
            UrlEncoder.Default);

        var scheme = new AuthenticationScheme(
            JwtBearerDPoPDefaults.AuthenticationScheme,
            displayName: null,
            typeof(JwtBearerDPoPHandler));

        await handler.InitializeAsync(scheme, context);
        return await handler.AuthenticateAsync();
    }

    private sealed class DelegateTokenStore(Func<string, bool> contains) : ITokenStore
    {
        public Task<bool> ContainsAsync(string accessToken, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(contains(accessToken));
        }
    }
}
