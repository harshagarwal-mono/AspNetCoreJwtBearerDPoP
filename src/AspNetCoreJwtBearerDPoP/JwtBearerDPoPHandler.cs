using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.Tokens;

namespace AspNetCoreJwtBearerDPoP;

/// <summary>
/// Authenticates requests that carry an access JWT and, when required, a DPoP proof (RFC 9449),
/// from headers and/or query string (WebSocket-friendly).
/// </summary>
public sealed class JwtBearerDPoPHandler(IOptionsMonitor<JwtBearerDPoPOptions> options, ILoggerFactory logger, UrlEncoder encoder) : AuthenticationHandler<JwtBearerDPoPOptions>(options, logger, encoder)
{
    /// <inheritdoc />
    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        (string? accessToken, string? dPoP, AuthenticateResult? earlyResult) = await ReadCredentialsAsync().ConfigureAwait(false);

        if (earlyResult is not null)
        {
            return earlyResult;
        }

        if (string.IsNullOrWhiteSpace(accessToken))
        {
            return AuthenticateResult.NoResult();
        }

        bool requireDPoP = Options.RequireDPoP;

        if (requireDPoP && string.IsNullOrWhiteSpace(dPoP))
        {
            return AuthenticateResult.NoResult();
        }

        AuthenticateResult? storeResult = await ValidateAgainstTokenStoreAsync(accessToken).ConfigureAwait(false);

        if (storeResult is not null)
        {
            return storeResult;
        }

        TokenValidationParameters accessTokenParameters = await ResolveAccessTokenValidationParametersAsync().ConfigureAwait(false);
        ClaimsPrincipal? principal = requireDPoP
            ? DPoPJwtValidator.Validate(accessToken, dPoP!, accessTokenParameters, CreateDPoPValidationParameters())
            : DPoPJwtValidator.ValidateAccessToken(accessToken, accessTokenParameters);

        if (principal is null)
        {
            return AuthenticateResult.Fail(requireDPoP ? JwtBearerDPoPErrors.AccessTokenOrDPoPProofInvalid : JwtBearerDPoPErrors.AccessTokenInvalid);
        }

        return await CreateSuccessResultAsync(accessToken, dPoP, principal).ConfigureAwait(false);
    }

    /// <summary>
    /// When an <see cref="ITokenStore"/> is registered, the access token must already be present.
    /// No registration means the check is skipped. A missing token and a store exception
    /// both fail with <see cref="JwtBearerDPoPErrors.AccessTokenNotPresentInTokenStore"/>.
    /// </summary>
    private async Task<AuthenticateResult?> ValidateAgainstTokenStoreAsync(string accessToken)
    {
        ITokenStore? store = Context.RequestServices.GetService<ITokenStore>();
        if (store is null)
        {
            return null;
        }

        try
        {
            if (await store.ContainsAsync(accessToken, Context.RequestAborted).ConfigureAwait(false))
            {
                return null;
            }
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            Logger.LogError(exception, JwtBearerDPoPErrors.TokenStoreLookupFailed);
        }

        return AuthenticateResult.Fail(JwtBearerDPoPErrors.AccessTokenNotPresentInTokenStore);
    }

    private async Task<(string? AccessToken, string? DPoP, AuthenticateResult? EarlyResult)> ReadCredentialsAsync()
    {
        JwtBearerDPoPOptions opts = Options;
        var context = new JwtBearerDPoPMessageReceivedContext(Context, Scheme, opts)
        {
            Token = ReadFirst(opts.AccessTokenHeaderNames, opts.AccessTokenQueryNames),
            DPoP = ReadFirst(opts.DPoPHeaderNames, opts.DPoPQueryNames),
        };

        await opts.Events.MessageReceived(context).ConfigureAwait(false);
        return (context.Token, context.DPoP, context.Result);
    }

    private async Task<TokenValidationParameters> ResolveAccessTokenValidationParametersAsync()
    {
        TokenValidationParameters validationParameters = Options.TokenValidationParameters.Clone();
        var context = new JwtBearerDPoPResolveSigningKeysContext(Context, Scheme, Options);
        await Options.Events.ResolveAccessTokenSigningKeys(context).ConfigureAwait(false);

        if (context.SigningKeys is not null)
        {
            validationParameters.IssuerSigningKeys = context.SigningKeys;
            validationParameters.IssuerSigningKey = null;
        }

        return validationParameters;
    }

    private DPoPValidationParameters CreateDPoPValidationParameters()
    {
        JwtBearerDPoPOptions options = Options;
        return new DPoPValidationParameters
        {
            PublicKeyClaimName = options.PublicKeyClaimName,
            AccessTokenHashClaimName = options.AccessTokenHashClaimName,
            ExpectedHtm = options.ValidateHtm ? Request.Method : null,
            ExpectedHtu = options.ValidateHtu ? BuildHtu(Request) : null,
        };
    }

    private async Task<AuthenticateResult> CreateSuccessResultAsync(string accessToken, string? dPoP, ClaimsPrincipal principal)
    {
        var ticketPrincipal = new ClaimsPrincipal(new ClaimsIdentity(principal.Claims, Scheme.Name, ClaimsIdentity.DefaultNameClaimType, ClaimsIdentity.DefaultRoleClaimType));

        var context = new JwtBearerDPoPTokenValidatedContext(Context, Scheme, Options)
        {
            AccessToken = accessToken,
            DPoP = dPoP ?? string.Empty,
            Principal = ticketPrincipal,
        };

        await Options.Events.TokenValidated(context).ConfigureAwait(false);

        if (context.Result is not null)
        {
            return context.Result;
        }

        return AuthenticateResult.Success(new AuthenticationTicket(context.Principal, Scheme.Name));
    }

    private string? ReadFirst(IList<string> headerNames, IList<string> queryNames)
    {
        foreach (string name in headerNames)
        {
            if (Request.Headers.TryGetValue(name, out StringValues values)
                && !string.IsNullOrWhiteSpace(values.ToString()))
            {
                return values.ToString().Trim();
            }
        }

        foreach (string name in queryNames)
        {
            if (Request.Query.TryGetValue(name, out StringValues values)
                && !string.IsNullOrWhiteSpace(values.ToString()))
            {
                return values.ToString().Trim();
            }
        }

        return null;
    }

    private static string BuildHtu(HttpRequest request)
    {
        return $"{request.Scheme}://{request.Host.Value}{request.Path.Value}";
    }
}
