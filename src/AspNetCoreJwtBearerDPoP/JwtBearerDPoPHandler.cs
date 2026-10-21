using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.Tokens;
using AspNetCoreJwtBearerDPoP.Abstractions;

namespace AspNetCoreJwtBearerDPoP;

/// <summary>
/// Authenticates requests that carry an access JWT plus a DPoP proof (RFC 9449),
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

        if (string.IsNullOrWhiteSpace(accessToken) || string.IsNullOrWhiteSpace(dPoP))
        {
            return AuthenticateResult.NoResult();
        }

        TokenValidationParameters accessTokenParameters = await ResolveAccessTokenValidationParametersAsync().ConfigureAwait(false);
        ClaimsPrincipal? principal = DPoPJwtValidator.Validate(accessToken, dPoP, accessTokenParameters, CreateDPoPValidationParameters());

        if (principal is null)
        {
            return AuthenticateResult.Fail("Access token or DPoP proof is invalid.");
        }

        return await CreateSuccessResultAsync(accessToken, dPoP, principal).ConfigureAwait(false);
    }

    private async Task<(string? AccessToken, string? DPoP, AuthenticateResult? EarlyResult)> ReadCredentialsAsync()
    {
        JwtBearerDPoPOptions options = Options;
        var context = new JwtBearerDPoPMessageReceivedContext(Context, Scheme, options)
        {
            Token = ReadFirst(options.AccessTokenHeaderNames, options.AccessTokenQueryNames),
            DPoP = ReadFirst(options.DPoPHeaderNames, options.DPoPQueryNames),
        };

        await options.Events.MessageReceived(context).ConfigureAwait(false);
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

    private async Task<AuthenticateResult> CreateSuccessResultAsync(string accessToken, string dPoP, ClaimsPrincipal principal)
    {
        var ticketPrincipal = new ClaimsPrincipal(new ClaimsIdentity(principal.Claims, Scheme.Name, ClaimsIdentity.DefaultNameClaimType, ClaimsIdentity.DefaultRoleClaimType));

        var context = new JwtBearerDPoPTokenValidatedContext(Context, Scheme, Options)
        {
            AccessToken = accessToken,
            DPoP = dPoP,
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
