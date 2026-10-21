using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace AspNetCoreJwtBearerDPoP.Abstractions;

/// <summary>
/// Context for <see cref="JwtBearerDPoPEvents.OnTokenValidated"/>.
/// </summary>
public sealed class JwtBearerDPoPTokenValidatedContext(HttpContext context, AuthenticationScheme scheme, JwtBearerDPoPOptions options) : ResultContext<JwtBearerDPoPOptions>(context, scheme, options)
{
    /// <summary>The validated access token.</summary>
    public required string AccessToken { get; init; }

    /// <summary>The validated DPoP proof bound to <see cref="AccessToken"/>.</summary>
    public required string DPoP { get; init; }
}
