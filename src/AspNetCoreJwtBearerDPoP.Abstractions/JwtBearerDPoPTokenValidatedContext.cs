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

    /// <summary>
    /// DPoP proof read from the request. Empty when none was sent.
    /// Validated only when <see cref="JwtBearerDPoPOptions.RequireDPoP"/> is <see langword="true"/>.
    /// </summary>
    public required string DPoP { get; init; }
}
