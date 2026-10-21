using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace AspNetCoreJwtBearerDPoP.Abstractions;

/// <summary>
/// Context for <see cref="JwtBearerDPoPEvents.OnMessageReceived"/>.
/// </summary>
public sealed class JwtBearerDPoPMessageReceivedContext(HttpContext context, AuthenticationScheme scheme, JwtBearerDPoPOptions options) : ResultContext<JwtBearerDPoPOptions>(context, scheme, options)
{
    /// <summary>Access token (header/query). Set to override.</summary>
    public string? Token { get; set; }

    /// <summary>DPoP proof JWT. Set to override.</summary>
    public string? DPoP { get; set; }
}
