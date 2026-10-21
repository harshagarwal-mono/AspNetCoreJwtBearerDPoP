using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Tokens;

namespace AspNetCoreJwtBearerDPoP;

/// <summary>
/// Context for <see cref="JwtBearerDPoPEvents.OnResolveAccessTokenSigningKeys"/>.
/// </summary>
public sealed class JwtBearerDPoPResolveSigningKeysContext(HttpContext context, AuthenticationScheme scheme, JwtBearerDPoPOptions options) : BaseContext<JwtBearerDPoPOptions>(context, scheme, options)
{
    /// <summary>
    /// Signing keys used to validate the access token. When set, replaces
    /// <see cref="TokenValidationParameters.IssuerSigningKeys"/>.
    /// </summary>
    public IEnumerable<SecurityKey>? SigningKeys { get; set; }
}
