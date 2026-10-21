using Microsoft.AspNetCore.Authentication;
using Microsoft.IdentityModel.Tokens;

namespace AspNetCoreJwtBearerDPoP.Abstractions;

/// <summary>
/// Options for validating an access JWT together with a DPoP proof (RFC 9449).
/// </summary>
public sealed class JwtBearerDPoPOptions : AuthenticationSchemeOptions
{
    /// <summary>
    /// Validation parameters for the access token (issuer, lifetime, signing keys, …).
    /// Signing keys may also be supplied per-request via <see cref="JwtBearerDPoPEvents.OnResolveAccessTokenSigningKeys"/>.
    /// </summary>
    public TokenValidationParameters TokenValidationParameters { get; set; } = new()
    {
        ValidateIssuerSigningKey = true,
        ValidateIssuer = true,
        ValidateAudience = false,
        ValidateLifetime = true,
        ClockSkew = TimeSpan.FromMinutes(1),
    };

    /// <summary>
    /// Header names checked (in order) for the access token.
    /// </summary>
    public IList<string> AccessTokenHeaderNames { get; } = [.. JwtBearerDPoPDefaults.AccessTokenHeaderNames];

    /// <summary>
    /// Query names checked (in order) for the access token when no header is present.
    /// </summary>
    public IList<string> AccessTokenQueryNames { get; } = [.. JwtBearerDPoPDefaults.AccessTokenQueryNames];

    /// <summary>
    /// Header names checked (in order) for the DPoP proof.
    /// </summary>
    public IList<string> DPoPHeaderNames { get; } = [.. JwtBearerDPoPDefaults.DPoPHeaderNames];

    /// <summary>
    /// Query names checked (in order) for the DPoP proof when no header is present.
    /// </summary>
    public IList<string> DPoPQueryNames { get; } = [.. JwtBearerDPoPDefaults.DPoPQueryNames];

    /// <summary>
    /// Access-token claim holding the client public JWK JSON.
    /// </summary>
    public string PublicKeyClaimName { get; set; } = JwtBearerDPoPDefaults.PublicKeyClaimName;

    /// <summary>
    /// DPoP proof claim for the access-token hash.
    /// </summary>
    public string AccessTokenHashClaimName { get; set; } = JwtBearerDPoPDefaults.AccessTokenHashClaimName;

    /// <summary>
    /// When <see langword="true"/>, requires DPoP <c>htu</c> to match the request URL (scheme+host+path).
    /// </summary>
    public bool ValidateHtu { get; set; }

    /// <summary>
    /// When <see langword="true"/>, requires DPoP <c>htm</c> to match the request method.
    /// </summary>
    public bool ValidateHtm { get; set; }

    /// <summary>
    /// Events raised during authentication.
    /// </summary>
    public new JwtBearerDPoPEvents Events { get; set; } = new();
}
