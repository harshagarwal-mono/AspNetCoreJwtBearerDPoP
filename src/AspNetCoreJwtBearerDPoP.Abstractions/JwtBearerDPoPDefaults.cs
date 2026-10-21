namespace AspNetCoreJwtBearerDPoP.Abstractions;

/// <summary>
/// Default names for the JWT + DPoP authentication scheme (RFC 9449).
/// </summary>
public static class JwtBearerDPoPDefaults
{
    /// <summary>
    /// Authentication scheme name used with <c>[Authorize(AuthenticationSchemes = ...)]</c>
    /// and <c>AddJwtBearerDPoP</c>.
    /// </summary>
    public const string AuthenticationScheme = "JwtBearerDPoP";

    /// <summary>
    /// Default access-token claim holding the client public JWK JSON.
    /// </summary>
    public const string PublicKeyClaimName = "jwk";

    /// <summary>
    /// Default DPoP proof claim for the access-token hash (<c>ath</c>).
    /// </summary>
    public const string AccessTokenHashClaimName = "ath";

    /// <summary>
    /// Default header names for the access token.
    /// </summary>
    public static IReadOnlyList<string> AccessTokenHeaderNames { get; } = ["token"];

    /// <summary>
    /// Default query names for the access token.
    /// </summary>
    public static IReadOnlyList<string> AccessTokenQueryNames { get; } = ["token"];

    /// <summary>
    /// Default header names for the DPoP proof (RFC 9449).
    /// </summary>
    public static IReadOnlyList<string> DPoPHeaderNames { get; } = ["DPoP"];

    /// <summary>
    /// Default query names for the DPoP proof.
    /// </summary>
    public static IReadOnlyList<string> DPoPQueryNames { get; } = ["DPoP"];
}
