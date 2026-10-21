namespace AspNetCoreJwtBearerDPoP.Abstractions;

/// <summary>
/// Parameters for DPoP proof validation beyond the access-token <see cref="Microsoft.IdentityModel.Tokens.TokenValidationParameters"/>.
/// </summary>
public sealed class DPoPValidationParameters
{
    /// <summary>
    /// Access-token claim holding the client public JWK JSON.
    /// </summary>
    public required string PublicKeyClaimName { get; init; }

    /// <summary>
    /// DPoP proof claim for the access-token hash (RFC 9449 <c>ath</c>).
    /// </summary>
    public required string AccessTokenHashClaimName { get; init; }

    /// <summary>
    /// When set, requires DPoP <c>htm</c> to match this HTTP method.
    /// </summary>
    public string? ExpectedHtm { get; init; }

    /// <summary>
    /// When set, requires DPoP <c>htu</c> to match this URI (no query/fragment).
    /// </summary>
    public string? ExpectedHtu { get; init; }
}
