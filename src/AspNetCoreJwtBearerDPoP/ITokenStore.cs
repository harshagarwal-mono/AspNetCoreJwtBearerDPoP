namespace AspNetCoreJwtBearerDPoP;

/// <summary>
/// Optional allowlist of access tokens consulted before cryptographic validation.
/// The library does not ship an implementation; register one (for example a Redis store)
/// when issued tokens must be recognized before a request is accepted.
/// When no implementation is registered, the check is skipped.
/// </summary>
public interface ITokenStore
{
    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="accessToken"/> is present and may be accepted.
    /// A <see langword="false"/> result fails authentication. A thrown exception also fails authentication.
    /// </summary>
    Task<bool> ContainsAsync(string accessToken, CancellationToken cancellationToken = default);
}
