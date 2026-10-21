namespace AspNetCoreJwtBearerDPoP;

/// <summary>
/// Failure messages returned by <see cref="JwtBearerDPoPHandler"/>.
/// </summary>
internal static class JwtBearerDPoPErrors
{
    /// <summary>Access token or DPoP proof failed validation.</summary>
    public const string AccessTokenOrDPoPProofInvalid = "Access token or DPoP proof is invalid.";

    /// <summary>Access token failed validation while DPoP is not required.</summary>
    public const string AccessTokenInvalid = "Access token is invalid.";

    /// <summary>
    /// Access token is missing from the token store, or the store lookup failed.
    /// </summary>
    public const string AccessTokenNotPresentInTokenStore = "Access token is not present in the token store.";

    /// <summary>Log message written when the token store throws.</summary>
    public const string TokenStoreLookupFailed = "Token store lookup failed.";
}
