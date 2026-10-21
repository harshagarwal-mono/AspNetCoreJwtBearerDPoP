using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using AspNetCoreJwtBearerDPoP.Abstractions;

namespace AspNetCoreJwtBearerDPoP;

/// <summary>
/// Validates an access JWT bound to a DPoP proof (RFC 9449 <c>ath</c> + asymmetric proof signature).
/// </summary>
public static class DPoPJwtValidator
{
    private static readonly JwtSecurityTokenHandler _handler = new();

    /// <summary>
    /// Validates <paramref name="accessToken"/> and <paramref name="dPoP"/>. Returns a principal on success.
    /// </summary>
    public static ClaimsPrincipal? Validate(string accessToken, string dPoP, TokenValidationParameters accessTokenValidationParameters, DPoPValidationParameters dPoPValidationParameters)
    {
        if (string.IsNullOrWhiteSpace(accessToken)
            || string.IsNullOrWhiteSpace(dPoP)
            || accessTokenValidationParameters is null
            || dPoPValidationParameters is null
            || string.IsNullOrWhiteSpace(dPoPValidationParameters.PublicKeyClaimName)
            || string.IsNullOrWhiteSpace(dPoPValidationParameters.AccessTokenHashClaimName))
        {
            return null;
        }

        try
        {
            ClaimsPrincipal principal = _handler.ValidateToken(accessToken, accessTokenValidationParameters, out SecurityToken _);
            string? jwkJson = principal.FindFirst(dPoPValidationParameters.PublicKeyClaimName)?.Value;

            if (string.IsNullOrWhiteSpace(jwkJson))
            {
                return null;
            }

            var clientPublicKey = new JsonWebKey(jwkJson);
            var dPoPParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = clientPublicKey,
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = false,
                RequireExpirationTime = false,
                RequireSignedTokens = true,
            };

            ClaimsPrincipal dPoPPrincipal = _handler.ValidateToken(dPoP, dPoPParameters, out SecurityToken _);

            if (!ValidateDPoP(dPoPPrincipal, dPoPValidationParameters, accessToken))
            {
                return null;
            }

            return principal;
        }
        catch (Exception)
        {
            return null;
        }
    }

    /// <summary>
    /// Checks DPoP proof claims: required <c>ath</c>, and optional <c>htm</c> / <c>htu</c> when expected.
    /// </summary>
    private static bool ValidateDPoP(ClaimsPrincipal dPoPPrincipal, DPoPValidationParameters options, string accessToken)
    {
        string? ath = dPoPPrincipal.FindFirst(options.AccessTokenHashClaimName)?.Value;

        if (string.IsNullOrWhiteSpace(ath) || !FixedTimeEqualsUtf8(ath, ComputeAccessTokenHash(accessToken)))
        {
            return false;
        }

        if (options.ExpectedHtm is not null)
        {
            string? htm = dPoPPrincipal.FindFirst("htm")?.Value;
            if (!string.Equals(htm, options.ExpectedHtm, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }
        }

        if (options.ExpectedHtu is not null)
        {
            string? htu = dPoPPrincipal.FindFirst("htu")?.Value;
            if (!string.Equals(htu, options.ExpectedHtu, StringComparison.Ordinal))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// RFC 9449 <c>ath</c>: base64url-encoded SHA-256 of the access token (ASCII).
    /// </summary>
    public static string ComputeAccessTokenHash(string accessToken)
    {
        byte[] hash = SHA256.HashData(Encoding.ASCII.GetBytes(accessToken));
        return Base64UrlEncoder.Encode(hash);
    }

    private static bool FixedTimeEqualsUtf8(string left, string right)
    {
        byte[] leftBytes = Encoding.UTF8.GetBytes(left);
        byte[] rightBytes = Encoding.UTF8.GetBytes(right);
        return leftBytes.Length == rightBytes.Length
               && CryptographicOperations.FixedTimeEquals(leftBytes, rightBytes);
    }
}
