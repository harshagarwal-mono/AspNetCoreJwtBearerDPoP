using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using AspNetCoreJwtBearerDPoP.Abstractions;

namespace AspNetCoreJwtBearerDPoP.Tests.TestHelpers;

internal static class DPoPTestTokenFactory
{
    private static readonly JwtSecurityTokenHandler _handler = new();

    public static (ECDsa Ecdsa, string PublicJwkJson, ECDsaSecurityKey SecurityKey) CreateClientKeyPair()
    {
        var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        ECParameters parameters = ecdsa.ExportParameters(includePrivateParameters: true);
        string x = Base64UrlEncoder.Encode(parameters.Q.X);
        string y = Base64UrlEncoder.Encode(parameters.Q.Y);
        string publicJwk = /*lang=json,strict*/ $"{{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"{x}\",\"y\":\"{y}\"}}";
        return (ecdsa, publicJwk, new ECDsaSecurityKey(ecdsa));
    }

    public static (SymmetricSecurityKey Key, SigningCredentials Credentials) CreateIssuerSigning()
    {
        var key = new SymmetricSecurityKey(RandomNumberGenerator.GetBytes(32))
        {
            KeyId = "test-issuer",
        };
        return (key, new SigningCredentials(key, SecurityAlgorithms.HmacSha256));
    }

    public static string CreateAccessToken(
        SigningCredentials issuerCredentials,
        string publicJwkJson,
        IEnumerable<Claim>? extraClaims = null,
        string? publicKeyClaimName = null,
        DateTime? expires = null)
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, "user-1"),
            new(publicKeyClaimName ?? JwtBearerDPoPDefaults.PublicKeyClaimName, publicJwkJson),
        };

        if (extraClaims is not null)
        {
            claims.AddRange(extraClaims);
        }

        DateTime expiresAt = expires ?? DateTime.UtcNow.AddHours(1);
        DateTime notBefore = expiresAt <= DateTime.UtcNow
            ? expiresAt.AddHours(-1)
            : DateTime.UtcNow.AddMinutes(-1);

        var token = new JwtSecurityToken(
            issuer: "https://test-issuer",
            audience: "test-audience",
            claims: claims,
            notBefore: notBefore,
            expires: expiresAt,
            signingCredentials: issuerCredentials);

        return _handler.WriteToken(token);
    }

    public static string CreateDPoP(
        string accessToken,
        ECDsa clientEcdsa,
        string? htm = null,
        string? htu = null,
        string? athOverride = null,
        string? athClaimName = null,
        bool omitAth = false)
    {
        var credentials = new SigningCredentials(new ECDsaSecurityKey(clientEcdsa), SecurityAlgorithms.EcdsaSha256);
        var claims = new List<Claim>
        {
            new(
                "iat",
                DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture),
                ClaimValueTypes.Integer64),
            new("jti", Guid.NewGuid().ToString("N")),
        };

        if (!omitAth)
        {
            claims.Add(new Claim(
                athClaimName ?? JwtBearerDPoPDefaults.AccessTokenHashClaimName,
                athOverride ?? DPoPJwtValidator.ComputeAccessTokenHash(accessToken)));
        }

        if (htm is not null)
        {
            claims.Add(new Claim("htm", htm));
        }

        if (htu is not null)
        {
            claims.Add(new Claim("htu", htu));
        }

        var token = new JwtSecurityToken(claims: claims, signingCredentials: credentials);
        return _handler.WriteToken(token);
    }

    public static TokenValidationParameters CreateAccessTokenValidationParameters(SecurityKey issuerKey)
    {
        return new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = issuerKey,
            ValidateIssuer = true,
            ValidIssuer = "https://test-issuer",
            ValidateAudience = false,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromMinutes(1),
        };
    }

    public static DPoPValidationParameters CreateDPoPParameters(
        string? expectedHtm = null,
        string? expectedHtu = null,
        string? publicKeyClaimName = null,
        string? accessTokenHashClaimName = null)
    {
        return new DPoPValidationParameters
        {
            PublicKeyClaimName = publicKeyClaimName ?? JwtBearerDPoPDefaults.PublicKeyClaimName,
            AccessTokenHashClaimName = accessTokenHashClaimName ?? JwtBearerDPoPDefaults.AccessTokenHashClaimName,
            ExpectedHtm = expectedHtm,
            ExpectedHtu = expectedHtu,
        };
    }
}
