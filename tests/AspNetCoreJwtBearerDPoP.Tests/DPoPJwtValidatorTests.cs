using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using AspNetCoreJwtBearerDPoP.Abstractions;
using AspNetCoreJwtBearerDPoP.Tests.TestHelpers;

namespace AspNetCoreJwtBearerDPoP.Tests;

public sealed class DPoPJwtValidatorTests
{
    [Fact]
    public void ComputeAccessTokenHash_ReturnsBase64UrlSha256OfAsciiBytes()
    {
        const string accessToken = "access.token.value";
        byte[] expectedHash = SHA256.HashData(Encoding.ASCII.GetBytes(accessToken));
        string expected = Base64UrlEncoder.Encode(expectedHash);

        Assert.Equal(expected, DPoPJwtValidator.ComputeAccessTokenHash(accessToken));
    }

    [Theory]
    [InlineData(null, "dpop")]
    [InlineData("", "dpop")]
    [InlineData("   ", "dpop")]
    [InlineData("access", null)]
    [InlineData("access", "")]
    [InlineData("access", "   ")]
    public void Validate_WhenAccessOrDPoPMissing_ReturnsNull(string? accessToken, string? dPoP)
    {
        (SymmetricSecurityKey issuerKey, _) = DPoPTestTokenFactory.CreateIssuerSigning();

        ClaimsPrincipal? result = DPoPJwtValidator.Validate(
            accessToken!,
            dPoP!,
            DPoPTestTokenFactory.CreateAccessTokenValidationParameters(issuerKey),
            DPoPTestTokenFactory.CreateDPoPParameters());

        Assert.Null(result);
    }

    [Fact]
    public void Validate_WhenAccessTokenValidationParametersNull_ReturnsNull()
    {
        Assert.Null(DPoPJwtValidator.Validate(
            "access",
            "dpop",
            accessTokenValidationParameters: null!,
            DPoPTestTokenFactory.CreateDPoPParameters()));
    }

    [Fact]
    public void Validate_WhenDPoPValidationParametersNull_ReturnsNull()
    {
        (SymmetricSecurityKey issuerKey, _) = DPoPTestTokenFactory.CreateIssuerSigning();

        Assert.Null(DPoPJwtValidator.Validate(
            "access",
            "dpop",
            DPoPTestTokenFactory.CreateAccessTokenValidationParameters(issuerKey),
            dPoPValidationParameters: null!));
    }

    [Theory]
    [InlineData(null, "ath")]
    [InlineData("", "ath")]
    [InlineData("   ", "ath")]
    [InlineData("jwk", null)]
    [InlineData("jwk", "")]
    [InlineData("jwk", "   ")]
    public void Validate_WhenClaimNamesMissing_ReturnsNull(string? publicKeyClaimName, string? athClaimName)
    {
        (SymmetricSecurityKey issuerKey, _) = DPoPTestTokenFactory.CreateIssuerSigning();
        var parameters = new DPoPValidationParameters
        {
            PublicKeyClaimName = publicKeyClaimName!,
            AccessTokenHashClaimName = athClaimName!,
        };

        Assert.Null(DPoPJwtValidator.Validate(
            "access",
            "dpop",
            DPoPTestTokenFactory.CreateAccessTokenValidationParameters(issuerKey),
            parameters));
    }

    [Fact]
    public void Validate_WhenTokensValid_ReturnsAccessPrincipal()
    {
        (SymmetricSecurityKey issuerKey, SigningCredentials issuerCredentials) = DPoPTestTokenFactory.CreateIssuerSigning();
        (ECDsa clientEcdsa, string publicJwk, _) = DPoPTestTokenFactory.CreateClientKeyPair();
        string accessToken = DPoPTestTokenFactory.CreateAccessToken(issuerCredentials, publicJwk);
        string dPoP = DPoPTestTokenFactory.CreateDPoP(accessToken, clientEcdsa);

        ClaimsPrincipal? principal = DPoPJwtValidator.Validate(
            accessToken,
            dPoP,
            DPoPTestTokenFactory.CreateAccessTokenValidationParameters(issuerKey),
            DPoPTestTokenFactory.CreateDPoPParameters());

        Assert.NotNull(principal);
        Assert.Equal("user-1", principal.FindFirst(ClaimTypes.NameIdentifier)?.Value);
        Assert.Equal(publicJwk, principal.FindFirst(JwtBearerDPoPDefaults.PublicKeyClaimName)?.Value);
    }

    [Fact]
    public void Validate_WhenHtmAndHtuMatch_ReturnsPrincipal()
    {
        (SymmetricSecurityKey issuerKey, SigningCredentials issuerCredentials) = DPoPTestTokenFactory.CreateIssuerSigning();
        (ECDsa clientEcdsa, string publicJwk, _) = DPoPTestTokenFactory.CreateClientKeyPair();
        string accessToken = DPoPTestTokenFactory.CreateAccessToken(issuerCredentials, publicJwk);
        string dPoP = DPoPTestTokenFactory.CreateDPoP(
            accessToken,
            clientEcdsa,
            htm: "GET",
            htu: "https://localhost/ws");

        ClaimsPrincipal? principal = DPoPJwtValidator.Validate(
            accessToken,
            dPoP,
            DPoPTestTokenFactory.CreateAccessTokenValidationParameters(issuerKey),
            DPoPTestTokenFactory.CreateDPoPParameters(expectedHtm: "get", expectedHtu: "https://localhost/ws"));

        Assert.NotNull(principal);
    }

    [Fact]
    public void Validate_WhenAccessTokenMissingJwkClaim_ReturnsNull()
    {
        (SymmetricSecurityKey issuerKey, SigningCredentials issuerCredentials) = DPoPTestTokenFactory.CreateIssuerSigning();
        (ECDsa clientEcdsa, _, _) = DPoPTestTokenFactory.CreateClientKeyPair();
        var token = new System.IdentityModel.Tokens.Jwt.JwtSecurityToken(
            issuer: "https://test-issuer",
            claims: [new Claim(ClaimTypes.NameIdentifier, "user-1")],
            expires: DateTime.UtcNow.AddHours(1),
            signingCredentials: issuerCredentials);
        string accessToken = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler().WriteToken(token);
        string dPoP = DPoPTestTokenFactory.CreateDPoP(accessToken, clientEcdsa);

        Assert.Null(DPoPJwtValidator.Validate(
            accessToken,
            dPoP,
            DPoPTestTokenFactory.CreateAccessTokenValidationParameters(issuerKey),
            DPoPTestTokenFactory.CreateDPoPParameters()));
    }

    [Fact]
    public void Validate_WhenAthMissing_ReturnsNull()
    {
        (SymmetricSecurityKey issuerKey, SigningCredentials issuerCredentials) = DPoPTestTokenFactory.CreateIssuerSigning();
        (ECDsa clientEcdsa, string publicJwk, _) = DPoPTestTokenFactory.CreateClientKeyPair();
        string accessToken = DPoPTestTokenFactory.CreateAccessToken(issuerCredentials, publicJwk);
        string dPoP = DPoPTestTokenFactory.CreateDPoP(accessToken, clientEcdsa, omitAth: true);

        Assert.Null(DPoPJwtValidator.Validate(
            accessToken,
            dPoP,
            DPoPTestTokenFactory.CreateAccessTokenValidationParameters(issuerKey),
            DPoPTestTokenFactory.CreateDPoPParameters()));
    }

    [Fact]
    public void Validate_WhenAthMismatch_ReturnsNull()
    {
        (SymmetricSecurityKey issuerKey, SigningCredentials issuerCredentials) = DPoPTestTokenFactory.CreateIssuerSigning();
        (ECDsa clientEcdsa, string publicJwk, _) = DPoPTestTokenFactory.CreateClientKeyPair();
        string accessToken = DPoPTestTokenFactory.CreateAccessToken(issuerCredentials, publicJwk);
        string dPoP = DPoPTestTokenFactory.CreateDPoP(accessToken, clientEcdsa, athOverride: "wrong-ath-value");

        Assert.Null(DPoPJwtValidator.Validate(
            accessToken,
            dPoP,
            DPoPTestTokenFactory.CreateAccessTokenValidationParameters(issuerKey),
            DPoPTestTokenFactory.CreateDPoPParameters()));
    }

    [Fact]
    public void Validate_WhenExpectedHtmMismatch_ReturnsNull()
    {
        (SymmetricSecurityKey issuerKey, SigningCredentials issuerCredentials) = DPoPTestTokenFactory.CreateIssuerSigning();
        (ECDsa clientEcdsa, string publicJwk, _) = DPoPTestTokenFactory.CreateClientKeyPair();
        string accessToken = DPoPTestTokenFactory.CreateAccessToken(issuerCredentials, publicJwk);
        string dPoP = DPoPTestTokenFactory.CreateDPoP(accessToken, clientEcdsa, htm: "POST");

        Assert.Null(DPoPJwtValidator.Validate(
            accessToken,
            dPoP,
            DPoPTestTokenFactory.CreateAccessTokenValidationParameters(issuerKey),
            DPoPTestTokenFactory.CreateDPoPParameters(expectedHtm: "GET")));
    }

    [Fact]
    public void Validate_WhenExpectedHtuMismatch_ReturnsNull()
    {
        (SymmetricSecurityKey issuerKey, SigningCredentials issuerCredentials) = DPoPTestTokenFactory.CreateIssuerSigning();
        (ECDsa clientEcdsa, string publicJwk, _) = DPoPTestTokenFactory.CreateClientKeyPair();
        string accessToken = DPoPTestTokenFactory.CreateAccessToken(issuerCredentials, publicJwk);
        string dPoP = DPoPTestTokenFactory.CreateDPoP(accessToken, clientEcdsa, htu: "https://other/path");

        Assert.Null(DPoPJwtValidator.Validate(
            accessToken,
            dPoP,
            DPoPTestTokenFactory.CreateAccessTokenValidationParameters(issuerKey),
            DPoPTestTokenFactory.CreateDPoPParameters(expectedHtu: "https://localhost/ws")));
    }

    [Fact]
    public void Validate_WhenAccessTokenSignatureInvalid_ReturnsNull()
    {
        (_, SigningCredentials issuerCredentials) = DPoPTestTokenFactory.CreateIssuerSigning();
        (SymmetricSecurityKey otherKey, _) = DPoPTestTokenFactory.CreateIssuerSigning();
        (ECDsa clientEcdsa, string publicJwk, _) = DPoPTestTokenFactory.CreateClientKeyPair();
        string accessToken = DPoPTestTokenFactory.CreateAccessToken(issuerCredentials, publicJwk);
        string dPoP = DPoPTestTokenFactory.CreateDPoP(accessToken, clientEcdsa);

        Assert.Null(DPoPJwtValidator.Validate(
            accessToken,
            dPoP,
            DPoPTestTokenFactory.CreateAccessTokenValidationParameters(otherKey),
            DPoPTestTokenFactory.CreateDPoPParameters()));
    }

    [Fact]
    public void Validate_WhenDPoPSignedWithDifferentKey_ReturnsNull()
    {
        (SymmetricSecurityKey issuerKey, SigningCredentials issuerCredentials) = DPoPTestTokenFactory.CreateIssuerSigning();
        (_, string publicJwk, _) = DPoPTestTokenFactory.CreateClientKeyPair();
        (ECDsa otherEcdsa, _, _) = DPoPTestTokenFactory.CreateClientKeyPair();
        string accessToken = DPoPTestTokenFactory.CreateAccessToken(issuerCredentials, publicJwk);
        string dPoP = DPoPTestTokenFactory.CreateDPoP(accessToken, otherEcdsa);

        Assert.Null(DPoPJwtValidator.Validate(
            accessToken,
            dPoP,
            DPoPTestTokenFactory.CreateAccessTokenValidationParameters(issuerKey),
            DPoPTestTokenFactory.CreateDPoPParameters()));
    }

    [Fact]
    public void Validate_WhenJwkJsonInvalid_ReturnsNull()
    {
        (SymmetricSecurityKey issuerKey, SigningCredentials issuerCredentials) = DPoPTestTokenFactory.CreateIssuerSigning();
        (ECDsa clientEcdsa, _, _) = DPoPTestTokenFactory.CreateClientKeyPair();
        string accessToken = DPoPTestTokenFactory.CreateAccessToken(issuerCredentials, "{not-json");
        string dPoP = DPoPTestTokenFactory.CreateDPoP(accessToken, clientEcdsa);

        Assert.Null(DPoPJwtValidator.Validate(
            accessToken,
            dPoP,
            DPoPTestTokenFactory.CreateAccessTokenValidationParameters(issuerKey),
            DPoPTestTokenFactory.CreateDPoPParameters()));
    }

    [Fact]
    public void Validate_WhenAccessTokenExpired_ReturnsNull()
    {
        (SymmetricSecurityKey issuerKey, SigningCredentials issuerCredentials) = DPoPTestTokenFactory.CreateIssuerSigning();
        (ECDsa clientEcdsa, string publicJwk, _) = DPoPTestTokenFactory.CreateClientKeyPair();
        string accessToken = DPoPTestTokenFactory.CreateAccessToken(
            issuerCredentials,
            publicJwk,
            expires: DateTime.UtcNow.AddHours(-2));
        string dPoP = DPoPTestTokenFactory.CreateDPoP(accessToken, clientEcdsa);

        Assert.Null(DPoPJwtValidator.Validate(
            accessToken,
            dPoP,
            DPoPTestTokenFactory.CreateAccessTokenValidationParameters(issuerKey),
            DPoPTestTokenFactory.CreateDPoPParameters()));
    }

    [Fact]
    public void Validate_WhenExpectedHtmPresentButClaimMissing_ReturnsNull()
    {
        (SymmetricSecurityKey issuerKey, SigningCredentials issuerCredentials) = DPoPTestTokenFactory.CreateIssuerSigning();
        (ECDsa clientEcdsa, string publicJwk, _) = DPoPTestTokenFactory.CreateClientKeyPair();
        string accessToken = DPoPTestTokenFactory.CreateAccessToken(issuerCredentials, publicJwk);
        string dPoP = DPoPTestTokenFactory.CreateDPoP(accessToken, clientEcdsa);

        Assert.Null(DPoPJwtValidator.Validate(
            accessToken,
            dPoP,
            DPoPTestTokenFactory.CreateAccessTokenValidationParameters(issuerKey),
            DPoPTestTokenFactory.CreateDPoPParameters(expectedHtm: "GET")));
    }

    [Fact]
    public void Validate_WhenExpectedHtuPresentButClaimMissing_ReturnsNull()
    {
        (SymmetricSecurityKey issuerKey, SigningCredentials issuerCredentials) = DPoPTestTokenFactory.CreateIssuerSigning();
        (ECDsa clientEcdsa, string publicJwk, _) = DPoPTestTokenFactory.CreateClientKeyPair();
        string accessToken = DPoPTestTokenFactory.CreateAccessToken(issuerCredentials, publicJwk);
        string dPoP = DPoPTestTokenFactory.CreateDPoP(accessToken, clientEcdsa);

        Assert.Null(DPoPJwtValidator.Validate(
            accessToken,
            dPoP,
            DPoPTestTokenFactory.CreateAccessTokenValidationParameters(issuerKey),
            DPoPTestTokenFactory.CreateDPoPParameters(expectedHtu: "https://localhost/ws")));
    }
}
