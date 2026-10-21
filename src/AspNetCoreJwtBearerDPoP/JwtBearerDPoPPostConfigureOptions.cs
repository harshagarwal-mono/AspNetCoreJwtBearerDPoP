using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace AspNetCoreJwtBearerDPoP;

/// <summary>
/// Applies safe defaults after <see cref="JwtBearerDPoPOptions"/> is configured.
/// </summary>
public sealed class JwtBearerDPoPPostConfigureOptions : IPostConfigureOptions<JwtBearerDPoPOptions>
{
    /// <inheritdoc />
    public void PostConfigure(string? name, JwtBearerDPoPOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        options.Events ??= new JwtBearerDPoPEvents();

        options.TokenValidationParameters ??= new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            ValidateIssuer = true,
            ValidateAudience = false,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromMinutes(1),
        };

        if (string.IsNullOrWhiteSpace(options.PublicKeyClaimName))
        {
            options.PublicKeyClaimName = JwtBearerDPoPDefaults.PublicKeyClaimName;
        }

        if (string.IsNullOrWhiteSpace(options.AccessTokenHashClaimName))
        {
            options.AccessTokenHashClaimName = JwtBearerDPoPDefaults.AccessTokenHashClaimName;
        }

        EnsureNames(options.AccessTokenHeaderNames, JwtBearerDPoPDefaults.AccessTokenHeaderNames);
        EnsureNames(options.AccessTokenQueryNames, JwtBearerDPoPDefaults.AccessTokenQueryNames);
        EnsureNames(options.DPoPHeaderNames, JwtBearerDPoPDefaults.DPoPHeaderNames);
        EnsureNames(options.DPoPQueryNames, JwtBearerDPoPDefaults.DPoPQueryNames);
    }

    private static void EnsureNames(IList<string> target, IReadOnlyList<string> defaults)
    {
        if (target.Count > 0)
        {
            return;
        }

        foreach (string value in defaults)
        {
            target.Add(value);
        }
    }
}
