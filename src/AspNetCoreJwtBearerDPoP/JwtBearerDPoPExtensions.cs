using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace AspNetCoreJwtBearerDPoP;

/// <summary>
/// Extension methods for registering JWT + DPoP authentication (RFC 9449).
/// </summary>
public static class JwtBearerDPoPExtensions
{
    /// <summary>
    /// Adds JWT access-token + DPoP proof authentication using
    /// <see cref="JwtBearerDPoPDefaults.AuthenticationScheme"/>.
    /// </summary>
    public static AuthenticationBuilder AddJwtBearerDPoP(this AuthenticationBuilder builder)
    {
        return builder.AddJwtBearerDPoP(JwtBearerDPoPDefaults.AuthenticationScheme, _ => { });
    }

    /// <summary>
    /// Adds JWT access-token + DPoP proof authentication using
    /// <see cref="JwtBearerDPoPDefaults.AuthenticationScheme"/>.
    /// </summary>
    public static AuthenticationBuilder AddJwtBearerDPoP(this AuthenticationBuilder builder, Action<JwtBearerDPoPOptions> configureOptions)
    {
        return builder.AddJwtBearerDPoP(JwtBearerDPoPDefaults.AuthenticationScheme, configureOptions);
    }

    /// <summary>
    /// Adds JWT access-token + DPoP proof authentication under <paramref name="authenticationScheme"/>.
    /// </summary>
    public static AuthenticationBuilder AddJwtBearerDPoP(this AuthenticationBuilder builder, string authenticationScheme, Action<JwtBearerDPoPOptions> configureOptions)
    {
        return builder.AddJwtBearerDPoP(authenticationScheme, displayName: null, configureOptions);
    }

    /// <summary>
    /// Adds JWT access-token + DPoP proof authentication under <paramref name="authenticationScheme"/>.
    /// Mirrors the shape of <c>AddJwtBearer</c> for reuse across hosts.
    /// </summary>
    public static AuthenticationBuilder AddJwtBearerDPoP(this AuthenticationBuilder builder, string authenticationScheme, string? displayName, Action<JwtBearerDPoPOptions> configureOptions)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(configureOptions);

        builder.Services.AddOptions<JwtBearerDPoPOptions>(authenticationScheme);
        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<JwtBearerDPoPOptions>, JwtBearerDPoPPostConfigureOptions>());

        return builder.AddScheme<JwtBearerDPoPOptions, JwtBearerDPoPHandler>(authenticationScheme, displayName, configureOptions);
    }
}
