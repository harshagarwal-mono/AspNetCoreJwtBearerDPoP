namespace AspNetCoreJwtBearerDPoP.Abstractions;

/// <summary>
/// Events for the JWT + DPoP authentication handler.
/// </summary>
public class JwtBearerDPoPEvents
{
    /// <summary>
    /// Invoked after the access token and DPoP strings are read from the request (or overridden).
    /// </summary>
    public Func<JwtBearerDPoPMessageReceivedContext, Task> OnMessageReceived { get; set; } =
        static _ => Task.CompletedTask;

    /// <summary>
    /// Invoked to supply or replace access-token signing keys before validation.
    /// </summary>
    public Func<JwtBearerDPoPResolveSigningKeysContext, Task> OnResolveAccessTokenSigningKeys { get; set; } =
        static _ => Task.CompletedTask;

    /// <summary>
    /// Invoked after a successful authentication.
    /// </summary>
    public Func<JwtBearerDPoPTokenValidatedContext, Task> OnTokenValidated { get; set; } =
        static _ => Task.CompletedTask;

    /// <summary>
    /// Invokes <see cref="OnMessageReceived"/>.
    /// </summary>
    public virtual Task MessageReceived(JwtBearerDPoPMessageReceivedContext context)
    {
        return OnMessageReceived(context);
    }

    /// <summary>
    /// Invokes <see cref="OnResolveAccessTokenSigningKeys"/>.
    /// </summary>
    public virtual Task ResolveAccessTokenSigningKeys(JwtBearerDPoPResolveSigningKeysContext context)
    {
        return OnResolveAccessTokenSigningKeys(context);
    }

    /// <summary>
    /// Invokes <see cref="OnTokenValidated"/>.
    /// </summary>
    public virtual Task TokenValidated(JwtBearerDPoPTokenValidatedContext context)
    {
        return OnTokenValidated(context);
    }
}
