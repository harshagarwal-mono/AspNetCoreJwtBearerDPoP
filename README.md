# AspNetCoreJwtBearerDPoP

ASP.NET Core authentication handler for **sender-constrained JWT access tokens** using **DPoP proofs** ([RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449)).

A stolen access token alone is not enough when DPoP is required: every request must also carry a DPoP proof signed with the client's **private** key, whose public half is embedded in the access token. Set `RequireDPoP` to `false` to validate the access token only.

- Familiar shape: `AddJwtBearerDPoP(...)`, just like `AddJwtBearer(...)`
- Reads the access token and the DPoP proof from **headers or the query string**, so browser WebSocket upgrades work (browsers cannot set custom WebSocket headers)
- Pluggable signing-key resolution and validation events
- Optional `htm` / `htu` request binding
- Optional access-token allowlist via `ITokenStore` (bring your own Redis or other store)
- Targets `net10.0`

| Package | Purpose |
| --- | --- |
| `AspNetCoreJwtBearerDPoP` | Handler, `AddJwtBearerDPoP`, `DPoPJwtValidator` |
| `AspNetCoreJwtBearerDPoP.Abstractions` | Options, defaults, events, context types, `ITokenStore` |

## Installation

```bash
dotnet add package AspNetCoreJwtBearerDPoP
```

`AspNetCoreJwtBearerDPoP.Abstractions` is pulled in automatically. Reference it directly only from projects that need the option and event types without the handler.

## Quick start

```csharp
using AspNetCoreJwtBearerDPoP;
using AspNetCoreJwtBearerDPoP.Abstractions;

builder.Services
    .AddAuthentication()
    .AddJwtBearerDPoP(options =>
    {
        options.TokenValidationParameters.ValidIssuer = "https://my-issuer";
        options.TokenValidationParameters.IssuerSigningKey = mySigningKey;
    });

builder.Services.AddAuthorization();

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();
```

Protect an endpoint:

```csharp
[Authorize(AuthenticationSchemes = JwtBearerDPoPDefaults.AuthenticationScheme)]
public class SecureController : ControllerBase { }
```

## How validation works

For each request the handler:

1. Reads the access token and, when `RequireDPoP` is `true` (the default), the DPoP proof (header first, then query string).
2. When an `ITokenStore` is registered, accepts the access token only if `ContainsAsync` returns `true`. A missing token and a store error both fail with the same message. With no store registered, this step is skipped.
3. Validates the access token with `TokenValidationParameters` (signature, issuer, lifetime, …).
4. When `RequireDPoP` is `true`, reads the client public JWK from the access-token claim `jwk`, validates the DPoP proof signature with that public key, requires the DPoP claim `ath` to equal `base64url(SHA-256(ASCII(access_token)))`, and optionally checks `htm` / `htu`.

On success the access-token claims become the authenticated principal. On failure the result is `AuthenticateResult.Fail` (401 on challenge).

## Client flow

1. Generate an EC P-256 (or RSA) key pair and keep the private key on the client.
2. Obtain an access token from your issuer that contains the **public** JWK as claim `jwk`.
3. For each request, create a fresh DPoP proof JWT signed with the **private** key:

   ```json
   { "alg": "ES256", "typ": "dpop+jwt" }
   ```

   | Claim | Required | Description |
   | --- | --- | --- |
   | `ath` | Yes | `base64url(SHA-256(ASCII access token))` |
   | `iat` | Recommended | Issued-at (unix seconds) |
   | `jti` | Recommended | Unique id per proof |
   | `htm` | When `ValidateHtm` is on | HTTP method, e.g. `GET` |
   | `htu` | When `ValidateHtu` is on | Target URL without query, e.g. `https://localhost/ws` |

4. Send both values:

   ```http
   GET /api/resource
   token: <access-jwt>
   DPoP: <dpop-proof-jwt>
   ```

   or, for browser WebSockets:

   ```text
   wss://localhost/ws?token=<access-jwt>&DPoP=<dpop-proof-jwt>
   ```

Computing `ath` in Node:

```js
const crypto = require('crypto');
const ath = crypto.createHash('sha256').update(accessToken, 'ascii').digest('base64url');
```

On the server, `DPoPJwtValidator.ComputeAccessTokenHash(accessToken)` produces the same value.

## Options

| Option | Default | Description |
| --- | --- | --- |
| `TokenValidationParameters` | validate issuer, signing key, lifetime (1 min skew) | Access-token validation |
| `AccessTokenHeaderNames` | `token` | Headers checked for the access token |
| `AccessTokenQueryNames` | `token` | Query keys checked when no header is present |
| `DPoPHeaderNames` | `DPoP` | Headers checked for the DPoP proof |
| `DPoPQueryNames` | `DPoP` | Query keys checked when no header is present |
| `PublicKeyClaimName` | `jwk` | Access-token claim holding the client public JWK JSON |
| `AccessTokenHashClaimName` | `ath` | DPoP claim holding the access-token hash |
| `RequireDPoP` | `true` | Require and validate a DPoP proof. `false` validates the access token only |
| `ValidateHtm` | `false` | Require DPoP `htm` to match the request method |
| `ValidateHtu` | `false` | Require DPoP `htu` to match scheme + host + path |
| `Events` | no-op | See below |

## Token store

`ITokenStore` is an allowlist the library does not implement. Register your own (Redis, a database, anything else) when a cryptographically valid access token must also have been issued and not revoked:

```csharp
builder.Services.AddSingleton<ITokenStore, RedisTokenStore>();
```

```csharp
public sealed class RedisTokenStore(IConnectionMultiplexer redis) : ITokenStore
{
    public async Task<bool> ContainsAsync(string accessToken, CancellationToken cancellationToken = default)
    {
        return await redis.GetDatabase().KeyExistsAsync(accessToken);
    }
}
```

Write the key when you issue the token, with a TTL that matches `exp`, and delete it to revoke. Hash the token inside your store when you would rather not keep the raw JWT as the Redis key. The handler calls `ContainsAsync` before signature and DPoP checks. `true` continues; `false` or a thrown exception fails the request with the same message. If nothing is registered for `ITokenStore`, the handler does not consult a store.

## Events

| Event | Use it to |
| --- | --- |
| `OnMessageReceived` | Override `Token` / `DPoP`, or short-circuit with `context.Fail(...)` / `context.NoResult()` |
| `OnResolveAccessTokenSigningKeys` | Supply signing keys per request (key rotation, keys derived at runtime) |
| `OnTokenValidated` | Add claims or reject the principal after successful validation |

Resolving signing keys at request time:

```csharp
.AddJwtBearerDPoP(options =>
{
    options.Events.OnResolveAccessTokenSigningKeys = context =>
    {
        var keyStore = context.HttpContext.RequestServices.GetRequiredService<IMyKeyStore>();
        context.SigningKeys = keyStore.GetCurrentKeys();
        return Task.CompletedTask;
    };
});
```

## Security notes

- Generate key pairs on the device; never ship a private key in an installer or page.
- Create a fresh DPoP proof (new `jti` / `iat`) for every request.
- Prefer headers over the query string when the client allows it; query strings can end up in logs.
- This package does not track `jti` values, so it does not prevent replay of a captured proof within the access token's lifetime. Add a replay cache in `OnTokenValidated` if you need that guarantee.

## License

[MIT](LICENSE)
