using Microsoft.Extensions.Options;

namespace AspNetCoreJwtBearerDPoP.Tests.TestHelpers;

internal sealed class TestOptionsMonitor<T>(T options) : IOptionsMonitor<T>
    where T : class
{
    public T CurrentValue { get; } = options;

    public T Get(string? name)
    {
        return CurrentValue;
    }

    public IDisposable? OnChange(Action<T, string?> listener)
    {
        return null;
    }
}
