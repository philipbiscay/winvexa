namespace Winvexa;

internal static class OperationCancellationContext
{
    private static readonly AsyncLocal<CancellationToken> CurrentToken = new();

    public static CancellationToken Token => CurrentToken.Value;

    public static bool IsCancellationRequested => CurrentToken.Value.IsCancellationRequested;

    public static IDisposable Enter(CancellationToken cancellationToken)
    {
        var previous = CurrentToken.Value;
        CurrentToken.Value = cancellationToken;
        return new Scope(previous);
    }

    public static void ThrowIfCancellationRequested() =>
        CurrentToken.Value.ThrowIfCancellationRequested();

    private sealed class Scope(CancellationToken previous) : IDisposable
    {
        private bool _disposed;

        public void Dispose()
        {
            if (_disposed)
                return;
            CurrentToken.Value = previous;
            _disposed = true;
        }
    }
}
