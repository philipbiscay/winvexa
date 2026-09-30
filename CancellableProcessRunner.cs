using System.ComponentModel;
using System.Diagnostics;
using System.IO;

namespace Winvexa;

internal enum ProcessStopPolicy
{
    TerminateProcessTree,
    FinishCurrentOperation
}

internal sealed class ProcessStopRequestedException(string operation, CancellationToken cancellationToken)
    : OperationCanceledException($"Stop was confirmed for '{operation}' after the protected Windows operation exited.", null, cancellationToken);

internal static class CancellableProcessRunner
{
    public static async Task<CommandResult> RunAsync(
        ProcessStartInfo startInfo,
        string operation,
        Action<string> log,
        CancellationToken cancellationToken,
        ProcessStopPolicy stopPolicy = ProcessStopPolicy.TerminateProcessTree,
        TimeSpan? timeout = null,
        Func<Task>? onStopRequested = null)
    {
        cancellationToken.ThrowIfCancellationRequested();

        using var process = new Process { StartInfo = startInfo };
        try
        {
            if (!process.Start())
                throw new InvalidOperationException($"Windows could not start '{startInfo.FileName}'.");
        }
        catch (Exception exception) when (exception is Win32Exception or FileNotFoundException)
        {
            throw new InvalidOperationException($"Could not start '{startInfo.FileName}': {exception.Message}", exception);
        }

        log($"Started '{Path.GetFileName(startInfo.FileName)}' process {process.Id} for {operation}.");
        var stdoutTask = process.StandardOutput.ReadToEndAsync();
        var stderrTask = process.StandardError.ReadToEndAsync();
        var exitTask = process.WaitForExitAsync();
        var cancellationTask = cancellationToken.CanBeCanceled
            ? Task.Delay(System.Threading.Timeout.InfiniteTimeSpan, cancellationToken)
            : Task.Delay(System.Threading.Timeout.InfiniteTimeSpan);
        var timeoutTask = timeout is null
            ? Task.Delay(System.Threading.Timeout.InfiniteTimeSpan)
            : Task.Delay(timeout.Value);
        var cancelled = false;
        var timedOut = false;
        Exception? cancellationActionFailure = null;

        while (!exitTask.IsCompleted)
        {
            var completedTask = await Task.WhenAny(exitTask, cancellationTask, timeoutTask);
            if (completedTask == exitTask)
                break;

            if (completedTask == cancellationTask)
            {
                cancelled = true;
                if (stopPolicy == ProcessStopPolicy.FinishCurrentOperation)
                {
                    if (onStopRequested is not null)
                    {
                        try
                        {
                            await onStopRequested();
                        }
                        catch (Exception exception)
                        {
                            cancellationActionFailure = exception;
                            log($"The cancellation action for '{operation}' failed; Winvexa will wait for the active Windows operation to finish safely. Details: {exception}");
                        }
                    }

                    log($"Stop requested during '{operation}'. Waiting for the active Windows operation to finish safely.");
                    await exitTask;
                    break;
                }

                if (onStopRequested is not null)
                {
                    try
                    {
                        await onStopRequested();
                    }
                    catch (Exception exception)
                    {
                        cancellationActionFailure = exception;
                        log($"The cancellation action for '{operation}' failed; Winvexa will still stop its owned process. Details: {exception}");
                    }
                }

                TerminateProcessTree(process, operation, log);
                await exitTask;
                break;
            }

            timedOut = true;
            if (stopPolicy == ProcessStopPolicy.FinishCurrentOperation)
            {
                log($"'{operation}' exceeded its expected run time. Waiting for the active Windows operation to finish safely.");
                await exitTask;
                break;
            }

            TerminateProcessTree(process, operation, log);
            await exitTask;
            break;
        }

        var result = new CommandResult(process.ExitCode, await stdoutTask, await stderrTask);
        log($"'{operation}' exited with code {result.ExitCode}.");
        if (!string.IsNullOrWhiteSpace(result.Output))
            log($"{operation} output: {result.Output.Trim()}");
        if (!string.IsNullOrWhiteSpace(result.Error))
            log($"{operation} diagnostic: {result.Error.Trim()}");

        if (cancelled && cancellationActionFailure is not null)
        {
            throw new InvalidOperationException(
                $"Winvexa could not confirm that Windows accepted the Stop request for '{operation}'. The process exited with code {result.ExitCode}; review its output before deciding whether the operation completed.",
                cancellationActionFailure);
        }
        if (cancelled && stopPolicy == ProcessStopPolicy.FinishCurrentOperation && onStopRequested is not null)
            throw new ProcessStopRequestedException(operation, cancellationToken);
        if (cancelled)
            throw new OperationCanceledException(cancellationToken);
        if (timedOut)
            throw new TimeoutException($"'{Path.GetFileName(startInfo.FileName)}' exceeded its allowed run time of {timeout}.");

        return result;
    }

    internal static void TerminateProcessTree(Process process, string operation, Action<string> log)
    {
        if (process.HasExited)
            return;

        try
        {
            process.Kill(entireProcessTree: true);
            log($"Stop requested termination of the Winvexa-owned process tree for '{operation}'.");
        }
        catch (InvalidOperationException) when (process.HasExited)
        {
        }
        catch (Exception exception) when (exception is Win32Exception or NotSupportedException)
        {
            log($"Could not terminate the process tree for '{operation}': {exception.Message}. Trying to stop the directly owned process.");
            try
            {
                if (!process.HasExited)
                    process.Kill();
            }
            catch (InvalidOperationException) when (process.HasExited)
            {
            }
            catch (Exception fallbackException) when (fallbackException is Win32Exception or NotSupportedException)
            {
                log($"Could not terminate the directly owned process for '{operation}': {fallbackException}");
            }
        }
    }
}
