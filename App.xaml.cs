using System.Windows;
using System.Runtime.InteropServices;
using System.IO;
using System.ComponentModel;
using System.Diagnostics;
using Microsoft.Win32.SafeHandles;
using System.Windows.Threading;

namespace Winvexa;

public partial class App : Application
{
    private const int AttachParentProcess = -1;
    private const string GuiMutexName = @"Local\Winvexa.DesktopApplication";
    private const string GuiActivationEventName = @"Local\Winvexa.DesktopApplication.Activate";
    private Mutex? _guiMutex;
    private EventWaitHandle? _guiActivationEvent;
    private DispatcherTimer? _guiActivationTimer;
    private bool _launcherOnly;

    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        if (e.Args.Contains("--watchlist-worker", StringComparer.OrdinalIgnoreCase))
        {
            ShutdownMode = ShutdownMode.OnExplicitShutdown;
            try
            {
                var exitCode = await UnknownThreatWatchlistWorker.RunAsync((threatName, filePath, details) =>
                    Dispatcher.BeginInvoke(new Action(() =>
                        UnknownThreatWatchlistWorker.ShowNotification(threatName, filePath, details))));
                Shutdown(exitCode);
            }
            catch (Exception exception)
            {
                WriteWatchlistWorkerFailure(exception);
                Shutdown((int)ConsoleExitCode.GeneralError);
            }
            return;
        }

        var launchGui = e.Args.Length == 0 ||
                        e.Args.Contains("--gui", StringComparer.OrdinalIgnoreCase) ||
                        e.Args.Contains("/gui", StringComparer.OrdinalIgnoreCase);
        if (launchGui)
        {
            var launcherOnly = e.Args.All(argument =>
                argument.Equals("--gui", StringComparison.OrdinalIgnoreCase) ||
                argument.Equals("/gui", StringComparison.OrdinalIgnoreCase));
            _guiMutex = new Mutex(initiallyOwned: true, GuiMutexName, out var createdNew);
            if (!createdNew)
            {
                try
                {
                    using var activationEvent = EventWaitHandle.OpenExisting(GuiActivationEventName);
                    activationEvent.Set();
                }
                catch (WaitHandleCannotBeOpenedException)
                {
                    MessageBox.Show(
                        "Another Winvexa process is starting. Please try again in a moment.",
                        "Winvexa is starting",
                        MessageBoxButton.OK,
                        MessageBoxImage.Information);
                }
                catch (UnauthorizedAccessException exception)
                {
                    MessageBox.Show(
                        $"Winvexa is already running, but its window could not be activated.{Environment.NewLine}{exception.Message}",
                        "Winvexa is already running",
                        MessageBoxButton.OK,
                        MessageBoxImage.Warning);
                }
                _guiMutex.Dispose();
                _guiMutex = null;
                Shutdown();
                return;
            }

            _guiActivationEvent = new EventWaitHandle(
                false,
                EventResetMode.AutoReset,
                GuiActivationEventName);
            _guiActivationTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(400) };
            _guiActivationTimer.Tick += (_, _) =>
            {
                if (_guiActivationEvent.WaitOne(0))
                    ActivateCurrentWindow();
            };
            _guiActivationTimer.Start();

            try
            {
                _launcherOnly = launcherOnly;
                var settingsWarning = GlassThemeService.Initialize(this);
                OpenEntryWindow();

                if (settingsWarning is not null)
                {
                    MessageBox.Show(
                        MainWindow,
                        settingsWarning,
                        "Liquid Glass setting unavailable",
                        MessageBoxButton.OK,
                        MessageBoxImage.Warning);
                }
            }
            catch (Exception exception)
            {
                MessageBox.Show(
                    $"Winvexa could not finish starting.{Environment.NewLine}{Environment.NewLine}{exception.Message}{Environment.NewLine}{Environment.NewLine}Close this message and try starting Winvexa again. If the problem continues, repair or reinstall the application.",
                    "Winvexa startup error",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
                Shutdown((int)ConsoleExitCode.GeneralError);
            }
            return;
        }

        ConsoleHost.Initialize();
        try
        {
            var exitCode = await ConsoleRunner.RunAsync(e.Args);
            Environment.ExitCode = exitCode;
            Shutdown(exitCode);
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine($"Fatal error: {exception.Message}");
            Environment.ExitCode = (int)ConsoleExitCode.GeneralError;
            Shutdown((int)ConsoleExitCode.GeneralError);
        }
    }

    internal void OpenMainWindow(bool openSettings = false)
    {
        if (MainWindow is MainWindow existingMainWindow)
        {
            ActivateWindow(existingMainWindow);
            if (openSettings)
                existingMainWindow.ShowSettingsDialog();
            return;
        }

        var launcher = Windows.OfType<LauncherWindow>().FirstOrDefault();
        var mainWindow = new MainWindow();
        MainWindow = mainWindow;
        mainWindow.Show();
        launcher?.Close();

        if (openSettings)
            mainWindow.ShowSettingsDialog();
    }

    private void OpenEntryWindow()
    {
        Window window = _launcherOnly
            ? new LauncherWindow()
            : new MainWindow();
        MainWindow = window;
        window.Show();
        EnsureRegisteredWatchlistTaskRunning();
    }

    private static void EnsureRegisteredWatchlistTaskRunning()
    {
        if (UnknownThreatWatchlistWorker.IsRunning)
            return;

        const string taskName = "Winvexa Unknown Threat Watchlist";
        try
        {
            using var query = StartTaskSchedulerCommand("/Query", "/TN", taskName);
            if (!query.WaitForExit(5000))
            {
                StopOwnedProcess(query);
                WriteWatchlistWorkerFailure(new TimeoutException("Checking the registered background watchlist task timed out."));
                return;
            }

            if (query.ExitCode != 0)
                return;

            using var start = StartTaskSchedulerCommand("/Run", "/TN", taskName);
            if (!start.WaitForExit(5000))
            {
                StopOwnedProcess(start);
                WriteWatchlistWorkerFailure(new TimeoutException("Starting the registered background watchlist task timed out."));
                return;
            }

            if (start.ExitCode != 0)
                WriteWatchlistWorkerFailure(new InvalidOperationException(
                    $"Windows Task Scheduler could not start the registered watchlist task (exit code {start.ExitCode})."));
        }
        catch (Exception exception) when (
            exception is InvalidOperationException or IOException or Win32Exception or ObjectDisposedException)
        {
            WriteWatchlistWorkerFailure(exception);
        }
    }

    private static Process StartTaskSchedulerCommand(params string[] arguments)
    {
        var startInfo = new ProcessStartInfo("schtasks.exe")
        {
            UseShellExecute = false,
            CreateNoWindow = true
        };
        foreach (var argument in arguments)
            startInfo.ArgumentList.Add(argument);

        var process = Process.Start(startInfo)
            ?? throw new InvalidOperationException("Windows could not start Task Scheduler's command-line utility.");
        return process;
    }

    private static void StopOwnedProcess(Process process)
    {
        if (process.HasExited)
            return;
        try
        {
            process.Kill(entireProcessTree: true);
            process.WaitForExit();
        }
        catch (Exception exception) when (
            exception is InvalidOperationException or Win32Exception or NotSupportedException)
        {
            WriteWatchlistWorkerFailure(new InvalidOperationException(
                "Winvexa could not stop its timed-out Task Scheduler query process.", exception));
        }
    }

    private void ActivateCurrentWindow()
    {
        if (MainWindow is LauncherWindow launcher && launcher.IsVisible)
        {
            ActivateWindow(launcher);
            return;
        }

        if (MainWindow is MainWindow mainWindow)
        {
            ActivateWindow(mainWindow);
            return;
        }

        OpenMainWindow();
    }

    private static void ActivateWindow(Window window)
    {
        if (window.WindowState == WindowState.Minimized)
            window.WindowState = WindowState.Normal;
        if (!window.IsVisible)
            window.Show();
        window.Activate();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _guiActivationTimer?.Stop();
        _guiActivationEvent?.Dispose();
        _guiActivationEvent = null;
        _guiMutex?.ReleaseMutex();
        _guiMutex?.Dispose();
        _guiMutex = null;
        base.OnExit(e);
    }

    private static void WriteWatchlistWorkerFailure(Exception exception)
    {
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var directory = string.IsNullOrWhiteSpace(appData)
            ? Path.Combine(Path.GetTempPath(), "Winvexa", "Logs")
            : Path.Combine(appData, "Winvexa", "Logs");
        try
        {
            Directory.CreateDirectory(directory);
            File.AppendAllText(
                Path.Combine(directory, "watchlist-worker.log"),
                $"[{DateTimeOffset.UtcNow:O}] Background watcher stopped with an error: {exception}{Environment.NewLine}");
        }
        catch (Exception logException) when (
            logException is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            Console.Error.WriteLine($"Background watcher stopped: {exception.Message}. Its log could not be written: {logException.Message}");
        }
    }

    private static class ConsoleHost
    {
        private const int StandardInput = -10;
        private const int StandardOutput = -11;
        private const int StandardError = -12;
        private const uint GenericRead = 0x80000000;
        private const uint GenericWrite = 0x40000000;
        private const uint ShareRead = 0x00000001;
        private const uint ShareWrite = 0x00000002;
        private const uint OpenExisting = 3;
        private static readonly IntPtr InvalidHandle = new(-1);

        public static void Initialize()
        {
            if (!AttachConsole(AttachParentProcess))
                _ = AllocConsole();

            try
            {
                Console.OutputEncoding = System.Text.Encoding.UTF8;
                Console.InputEncoding = System.Text.Encoding.UTF8;
                var output = GetOrOpenConsoleHandle(StandardOutput, "CONOUT$", GenericWrite, ShareWrite);
                var error = GetOrOpenConsoleHandle(StandardError, "CONOUT$", GenericWrite, ShareWrite);
                var input = GetOrOpenConsoleHandle(StandardInput, "CONIN$", GenericRead, ShareRead);
                Console.SetOut(new StreamWriter(new FileStream(new SafeFileHandle(output, ownsHandle: false), FileAccess.Write), Console.OutputEncoding) { AutoFlush = true });
                Console.SetError(new StreamWriter(new FileStream(new SafeFileHandle(error, ownsHandle: false), FileAccess.Write), Console.OutputEncoding) { AutoFlush = true });
                Console.SetIn(new StreamReader(new FileStream(new SafeFileHandle(input, ownsHandle: false), FileAccess.Read), Console.InputEncoding));
            }
            catch (Exception exception) when (exception is IOException or InvalidOperationException or Win32Exception)
            {
                Console.Error.WriteLine($"Could not initialize the command console: {exception.Message}");
            }
        }

        private static IntPtr GetOrOpenConsoleHandle(int standardHandle, string device, uint access, uint share)
        {
            var handle = GetStdHandle(standardHandle);
            if (handle != IntPtr.Zero && handle != InvalidHandle)
                return handle;

            handle = CreateFile(device, access, share, IntPtr.Zero, OpenExisting, 0, IntPtr.Zero);
            if (handle == InvalidHandle)
                throw new Win32Exception(Marshal.GetLastWin32Error(), $"Could not open {device}.");
            if (!SetStdHandle(standardHandle, handle))
                throw new Win32Exception(Marshal.GetLastWin32Error(), $"Could not set the standard {device} handle.");
            return handle;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool AttachConsole(int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool AllocConsole();

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GetStdHandle(int standardHandle);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetStdHandle(int standardHandle, IntPtr handle);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateFile(string fileName, uint desiredAccess, uint shareMode, IntPtr securityAttributes,
            uint creationDisposition, uint flagsAndAttributes, IntPtr templateFile);
    }
}
