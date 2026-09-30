using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Security.Principal;

namespace Winvexa;

internal enum ConsoleExitCode
{
    Success = 0,
    GeneralError = 1,
    AdministratorRequired = 2,
    WindowsUpdateError = 3,
    DefenderError = 4,
    DriveCheckError = 5,
    CleanupError = 6,
    RestartRequired = 10
}

internal static class ConsoleRunner
{
    private sealed class SessionLog
    {
        private readonly string _path;

        public SessionLog()
        {
            var appData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            var logDirectory = string.IsNullOrWhiteSpace(appData)
                ? System.IO.Path.Combine(System.IO.Path.GetTempPath(), "Winvexa", "Logs")
                : System.IO.Path.Combine(appData, "Winvexa", "Logs");
            try
            {
                Directory.CreateDirectory(logDirectory);
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                logDirectory = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "Winvexa", "Logs");
                try
                {
                    Directory.CreateDirectory(logDirectory);
                    Console.Error.WriteLine($"Could not create the preferred log folder: {exception.Message}. Using {logDirectory}.");
                }
                catch (Exception fallbackException) when (fallbackException is IOException or UnauthorizedAccessException)
                {
                    throw new IOException($"Could not create a session log folder. Preferred location: {exception.Message}; fallback location: {fallbackException.Message}", fallbackException);
                }
            }
            _path = System.IO.Path.Combine(logDirectory, $"console-{DateTime.Now:yyyyMMdd-HHmmssfff}-{Environment.ProcessId}.log");
        }

        public string Path => _path;

        public void Write(string message)
        {
            var line = $"[{DateTime.Now:HH:mm:ss}] {message}";
            Console.WriteLine(line);
            try
            {
                File.AppendAllText(_path, $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff zzz}] {message}{Environment.NewLine}");
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                Console.Error.WriteLine($"ERROR: Could not write the detailed log '{_path}': {exception.Message}");
                throw;
            }
        }
    }

    private sealed class RepairReport
    {
        public long CleanedBytes { get; set; }
        public int DrivesChecked { get; set; }
        public string Defender { get; set; } = "Not run";
        public string WindowsUpdate { get; set; } = "Not run";
        public bool RestartRequired { get; set; }
        public ConsoleExitCode ExitCode { get; set; }
    }

    public static async Task<int> RunAsync(string[] arguments)
    {
        var command = ParseCommand(
            arguments,
            out var fullScan,
            out var elevated,
            out var installerPath,
            out var parseError);
        if (parseError is not null)
        {
            Console.Error.WriteLine(parseError);
            PrintHelp();
            return (int)ConsoleExitCode.GeneralError;
        }
        if (command == "/help")
        {
            PrintHelp();
            return (int)ConsoleExitCode.Success;
        }

        var log = new SessionLog();
        PrintBanner();
        log.Write($"Windows version: {GetWindowsVersion()}");
        log.Write($"Command: {command}{(fullScan ? " --full" : string.Empty)}");
        log.Write($"Detailed log: {log.Path}");

        if (!OperatingSystem.IsWindowsVersionAtLeast(10, 0, 22000))
        {
            log.Write("This program requires Windows 11 build 22000 or later.");
            return (int)ConsoleExitCode.GeneralError;
        }

        if (command == "/install")
        {
            return await RunInstallerAsync(installerPath, log);
        }

        var service = new MaintenanceService(log.Write);
        if (command != "/cleanup" && !IsAdministrator())
        {
            Console.WriteLine();
            Console.WriteLine("Administrator privileges required.");
            Console.WriteLine("Requesting Windows administrator permission...");
            log.Write("Administrator privileges required; requesting the standard Windows UAC prompt.");
            return await RequestElevationAsync(command, fullScan, elevated, log);
        }

        Console.WriteLine();
        if (IsAdministrator())
        {
            Console.WriteLine("Administrator privileges confirmed.");
            log.Write("Administrator privileges confirmed.");
        }
        else
        {
            Console.WriteLine("Running cleanup without administrator privileges; inaccessible locations will be skipped or reported.");
            log.Write("Running cleanup without administrator privileges.");
        }
        Console.WriteLine("Starting Winvexa...");

        var report = new RepairReport();
        switch (command)
        {
            case "/scan":
                await RunScanAsync(service, log, report);
                break;
            case "/repair":
                await RunRepairAsync(service, log, report);
                break;
            case "/cleanup":
                await RunCleanupAsync(service, log, report);
                break;
            case "/drives":
                await ExecuteStageAsync(log, report, ConsoleExitCode.DriveCheckError, "Checking drive health...", async () =>
                {
                    await RunDriveCheckAsync(service, log, report);
                });
                break;
            case "/defender":
                await RunDefenderAsync(service, log, report, fullScan);
                break;
            case "/update":
                await ExecuteStageAsync(log, report, ConsoleExitCode.WindowsUpdateError, "Scanning, repairing, and verifying Windows Update...", async () =>
                {
                    await RunUpdateAsync(service, log, report);
                });
                break;
            case "/gui":
                Console.WriteLine("Graphical interface mode was requested; the desktop app is responsible for opening the UI.");
                report.ExitCode = ConsoleExitCode.Success;
                break;
            default:
                Console.Error.WriteLine($"Unknown command: {command}");
                PrintHelp();
                report.ExitCode = ConsoleExitCode.GeneralError;
                break;
        }

        PrintReport(report, command == "/repair");
        return (int)report.ExitCode;
    }

    private static string ParseCommand(
        string[] arguments,
        out bool fullScan,
        out bool elevated,
        out string? installerPath,
        out string? error)
    {
        fullScan = false;
        elevated = arguments.Contains("--elevated", StringComparer.OrdinalIgnoreCase);
        var commandArgs = arguments.Where(argument => !string.Equals(argument, "--elevated", StringComparison.OrdinalIgnoreCase)).ToArray();
        installerPath = null;
        error = null;
        if (commandArgs.Length == 0)
            return "/repair";

        var command = commandArgs[0].ToLowerInvariant() switch
        {
            "/scan" or "-scan" or "--scan" => "/scan",
            "/repair" or "-repair" or "--repair" => "/repair",
            "/cleanup" or "-cleanup" or "--cleanup" => "/cleanup",
            "/drives" or "-drives" or "--drives" => "/drives",
            "/defender" or "-defender" or "--defender" => "/defender",
            "/update" or "-update" or "--update" => "/update",
            "/install" or "-install" or "--install" => "/install",
            "/gui" or "-gui" or "--gui" => "/gui",
            "/help" or "-help" or "--help" or "/?" or "-?" or "--?" => "/help",
            _ => commandArgs[0]
        };

        if (command is not ("/scan" or "/repair" or "/cleanup" or "/drives" or "/defender" or "/update" or "/install" or "/gui" or "/help"))
        {
            error = $"Unknown command: {command}";
            return command;
        }

        var options = commandArgs.Skip(1).ToArray();
        if (command == "/defender")
        {
            if (options.Length == 1 && string.Equals(options[0], "--full", StringComparison.OrdinalIgnoreCase))
                fullScan = true;
            else if (options.Length > 0)
                error = "The /defender command accepts only the optional --full flag.";
        }
        else if (command == "/install")
        {
            if (options.Length == 1)
                installerPath = options[0];
            else if (options.Length > 1)
                error = "The /install command accepts one optional installer path.";
        }
        else if (options.Length > 0)
        {
            error = $"{command} does not accept additional options.";
        }
        return command;
    }

    private static async Task<int> RunInstallerAsync(string? configuredPath, SessionLog log)
    {
        string installerPath;
        try
        {
            installerPath = InstallerCommand.ResolveInstallerPath(
                configuredPath,
                AppContext.BaseDirectory);
        }
        catch (FileNotFoundException exception)
        {
            Console.Error.WriteLine(exception.Message);
            log.Write(exception.Message);
            return (int)ConsoleExitCode.GeneralError;
        }
        catch (Exception exception) when (
            exception is ArgumentException or IOException or UnauthorizedAccessException or NotSupportedException)
        {
            var message = $"Could not locate the Winvexa installer: {exception.Message}";
            Console.Error.WriteLine(message);
            log.Write(message);
            return (int)ConsoleExitCode.GeneralError;
        }

        Console.WriteLine($"Starting the Winvexa installer: {installerPath}");
        log.Write($"Starting the Winvexa installer with the standard Windows UAC prompt: {installerPath}");
        try
        {
            using var installer = Process.Start(InstallerCommand.CreateStartInfo(installerPath))
                ?? throw new InvalidOperationException("Windows did not start the Winvexa installer.");
            Console.WriteLine("Waiting for the installer to finish...");
            await installer.WaitForExitAsync();

            if (installer.ExitCode == 0)
            {
                const string successMessage = "Winvexa installation completed successfully.";
                Console.WriteLine(successMessage);
                log.Write(successMessage);
                return (int)ConsoleExitCode.Success;
            }

            var failureMessage =
                $"The Winvexa installer did not complete successfully (exit code {installer.ExitCode}).";
            Console.Error.WriteLine(failureMessage);
            log.Write(failureMessage);
            return (int)ConsoleExitCode.GeneralError;
        }
        catch (System.ComponentModel.Win32Exception exception) when (exception.NativeErrorCode == 1223)
        {
            const string cancelledMessage = "Windows administrator permission was declined; Winvexa was not installed.";
            Console.WriteLine(cancelledMessage);
            log.Write(cancelledMessage);
            return (int)ConsoleExitCode.AdministratorRequired;
        }
        catch (Exception exception) when (
            exception is InvalidOperationException or System.ComponentModel.Win32Exception or IOException or
                UnauthorizedAccessException or ArgumentException)
        {
            var failureMessage = $"Could not start the Winvexa installer: {exception.Message}";
            Console.Error.WriteLine(failureMessage);
            log.Write(failureMessage);
            return (int)ConsoleExitCode.GeneralError;
        }
    }

    private static async Task<int> RequestElevationAsync(string command, bool fullScan, bool alreadyElevated, SessionLog log)
    {
        if (alreadyElevated)
        {
            log.Write("The elevated process does not have administrator privileges. Stopping safely.");
            return (int)ConsoleExitCode.AdministratorRequired;
        }

        try
        {
            var executable = Environment.ProcessPath
                ?? throw new InvalidOperationException("Windows did not provide the application executable path.");
            var start = new ProcessStartInfo(executable)
            {
                UseShellExecute = true,
                Verb = "runas"
            };
            if (string.Equals(System.IO.Path.GetFileNameWithoutExtension(executable), "dotnet", StringComparison.OrdinalIgnoreCase))
            {
                var assemblyPath = Assembly.GetEntryAssembly()?.Location;
                if (string.IsNullOrWhiteSpace(assemblyPath))
                    throw new InvalidOperationException("Could not locate the application assembly for elevation.");
                start.ArgumentList.Add(assemblyPath);
            }
            start.ArgumentList.Add(command);
            if (fullScan)
                start.ArgumentList.Add("--full");
            start.ArgumentList.Add("--elevated");

            using var elevatedProcess = Process.Start(start)
                ?? throw new InvalidOperationException("Windows did not start the elevated process.");
            Console.WriteLine("Windows opened the elevated command session. This Command Prompt will remain open until it completes.");
            log.Write($"Started elevated command '{command}' using the Windows UAC prompt; waiting for completion.");
            await elevatedProcess.WaitForExitAsync();
            var exitCode = elevatedProcess.ExitCode;
            log.Write($"Elevated command completed with exit code {exitCode}.");
            Console.WriteLine($"Elevated operation finished with exit code {exitCode}.");
            return exitCode;
        }
        catch (System.ComponentModel.Win32Exception exception) when (exception.NativeErrorCode == 1223)
        {
            log.Write("The user cancelled the Windows UAC prompt. No repair operation was run.");
            Console.WriteLine("Administrator permission was declined. No changes were made.");
            return (int)ConsoleExitCode.AdministratorRequired;
        }
        catch (Exception exception)
        {
            log.Write($"Could not start the elevated operation: {exception}");
            return (int)ConsoleExitCode.GeneralError;
        }
    }

    private static async Task RunScanAsync(MaintenanceService service, SessionLog log, RepairReport report)
    {
        await ExecuteStageAsync(log, report, ConsoleExitCode.DriveCheckError, "[1/2] Checking storage drives (read-only)...", async () =>
        {
            await RunDriveCheckAsync(service, log, report);
        });
        await ExecuteStageAsync(log, report, ConsoleExitCode.CleanupError, "[2/2] Analyzing safe temporary files (no deletion)...", async () =>
        {
            var scan = await Task.Run(service.ScanCleanup);
            LogCleanupSummary(log, scan);
        });
    }

    private static async Task RunRepairAsync(MaintenanceService service, SessionLog log, RepairReport report)
    {
        if (!await VerifyWindowsRepairSourceAsync(service, log))
        {
            report.ExitCode = ConsoleExitCode.GeneralError;
            return;
        }

        log.Write("[1/8] Creating a Windows restore point...");
        await ExecuteStageAsync(log, report, ConsoleExitCode.GeneralError, "Creating a restore point...", service.CreateRestorePointAsync);

        CleanupScan? scan = null;
        log.Write("[2/8] Analyzing approved temporary files...");
        await ExecuteStageAsync(log, report, ConsoleExitCode.CleanupError, "Scanning safe temporary files...", async () =>
        {
            scan = await Task.Run(service.ScanCleanup);
            LogCleanupSummary(log, scan);
        });

        if (scan is not null)
        {
            if (scan.FileCount > 0 && Confirm(
                    $"Remove {scan.FileCount} stale file(s) in the listed user temp/cache folders? Approximate recovery: {MaintenanceService.FormatBytes(scan.Bytes)}. Personal folders are not scanned.",
                    log))
            {
                await CleanScannedFilesAsync(service, log, report, scan);
            }
            else
            {
                log.Write(scan.FileCount == 0 ? "No eligible temporary files were found." : "Temporary-file cleanup declined; no scanned files were removed.");
            }
            await EmptyRecycleBinIfApprovedAsync(service, log, report);
        }
        else
        {
            report.ExitCode = Max(report.ExitCode, ConsoleExitCode.CleanupError);
        }

        log.Write("[3/8] Checking drive and file-system health...");
        await ExecuteStageAsync(log, report, ConsoleExitCode.DriveCheckError, "Checking drive health...", async () =>
        {
            await RunDriveCheckAsync(service, log, report);
        });

        log.Write("[4/8] Checking Windows system files and component store (optional)...");
        if (Confirm("Run Microsoft's read-only DISM ScanHealth and System File Checker VerifyOnly checks? These may take several minutes and do not repair files.", log))
        {
            await ExecuteStageAsync(log, report, ConsoleExitCode.GeneralError, "Checking Windows system files and component store...", async () =>
            {
                var dism = await service.RunDismScanHealthAsync();
                var sfc = await service.RunSystemFileVerificationAsync();
                log.Write($"DISM ScanHealth exit code: {dism.ExitCode}.");
                log.Write($"System File Checker VerifyOnly exit code: {sfc.ExitCode}.");
                if (dism.ExitCode != 0 || sfc.ExitCode != 0)
                    throw new InvalidOperationException($"Read-only system checks reported DISM exit {dism.ExitCode} and SFC exit {sfc.ExitCode}.");
            });
        }
        else
        {
            log.Write("Optional read-only Windows system/component checks declined.");
        }

        log.Write("[5/8] Updating Microsoft Defender security intelligence...");
        await ExecuteStageAsync(log, report, ConsoleExitCode.DefenderError, "Updating Defender security intelligence...", service.UpdateDefenderSignaturesAsync);

        log.Write("[6/8] Running Microsoft Defender Quick Scan...");
        await ExecuteStageAsync(log, report, ConsoleExitCode.DefenderError, "Running Microsoft Defender Quick Scan...", async () =>
        {
            report.Defender = await service.RunDefenderScanAsync(fullScan: false);
            log.Write(report.Defender);
        });

        log.Write("[7/8] Running supported Windows Cleanup...");
        await RunWindowsCleanupAsync(service, log, report);

        log.Write("[8/8] Checking Windows Update...");
        await ExecuteStageAsync(log, report, ConsoleExitCode.WindowsUpdateError, "Checking Windows Update...", async () =>
        {
            await RunUpdateAsync(service, log, report);
        });
    }

    private static async Task RunCleanupAsync(MaintenanceService service, SessionLog log, RepairReport report)
    {
        var scan = await ExecuteStageAsync<CleanupScan>(log, report, ConsoleExitCode.CleanupError,
            "Analyzing approved temporary files...", async () =>
            {
                var result = await Task.Run(service.ScanCleanup);
                LogCleanupSummary(log, result);
                return result;
            });

        if (scan is not null)
        {
            if (scan.FileCount > 0 && Confirm(
                    $"Remove {scan.FileCount} stale file(s) in the listed user temp/cache folders? Approximate recovery: {MaintenanceService.FormatBytes(scan.Bytes)}. Personal folders are not scanned.",
                    log))
                await CleanScannedFilesAsync(service, log, report, scan);
            else
                log.Write(scan.FileCount == 0 ? "No eligible temporary files were found." : "Temporary-file cleanup declined; no scanned files were removed.");

            await EmptyRecycleBinIfApprovedAsync(service, log, report);
        }

        await RunWindowsCleanupAsync(service, log, report);
    }

    private static async Task RunDriveCheckAsync(MaintenanceService service, SessionLog log, RepairReport report)
    {
        var result = await service.CheckDriveHealthAsync();
        report.DrivesChecked = result.Checked;
        log.Write($"Drive summary: {result.Checked} NTFS volume(s) checked, {result.Issues} file-system or physical-disk issue(s), " +
                  $"{result.Skipped} volume(s) skipped or not supported for online NTFS scanning, " +
                  $"{result.PhysicalDisksChecked} physical disk(s) inspected, {result.Failed} check(s) failed.");
        if (result.Issues > 0 || result.Failed > 0)
            report.ExitCode = Max(report.ExitCode, ConsoleExitCode.DriveCheckError);
    }

    private static async Task RunDefenderAsync(MaintenanceService service, SessionLog log, RepairReport report, bool fullScan)
    {
        if (fullScan && !Confirm("A Full Scan may take a long time. Start it now?", log))
        {
            log.Write("Full Scan declined.");
            return;
        }
        await ExecuteStageAsync(log, report, ConsoleExitCode.DefenderError, "Updating Defender security intelligence...", service.UpdateDefenderSignaturesAsync);
        await ExecuteStageAsync(log, report, ConsoleExitCode.DefenderError,
            $"Running Microsoft Defender {(fullScan ? "Full" : "Quick")} Scan...", async () =>
            {
                report.Defender = await service.RunDefenderScanAsync(fullScan);
                log.Write(report.Defender);
            });
    }

    private static async Task RunUpdateAsync(MaintenanceService service, SessionLog log, RepairReport report)
    {
        if (!await VerifyWindowsRepairSourceAsync(service, log))
        {
            report.WindowsUpdate = "Repair was not started because the Microsoft Windows repair source could not be verified.";
            report.ExitCode = ConsoleExitCode.WindowsUpdateError;
            return;
        }

        var diagnostics = await service.DiagnoseWindowsUpdateAsync();
        LogUpdateDiagnostics(log, "Initial Windows Update diagnostics", diagnostics);
        var disabledServices = diagnostics.Services
            .Where(item => item.Name is "wuauserv" or "bits" or "cryptsvc")
            .Where(item => item.StartMode.Equals("Disabled", StringComparison.OrdinalIgnoreCase))
            .Select(item => item.Name)
            .ToArray();

        if (!diagnostics.IsOperational && diagnostics.SearchError is not null && disabledServices.Length == 0)
        {
            if (Confirm(
                    $"Windows Update scan failed ({FormatUpdateError(diagnostics)}). Start eligible Windows Update services without changing their startup configuration, then check again?",
                    log))
            {
                try
                {
                    var serviceRepair = await service.StartWindowsUpdateServicesAsync();
                    foreach (var error in serviceRepair.Errors)
                        log.Write($"Service recovery warning: {error}");
                    diagnostics = await service.DiagnoseWindowsUpdateAsync();
                    LogUpdateDiagnostics(log, "After service recovery", diagnostics);
                }
                catch (Exception exception)
                {
                    log.Write($"Windows Update service recovery failed: {exception.Message}");
                }
            }

        }
        else if (disabledServices.Length > 0)
        {
            log.Write($"Windows Update service(s) configured as Disabled: {string.Join(", ", disabledServices)}. Startup configuration was not changed.");
        }

        var cacheRepairIndicated = diagnostics.RecentFailures.Count > 0 || diagnostics.RecentEventErrors.Count > 0;
        if (!diagnostics.IsOperational && diagnostics.SearchError is not null && disabledServices.Length == 0 && cacheRepairIndicated &&
            Confirm(
                $"Windows Update is still not responding, and recent update failures/errors were found ({FormatUpdateError(diagnostics)}). Move only the Windows Update Download cache to a timestamped backup, restart services that were running, and verify again? The backup will be retained.",
                log))
        {
            try
            {
                var cacheRepair = await service.RebuildWindowsUpdateDownloadCacheAsync();
                log.Write(string.IsNullOrWhiteSpace(cacheRepair.BackupPath)
                    ? "Windows Update Download cache was absent; no cache files were changed."
                    : $"Windows Update Download cache moved to retained backup '{cacheRepair.BackupPath}'.");
                diagnostics = await service.DiagnoseWindowsUpdateAsync();
                LogUpdateDiagnostics(log, "After Download cache repair", diagnostics);
            }
            catch (Exception exception)
            {
                log.Write($"Windows Update Download cache repair failed: {exception.Message}");
            }
        }
        else if (!diagnostics.IsOperational && diagnostics.SearchError is not null && disabledServices.Length == 0)
        {
            log.Write("No recent failed installations or Windows Update error events implicated the Download cache; skipped cache rebuild.");
        }

        if (!diagnostics.IsOperational && diagnostics.SearchError is not null && disabledServices.Length == 0 &&
            Confirm(
                $"Windows Update remains unavailable ({FormatUpdateError(diagnostics)}). Run Microsoft's DISM RestoreHealth followed by System File Checker? These system-wide checks can take a long time. Continue?",
                log))
        {
            var dismSucceeded = false;
            try
            {
                var dism = await service.RunDismRestoreHealthAsync();
                log.Write($"DISM RestoreHealth exit code: {dism.ExitCode}.");
                dismSucceeded = dism.ExitCode == 0;
            }
            catch (Exception exception)
            {
                log.Write($"DISM RestoreHealth failed: {exception.Message}");
            }
            if (dismSucceeded)
            {
                try
                {
                    var sfc = await service.RunSystemFileCheckerAsync();
                    log.Write($"System File Checker exit code: {sfc.ExitCode}.");
                }
                catch (Exception exception)
                {
                    log.Write($"System File Checker failed: {exception.Message}");
                }
            }
            else
            {
                log.Write("SFC /scannow was not started because DISM repair or source verification did not succeed.");
            }
            diagnostics = await service.DiagnoseWindowsUpdateAsync();
            LogUpdateDiagnostics(log, "Final Windows Update verification", diagnostics);
        }

        if (!diagnostics.IsOperational)
        {
            report.WindowsUpdate = $"Could not be completely repaired: {FormatUpdateError(diagnostics)}";
            report.ExitCode = Max(report.ExitCode, ConsoleExitCode.WindowsUpdateError);
            log.Write($"Windows Update could not be completely repaired. {FormatUpdateError(diagnostics)}");
            return;
        }
        if (diagnostics.RestartRequired)
        {
            report.RestartRequired = true;
            report.WindowsUpdate = "Restart required before final update check";
            report.ExitCode = Max(report.ExitCode, ConsoleExitCode.RestartRequired);
            log.Write("Windows Update requires a restart before the final update check can be completed. No restart was forced.");
            return;
        }
        if (diagnostics.RecentFailures.Count > 0 || diagnostics.RecentEventErrors.Count > 0)
            log.Write($"Historical Windows Update records remain: {diagnostics.RecentFailures.Count} failed installation(s), {diagnostics.RecentEventErrors.Count} error event(s). The current scan succeeded.");

        try
        {
            await RunUpdateInstallationAsync(
                service,
                log,
                report,
                new UpdateSearch(diagnostics.PendingUpdates, diagnostics.RestartRequired, "Final diagnostic scan succeeded."));
        }
        catch (Exception exception)
        {
            report.WindowsUpdate = $"Update installation/check failed: {exception.Message}";
            report.ExitCode = Max(report.ExitCode, ConsoleExitCode.WindowsUpdateError);
            log.Write($"Windows Update installation/check failed: {exception}");
        }

        if (report.RestartRequired)
            return;

        var final = await service.DiagnoseWindowsUpdateAsync();
        LogUpdateDiagnostics(log, "Post-installation Windows Update verification", final);
        if (!final.IsOperational)
        {
            report.WindowsUpdate = $"Could not be completely verified: {FormatUpdateError(final)}";
            report.ExitCode = Max(report.ExitCode, ConsoleExitCode.WindowsUpdateError);
        }
        else if (final.RestartRequired)
        {
            report.RestartRequired = true;
            report.WindowsUpdate = "Restart required before final update verification";
            report.ExitCode = Max(report.ExitCode, ConsoleExitCode.RestartRequired);
            log.Write("Windows Update requires a restart before the final update check can be completed. No restart was forced.");
        }
        else if (final.PendingUpdates.Count == 0 &&
                 !report.WindowsUpdate.Contains("failed", StringComparison.OrdinalIgnoreCase))
        {
            report.WindowsUpdate = "No additional applicable updates";
            log.Write("Windows Update check complete. No additional applicable updates were found.");
        }
        else if (string.IsNullOrWhiteSpace(report.WindowsUpdate) || report.WindowsUpdate == "Not run")
        {
            report.WindowsUpdate = $"{final.PendingUpdates.Count} applicable update(s) remain";
        }
    }

    private static async Task<bool> VerifyWindowsRepairSourceAsync(MaintenanceService service, SessionLog log)
    {
        try
        {
            log.Write("[0/8] Checking installed Windows edition, architecture, release, build, servicing details, and source policy...");
            var installation = service.GetWindowsInstallationInfo();
            log.Write($"Repair target: Windows 11 {installation.Edition}, {installation.Architecture}, version {installation.Version}, build {installation.Build}, servicing build {installation.ServicingBuild}.");
            if (installation.RepairSourcePolicyOverridesWindowsUpdate)
            {
                throw new InvalidOperationException(
                    $"{installation.ConfiguredRepairSource} overrides the Microsoft Windows Update repair source. Winvexa will not change servicing policy or use an unverified source.");
            }

            log.Write("Checking the explicitly selected official Microsoft Windows Update service...");
            var source = await service.CheckMicrosoftWindowsUpdateSourceAsync();
            log.Write(source.Details);
            log.Write("Verifying Microsoft signatures and the current Windows component store...");
            var verification = await service.VerifyWindowsRepairSourceAsync(installation);
            log.Write(verification.Details);
            log.Write("Windows repair source verification completed. No complete Windows image or feature upgrade was downloaded.");
            return true;
        }
        catch (Exception exception)
        {
            log.Write($"Windows repair was blocked because its repair source could not be verified: {exception}");
            Console.Error.WriteLine(
                $"Windows repair was not started because a compatible Microsoft repair source could not be verified.{Environment.NewLine}{exception.Message}{Environment.NewLine}Connect to Windows Update and retry. If this PC is managed, ask the administrator to configure Microsoft Windows Update as the repair-content source.");
            return false;
        }
    }

    private static async Task RunUpdateInstallationAsync(
        MaintenanceService service,
        SessionLog log,
        RepairReport report,
        UpdateSearch? initialSearch = null)
    {
        var search = initialSearch ?? await service.SearchWindowsUpdatesAsync();
        if (search.Count == 0)
        {
            report.WindowsUpdate = "No additional applicable updates";
            log.Write("Windows Update check complete. No additional applicable updates were found.");
            return;
        }

        for (var round = 1; ; round++)
        {
            if (round > 10)
            {
                report.WindowsUpdate = "Stopped after 10 update rounds";
                report.ExitCode = Max(report.ExitCode, ConsoleExitCode.WindowsUpdateError);
                log.Write("Windows Update safety limit reached after 10 rounds; run the command again to continue.");
                return;
            }
            var visibleTitles = string.Join(Environment.NewLine, search.Titles.Take(12).Select(title => $"  - {title}"));
            if (search.Titles.Count > 12)
                visibleTitles += $"{Environment.NewLine}  - and {search.Titles.Count - 12} more";
            Console.WriteLine($"Found {search.Count} applicable update(s):{Environment.NewLine}{visibleTitles}");
            if (!Confirm($"Download and install this approved update set (round {round})? No restart will be forced.", log))
            {
                report.WindowsUpdate = $"{search.Count} update(s) found but not installed";
                log.Write("Windows Update installation declined; no updates were installed.");
                return;
            }

            var installation = await service.InstallWindowsUpdatesAsync(search.Updates);
            if (installation.RebootRequired)
            {
                report.RestartRequired = true;
                report.WindowsUpdate = $"Restart required after installing {installation.Installed} update(s)";
                report.ExitCode = Max(report.ExitCode, ConsoleExitCode.RestartRequired);
                log.Write("Windows Update requires a restart before the final update check can be completed. No restart was forced.");
                return;
            }
            search = await service.SearchWindowsUpdatesAsync();
            if (installation.Failed > 0)
            {
                report.WindowsUpdate = $"{installation.Failed} update(s) failed; {search.Count} remain";
                report.ExitCode = Max(report.ExitCode, ConsoleExitCode.WindowsUpdateError);
                log.Write($"Windows Update reported {installation.Failed} failed or partial update(s).");
                return;
            }
            if (search.Count == 0)
            {
                report.WindowsUpdate = "No additional applicable updates";
                log.Write("Windows Update check complete. No additional applicable updates were found.");
                return;
            }
            if (installation.Installed == 0)
            {
                report.WindowsUpdate = $"{search.Count} update(s) remain";
                report.ExitCode = Max(report.ExitCode, ConsoleExitCode.WindowsUpdateError);
                log.Write($"No updates installed successfully; {search.Count} applicable update(s) remain.");
                return;
            }
            log.Write($"{search.Count} additional applicable update(s) found; confirmation is required for this new update set.");
        }
    }

    private static void LogUpdateDiagnostics(SessionLog log, string heading, WindowsUpdateDiagnostics diagnostics)
    {
        log.Write($"{heading}: scan {(diagnostics.SearchSucceeded ? "succeeded" : "failed")}, {diagnostics.PendingUpdates.Count} pending update(s), restart required={diagnostics.RestartRequired}.");
        foreach (var service in diagnostics.Services)
            log.Write($"Windows Update service {service.Name}: {service.State}, startup type {service.StartMode}.");
        foreach (var failure in diagnostics.RecentFailures)
            log.Write($"Historical update failure [{failure.HResult}] {failure.Date}: {failure.Title} (result {failure.ResultCode}).");
        foreach (var error in diagnostics.RecentEventErrors)
            log.Write($"Windows Update event error {error.EventId} [{error.HResult}] {error.Date}: {error.Message}");
        foreach (var warning in diagnostics.DiagnosticWarnings)
            log.Write($"Windows Update diagnostic warning: {warning}");
        if (diagnostics.SearchError is not null)
            log.Write($"Windows Update scan error [{diagnostics.SearchHResult}]: {diagnostics.SearchError}");
    }

    private static string FormatUpdateError(WindowsUpdateDiagnostics diagnostics)
    {
        var code = string.IsNullOrWhiteSpace(diagnostics.SearchHResult) ? "HRESULT unavailable" : diagnostics.SearchHResult;
        return $"error {code}: {diagnostics.SearchError ?? "one or more required Windows Update services could not be verified"}";
    }

    private static async Task RunWindowsCleanupAsync(MaintenanceService service, SessionLog log, RepairReport report)
    {
        if (!Confirm("Open Microsoft's Windows Disk Cleanup UI for every accessible local drive? You choose cleanup categories in each Windows dialog.", log))
        {
            log.Write("Windows Disk Cleanup declined.");
            return;
        }

        var drives = service.GetLocalDrives();
        foreach (var drive in drives)
        {
            await ExecuteStageAsync(log, report, ConsoleExitCode.CleanupError,
                $"Opening Windows Disk Cleanup for {drive.Name}...", async () =>
                {
                    var recovered = await service.LaunchWindowsCleanupAsync(drive.Name);
                    if (recovered.HasValue)
                    {
                        report.CleanedBytes += recovered.Value;
                        log.Write($"{drive.Name} Windows Cleanup free-space increase: approximately {MaintenanceService.FormatBytes(recovered.Value)} (estimate).");
                    }
                });
        }
    }

    private static async Task CleanScannedFilesAsync(MaintenanceService service, SessionLog log, RepairReport report, CleanupScan scan)
    {
        await ExecuteStageAsync(log, report, ConsoleExitCode.CleanupError, "Cleaning approved temporary files...", async () =>
        {
            report.CleanedBytes += await Task.Run(() => service.CleanFiles(scan));
            log.Write($"Storage cleaned: approximately {MaintenanceService.FormatBytes(report.CleanedBytes)}.");
        });
    }

    private static async Task EmptyRecycleBinIfApprovedAsync(MaintenanceService service, SessionLog log, RepairReport report)
    {
        try
        {
            var (bytes, items) = service.GetRecycleBinSize();
            if (items == 0)
            {
                log.Write("Recycle Bin is empty.");
                return;
            }
            if (!Confirm($"Windows reports {items} Recycle Bin item(s) ({MaintenanceService.FormatBytes(bytes)}). Permanently empty the Recycle Bin?", log))
            {
                log.Write("Recycle Bin cleanup declined.");
                return;
            }
            service.EmptyRecycleBin();
            report.CleanedBytes += bytes;
            log.Write($"Recycle Bin emptied after confirmation; approximately {MaintenanceService.FormatBytes(bytes)} recovered.");
        }
        catch (Exception exception)
        {
            log.Write($"Recycle Bin cleanup failed: {exception.Message}");
            report.ExitCode = Max(report.ExitCode, ConsoleExitCode.CleanupError);
        }
        await Task.CompletedTask;
    }

    private static void LogCleanupSummary(SessionLog log, CleanupScan scan)
    {
        log.Write($"Accessible local drives found: {scan.DriveCount}.");
        foreach (var category in scan.Categories)
            log.Write($"{category.Name}: {category.Files.Count} eligible file(s), {MaintenanceService.FormatBytes(category.Bytes)}.");
        log.Write($"{scan.FileCount} safe temporary file(s); approximately {MaintenanceService.FormatBytes(scan.Bytes)} potentially recoverable. Personal folders were not scanned.");
    }

    private static async Task ExecuteStageAsync(
        SessionLog log,
        RepairReport report,
        ConsoleExitCode errorCode,
        string description,
        Func<Task> action)
    {
        log.Write(description);
        try
        {
            await action();
        }
        catch (Exception exception)
        {
            log.Write($"{description} failed: {exception.Message}");
            report.ExitCode = Max(report.ExitCode, errorCode);
        }
    }

    private static async Task<T?> ExecuteStageAsync<T>(
        SessionLog log,
        RepairReport report,
        ConsoleExitCode errorCode,
        string description,
        Func<Task<T>> action) where T : class
    {
        log.Write(description);
        try
        {
            return await action();
        }
        catch (Exception exception)
        {
            log.Write($"{description} failed: {exception.Message}");
            report.ExitCode = Max(report.ExitCode, errorCode);
            return null;
        }
    }

    private static bool Confirm(string prompt, SessionLog log)
    {
        Console.Write($"{prompt}{Environment.NewLine}Type Y to continue (default: No): ");
        var answer = Console.ReadLine();
        var confirmed = string.Equals(answer?.Trim(), "Y", StringComparison.OrdinalIgnoreCase)
            || string.Equals(answer?.Trim(), "YES", StringComparison.OrdinalIgnoreCase);
        log.Write(confirmed ? $"User confirmed: {prompt}" : $"User declined: {prompt}");
        return confirmed;
    }

    private static void PrintReport(RepairReport report, bool fullRepair)
    {
        Console.WriteLine();
        Console.WriteLine("========================================");
        var heading = report.ExitCode == ConsoleExitCode.RestartRequired
            ? fullRepair ? "         REPAIR REQUIRES RESTART" : "       OPERATION REQUIRES RESTART"
            : report.ExitCode != ConsoleExitCode.Success
                ? fullRepair ? "       REPAIR COMPLETED WITH ISSUES" : "     OPERATION COMPLETED WITH ISSUES"
                : fullRepair ? "             REPAIR COMPLETE" : "            OPERATION COMPLETE";
        Console.WriteLine(heading);
        Console.WriteLine("========================================");
        Console.WriteLine($"Storage cleaned: {MaintenanceService.FormatBytes(report.CleanedBytes)}");
        Console.WriteLine($"Drives checked: {report.DrivesChecked}");
        Console.WriteLine($"Microsoft Defender: {report.Defender}");
        Console.WriteLine($"Windows Update: {report.WindowsUpdate}");
        Console.WriteLine($"Restart required: {(report.RestartRequired ? "Yes" : "No")}");
        Console.WriteLine($"Exit code: {(int)report.ExitCode} ({report.ExitCode})");
    }

    private static void PrintBanner()
    {
        Console.WriteLine("========================================");
        Console.WriteLine("       WINDOWS 11 REPAIR UTILITY");
        Console.WriteLine("========================================");
    }

    private static void PrintHelp()
    {
        Console.WriteLine("""
            Winvexa - Windows 11 Maintenance & Repair

            Usage:
              Winvexa.exe                 Open the Windows desktop interface
              Winvexa.exe /scan           Read-only drive and cleanup diagnostics
              Winvexa.exe /repair         Complete repair workflow
              Winvexa.exe /cleanup        Confirmed temp cleanup and Windows cleanup
              Winvexa.exe /drives         Read-only drive health checks
              Winvexa.exe /defender       Update Defender signatures and Quick Scan
              Winvexa.exe /defender --full  Run a confirmed Full Scan
              Winvexa.exe /update         Check for updates and ask before installing
              Winvexa.exe /install [path] Install from WinvexaSetup.exe or the specified installer
              Winvexa.exe /help           Show this help
              Winvexa.exe /gui            Open the graphical interface

              Installer path:
                WINVEXA_INSTALLER_PATH   Optional path to WinvexaSetup.exe

            Exit codes:
               0  Successful
               1  General error / unsupported Windows
               2  Administrator privileges required or UAC declined
               3  Windows Update error
               4  Defender error
               5  Drive check error
               6  Cleanup error
              10  Restart required

            Logs:
              %LOCALAPPDATA%\Winvexa\Logs
            """);
    }

    private static ConsoleExitCode Max(ConsoleExitCode current, ConsoleExitCode next)
    {
        if (current == ConsoleExitCode.RestartRequired || next == ConsoleExitCode.RestartRequired)
            return ConsoleExitCode.RestartRequired;
        return (int)next > (int)current ? next : current;
    }

    private static bool IsAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    private static string GetWindowsVersion()
    {
        var version = Environment.OSVersion.Version;
        return $"Windows (build {version.Build})";
    }
}
