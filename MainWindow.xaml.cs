using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Security.Principal;
using System.Text.Json;
using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;

namespace Winvexa;

public partial class MainWindow : Window
{
    private sealed record WindowsUpdateLoopVerificationState(
        DateTimeOffset RepairStartedUtc,
        string[] RepeatedFailureTitles,
        string[] PendingUpdateTitles);

    private static readonly JsonSerializerOptions VerificationJsonOptions = new() { WriteIndented = true };
    private readonly MaintenanceService _service;
    private readonly string _logPath;
    private readonly List<string> _report = [];
    private readonly List<string> _workflowFailures = [];
    private readonly Stopwatch _operationStopwatch = new();
    private readonly DispatcherTimer _operationHeartbeat;
    private SecurityWindow? _securityWindow;
    private CancellationTokenSource? _operationCancellation;
    private bool _busy;
    private bool _operationFailed;
    private bool _stopRequested;
    private bool _windowsRepairSourceChecked;
    private bool _windowsRepairSourceVerified;
    private string _windowsRepairSourceFailure = string.Empty;
    private string _operationStatus = string.Empty;
    private bool _supportedWindows;
    private bool _logFailureNotified;

    public MainWindow()
    {
        InitializeComponent();
        GlassThemeService.ApplyToWindow(this);
        _operationHeartbeat = new DispatcherTimer { Interval = TimeSpan.FromSeconds(15) };
        _operationHeartbeat.Tick += (_, _) =>
        {
            if (_busy && !string.IsNullOrWhiteSpace(_operationStatus))
            {
                var stopMessage = _stopRequested
                    ? " Stop requested; canceling cancellable work. DISM/SFC repair, Defender scans, Windows Update searches/installation, restore-point creation, Recycle Bin emptying, or drive optimization may need to finish before Winvexa returns to idle."
                    : string.Empty;
                StatusText.Text =
                    $"{_operationStatus}{stopMessage} Still working — {_operationStopwatch.Elapsed.ToString(@"mm\:ss")} elapsed.";
            }
        };
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var logDirectory = string.IsNullOrWhiteSpace(appData)
            ? Path.Combine(Path.GetTempPath(), "Winvexa", "Logs")
            : Path.Combine(appData, "Winvexa", "Logs");
        string? logWarning = null;
        try
        {
            Directory.CreateDirectory(logDirectory);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            var requestedDirectory = logDirectory;
            logDirectory = Path.Combine(Path.GetTempPath(), "Winvexa", "Logs");
            try
            {
                Directory.CreateDirectory(logDirectory);
                logWarning = $"Could not create the preferred log folder '{requestedDirectory}': {exception.Message}. Using '{logDirectory}' instead.";
            }
            catch (Exception fallbackException) when (fallbackException is IOException or UnauthorizedAccessException)
            {
                MessageBox.Show(
                    $"Could not create either session log folder. Preferred location: {exception.Message}{Environment.NewLine}Fallback location: {fallbackException.Message}",
                    "Session logging unavailable",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
                throw new InvalidOperationException("A session log could not be created. Repair operations will not start.", fallbackException);
            }
        }
        _logPath = Path.Combine(logDirectory, $"repair-{DateTime.Now:yyyyMMdd-HHmmssfff}.log");
        _service = new MaintenanceService(WriteLog);

        if (logWarning is not null)
            WriteLog(logWarning);
        WriteLog("Session started.");
        WriteLog($"Windows: {GetWindowsVersion()}");
        WriteLog($"Administrator: {IsAdministrator()}");
        WriteLog($"Log file: {_logPath}");

        _supportedWindows = OperatingSystem.IsWindowsVersionAtLeast(10, 0, 22000);
        var version = Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "Unknown";
        SystemSubtitle.Text = _supportedWindows
            ? $"{GetWindowsVersion()}  •  Version {version}"
            : "This utility is designed for Windows 11. Maintenance actions are disabled on this version of Windows.";
        if (!_supportedWindows)
        {
            StatusText.Text = "Windows 11 (build 22000 or later) is required for maintenance actions.";
            WriteLog("Unsupported Windows version; maintenance actions disabled.");
            SetControlsEnabled(false);
        }
        else if (IsAdministrator())
        {
            StatusText.Text = "Administrator privileges confirmed. Winvexa is ready.";
            WriteLog("Administrator privileges confirmed. Starting Winvexa.");
        }

        Loaded += async (_, _) =>
        {
            var arguments = Environment.GetCommandLineArgs();
            var elevatedSecurityAction = arguments.FirstOrDefault(argument =>
                argument.StartsWith("--security-action-", StringComparison.OrdinalIgnoreCase));
            if (elevatedSecurityAction is not null)
            {
                await OpenSecurityWindowForElevatedActionAsync(elevatedSecurityAction);
            }
            else if (arguments.Contains("--fix-my-pc", StringComparer.OrdinalIgnoreCase))
            {
                if (!IsAdministrator())
                {
                    WriteLog("On-Demand PC Repair startup was requested but the process is not elevated.");
                    SetStatus("Fix My PC did not start because administrator access was not granted.");
                    return;
                }
                await RunActionAsync("Fix My PC", () => RunOnDemandRepairWorkflowAsync());
            }
            else if (arguments.Contains("--system-health-check", StringComparer.OrdinalIgnoreCase))
            {
                if (!IsAdministrator())
                {
                    WriteLog("System Health Check startup was requested but the process is not elevated.");
                    SetStatus("System Health Check did not start because administrator access was not granted.");
                    return;
                }
                await RunActionAsync("System Health Check",
                    () => RunOnDemandRepairWorkflowAsync(diagnosisOnly: true));
            }
            else if (arguments.Contains("--repair", StringComparer.OrdinalIgnoreCase))
            {
                if (!IsAdministrator())
                {
                    WriteLog("Elevated repair startup was requested but the process is not elevated.");
                    SetStatus("Repair did not start because administrator access was not granted.");
                    return;
                }
                await RunActionAsync("Repair My PC", RunRepairWorkflowAsync);
            }
            else if (arguments.Contains("--drive-health", StringComparer.OrdinalIgnoreCase) && IsAdministrator())
            {
                await RunActionAsync("Drive Health", RunDriveHealthAsync);
            }
            else if (arguments.Contains("--windows-update-repair", StringComparer.OrdinalIgnoreCase) && IsAdministrator())
            {
                await RunActionAsync("Windows Update Scan & Repair", RunWindowsUpdateScanRepairWorkflowAsync);
            }
            else if (arguments.Contains("--windows-update-loop-repair", StringComparer.OrdinalIgnoreCase) && IsAdministrator())
            {
                await RunActionAsync("Fix Windows Update Loop", RunWindowsUpdateLoopRepairWorkflowAsync);
            }
            else if (arguments.Contains("--verify-windows-update", StringComparer.OrdinalIgnoreCase) && IsAdministrator())
            {
                await RunActionAsync("Verify Windows Update", VerifyWindowsUpdateLoopAsync);
            }
        };
    }

    private async void ScanOnly_Click(object sender, RoutedEventArgs e)
    {
        await RunActionAsync("Scan Only", async () =>
        {
            var scan = await ScanAndReportAsync();
            var driveHealth = await CheckDriveHealthInBackgroundAsync();
            AddReport($"Drive health: {driveHealth.Checked} NTFS volume(s) checked, {driveHealth.Issues} issue(s), " +
                      $"{driveHealth.Failed} check(s) failed, {driveHealth.Skipped} skipped, " +
                      $"{driveHealth.PhysicalDisksChecked} physical disk(s) inspected.");
            ShowScanSummary(scan);
            SetStatus(driveHealth.Issues == 0 && driveHealth.Failed == 0
                ? $"Scan complete. {scan.FileCount} safe temporary file(s), approximately {MaintenanceService.FormatBytes(scan.Bytes)} eligible for cleanup."
                : driveHealth.Issues > 0
                    ? $"Scan complete with {driveHealth.Issues} reported drive health issue(s). Review the report and activity log."
                    : $"Scan incomplete: {driveHealth.Failed} drive health check(s) could not complete. Review the report and activity log.");
            SetProgress(100, driveHealth.Failed > 0 ? "Scan finished; some drive checks were incomplete" : "Scan complete");
        });
    }

    private async void ScanWindows_Click(object sender, RoutedEventArgs e)
    {
        if (MessageBox.Show(
                this,
                "Run a Microsoft Defender Quick Scan? Winvexa will use Defender's supported scan and will not replace or change its protections.",
                "Microsoft Defender Quick Scan",
                MessageBoxButton.YesNo,
                MessageBoxImage.Question) != MessageBoxResult.Yes)
            return;

        await RunDefenderScanAsync(fullScan: false);
    }

    private async void SystemHealth_Click(object sender, RoutedEventArgs e)
    {
        if (!EnsureSupported() || _busy)
            return;
        if (!IsAdministrator())
        {
            RequestElevation(
                "--system-health-check",
                "A complete System Health Check uses Microsoft's read-only DISM and System File Checker diagnostics, checks Windows Update and drive status, and verifies Microsoft Defender status. Administrator access is needed for reliable results. The check does not repair or remove anything.");
            return;
        }

        await RunActionAsync("System Health Check",
            () => RunOnDemandRepairWorkflowAsync(diagnosisOnly: true));
    }

    private void ViewResults_Click(object sender, RoutedEventArgs e)
    {
        DetailsTabs.SelectedItem = FinalReportTab;
    }

    private async void FixMyPc_Click(object sender, RoutedEventArgs e)
    {
        if (!EnsureSupported() || _busy)
            return;
        if (!IsAdministrator())
        {
            RequestElevation(
                "--fix-my-pc",
                "Fix My PC checks Windows system files, component-store health, Windows Update, and drive health. Administrator access is needed for complete diagnostics and any approved system repair. Windows will show its standard UAC prompt.");
            return;
        }
        await RunActionAsync("Fix My PC", () => RunOnDemandRepairWorkflowAsync());
    }

    private async Task RunOnDemandRepairWorkflowAsync(bool diagnosisOnly = false)
    {
        _report.Clear();
        _workflowFailures.Clear();
        ReportText.Clear();
        var problems = new List<string>();
        var repairActions = new List<string>();
        var repairSuccesses = new List<string>();
        var repairFailures = new List<string>();
        var userActions = new List<string>();
        var unresolved = new List<string>();
        CleanupScan? cleanupScan = null;
        DriveHealthSummary? driveHealth = null;
        WindowsUpdateDiagnostics? updateDiagnostics = null;
        var systemChecks = new List<(string Name, WindowsSystemRepairResult Result, bool RepairIndicated, bool CheckFailed)>();
        var systemRepairAttempted = false;
        var cleanupAttempted = false;
        var updateRepairAttempted = false;

        AddReport(diagnosisOnly ? "WINDOWS SYSTEM HEALTH CHECK" : "ON-DEMAND PC REPAIR");
        AddReport($"Started: {DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss zzz}");
        AddReport("No changes are made during diagnosis. Personal folders are never scanned or cleaned.");

        SetStatus("Preparing diagnostic scan...");
        SetProgress(1, "Preparing diagnostic checks");
        WriteLog("=== On-Demand PC Repair diagnosis started ===");
        try
        {
            if (!diagnosisOnly && !await EnsureVerifiedWindowsRepairSourceAsync())
                return;

            SetStatus("Checking safe temporary/cache files...");
            SetProgress(3, "Checking safe temporary/cache files");
            cleanupScan = await Task.Run(_service.ScanCleanup);
            AddReport($"Safe temporary/cache files: {cleanupScan.FileCount} eligible file(s), approximately {MaintenanceService.FormatBytes(cleanupScan.Bytes)}.");
            foreach (var category in cleanupScan.Categories)
                AddReport($"  {category.Name}: {category.Files.Count} file(s), {MaintenanceService.FormatBytes(category.Bytes)}.");
            if (cleanupScan.FileCount > 0)
                problems.Add($"{cleanupScan.FileCount} safe temporary/cache file(s) can potentially be removed ({MaintenanceService.FormatBytes(cleanupScan.Bytes)}).");
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception exception) when (!_stopRequested || exception is not OperationCanceledException)
        {
            WriteLog($"On-Demand PC Repair temporary-file diagnosis failed: {exception}");
            repairFailures.Add($"Temporary/cache file diagnosis failed: {exception.Message}");
        }

        SetProgress(18, "Checking drive and file-system health");
        SetStatus("Checking drive and file-system health...");
        try
        {
            driveHealth = await CheckDriveHealthInBackgroundAsync();
            AddReport($"Drive health: {driveHealth.Checked} NTFS volume(s) checked, {driveHealth.Issues} issue(s), {driveHealth.Failed} failed check(s), {driveHealth.Skipped} skipped, {driveHealth.PhysicalDisksChecked} physical disk(s) inspected.");
            if (driveHealth.Issues > 0)
                problems.Add($"Drive health reported {driveHealth.Issues} file-system or physical-disk issue(s).");
            if (driveHealth.Failed > 0)
                repairFailures.Add($"{driveHealth.Failed} drive health check(s) could not complete.");
            if (driveHealth.Skipped > 0)
                userActions.Add($"{driveHealth.Skipped} volume(s) were skipped because their file system is not supported by the online read-only check.");
        }
        catch (Exception exception) when (!_stopRequested || exception is not OperationCanceledException)
        {
            WriteLog($"On-Demand PC Repair drive-health diagnosis failed: {exception}");
            repairFailures.Add($"Drive-health diagnosis failed: {exception.Message}");
        }

        SetProgress(34, "Checking Windows component store and system files");
        SetStatus("Checking Windows component store and system files...");
        foreach (var check in new[]
                 {
                     ("DISM ScanHealth", (Func<Task<WindowsSystemRepairResult>>)_service.RunDismScanHealthAsync),
                     ("System File Checker VerifyOnly", (Func<Task<WindowsSystemRepairResult>>)_service.RunSystemFileVerificationAsync)
                 })
        {
            try
            {
                var result = await check.Item2();
                var repairIndicated = SystemCheckOutputIndicatesRepair(result.Output) ||
                                      SystemCheckOutputIndicatesRepair(result.Error);
                var checkFailed = result.ExitCode != 0;
                systemChecks.Add((check.Item1, result, repairIndicated, checkFailed));
                AddReport($"{check.Item1}: exit code {result.ExitCode}.");
                if (!string.IsNullOrWhiteSpace(result.Output))
                    AddReport($"{check.Item1} result: {result.Output.Trim()}");
                if (!string.IsNullOrWhiteSpace(result.Error))
                    AddReport($"{check.Item1} diagnostic: {result.Error.Trim()}");
                if (repairIndicated)
                    problems.Add($"{check.Item1} reported possible Windows component/system-file corruption.");
                else if (checkFailed)
                    repairFailures.Add($"{check.Item1} did not complete successfully (exit code {result.ExitCode}); corruption could not be confirmed.");
            }
            catch (Exception exception) when (!_stopRequested || exception is not OperationCanceledException)
            {
                WriteLog($"On-Demand PC Repair {check.Item1} diagnosis failed: {exception}");
                systemChecks.Add((check.Item1, new WindowsSystemRepairResult(-1, string.Empty, exception.Message), false, true));
                repairFailures.Add($"{check.Item1} could not complete: {exception.Message}");
            }
        }

        SetProgress(52, "Checking Windows Update services, errors, and restart state");
        SetStatus("Checking Windows Update...");
        try
        {
            updateDiagnostics = await _service.DiagnoseWindowsUpdateAsync();
            AddUpdateDiagnosticsToReport("Windows Update diagnosis", updateDiagnostics);
            var repeatedFailures = GetRepeatedUpdateFailures(updateDiagnostics);
            if (!updateDiagnostics.IsOperational || repeatedFailures.Length > 0)
            {
                problems.Add(!updateDiagnostics.IsOperational
                    ? "Windows Update scan or required service checks reported a problem."
                    : $"Windows Update history indicates repeated/reoffered failure(s) for {repeatedFailures.Length} update(s).");
            }
            if (updateDiagnostics.RestartRequired)
            {
                userActions.Add("Windows reports a pending restart. Winvexa will not restart the computer automatically.");
                problems.Add("Windows reports a pending restart before all update state can be verified.");
            }
            if (updateDiagnostics.PendingUpdates.Count > 0)
            {
                AddReport($"Windows Update has {updateDiagnostics.PendingUpdates.Count} applicable update(s); installation requires separate confirmation.");
                problems.Add($"Windows Update has {updateDiagnostics.PendingUpdates.Count} applicable update(s) available for confirmation.");
            }
        }
        catch (Exception exception) when (!_stopRequested || exception is not OperationCanceledException)
        {
            WriteLog($"On-Demand PC Repair Windows Update diagnosis failed: {exception}");
            repairFailures.Add($"Windows Update diagnosis failed: {exception.Message}");
        }

        SetProgress(66, "Checking Microsoft Defender status");
        SetStatus("Checking Microsoft Defender status...");
        try
        {
            var defenderStatus = await _service.GetDefenderSecurityStatusAsync();
            AddReport(
                $"Microsoft Defender status: {defenderStatus.OverallStatus}; service={defenderStatus.ServiceEnabled}; " +
                $"antivirus={defenderStatus.AntivirusEnabled}; real-time protection={defenderStatus.RealTimeProtectionEnabled}; " +
                $"security intelligence version={defenderStatus.SignatureVersion}; age={defenderStatus.SignatureAgeDays?.ToString() ?? "unavailable"} day(s); " +
                $"active threats={defenderStatus.ActiveThreats.Count}; recent detections={defenderStatus.RecentDetections.Count}.");
            if (defenderStatus.OverallStatus != "Protected")
            {
                var issue = $"Microsoft Defender reports '{defenderStatus.OverallStatus}'.";
                problems.Add(issue);
                unresolved.Add(issue + " Winvexa did not modify antivirus settings. Review Windows Security.");
                userActions.Add("Review Microsoft Defender protection and Protection history in Windows Security.");
            }
            else
            {
                AddReport("Microsoft Defender Antivirus is available and active. Winvexa did not change Defender protections.");
            }
        }
        catch (Exception exception) when (!_stopRequested || exception is not OperationCanceledException)
        {
            WriteLog($"On-Demand PC Repair Defender status check failed: {exception}");
            problems.Add("Microsoft Defender status could not be verified as active.");
            unresolved.Add("Microsoft Defender status could not be verified as active. Winvexa did not disable or alter Defender protections.");
            userActions.Add($"Review Microsoft Defender in Windows Security: {exception.Message}");
        }

        SetStatus("Analyzing results...");
        SetProgress(68, "Analyzing diagnostic results");
        var diagnosisIncomplete = repairFailures.Count > 0;
        if (diagnosisOnly)
        {
            AddReport("DIAGNOSTIC FINDINGS:");
            if (problems.Count == 0)
                AddReport(diagnosisIncomplete
                    ? "  No issue was confirmed by completed checks; one or more diagnostics could not complete."
                    : "  No issue was identified by the supported checks.");
            else
                foreach (var problem in problems)
                    AddReport($"  - {problem}");

            if (repairFailures.Count > 0)
            {
                AddReport("CHECKS THAT COULD NOT COMPLETE:");
                foreach (var failure in repairFailures)
                    AddReport($"  - {failure}");
            }

            AddReport("REPAIRS PERFORMED: None. This was a diagnostic-only check.");
            AddReport("FINAL SYSTEM STATUS:");
            var healthCheckIncomplete = diagnosisIncomplete || problems.Count > 0;
            AddReport(healthCheckIncomplete
                ? "System Health Check completed with findings or incomplete checks. Review this report and the activity log."
                : "System Health Check complete. No issue was identified by the supported checks.");
            SetStatus(healthCheckIncomplete
                ? "System Health Check complete — review findings and any incomplete checks."
                : "System Health Check complete — no issue was identified.");
            SetProgress(100, healthCheckIncomplete ? "Health check complete with findings" : "Health check complete");
            WriteLog($"=== System Health Check finished: {(healthCheckIncomplete ? "findings or incomplete checks" : "no issue identified")} ===");
            return;
        }

        if (problems.Count == 0 && !diagnosisIncomplete)
        {
            AddReport("PROBLEMS DETECTED: None.");
            AddReport("REPAIR ACTIONS RUN / ATTEMPTED: None.");
            AddReport("REPAIRS THAT SUCCEEDED: None required.");
            AddReport("REPAIRS THAT FAILED: None.");
            AddReport("ITEMS REQUIRING USER ACTION: None.");
            AddReport("FINAL SYSTEM STATUS: No repair was identified as necessary from the supported checks.");
            SetProgress(100, "Repair Complete");
            SetStatus("Repair Complete — no repair was identified as necessary.");
            WriteLog("=== On-Demand PC Repair diagnosis complete: no problems detected ===");
            return;
        }

        AddReport("PROBLEMS DETECTED:");
        if (problems.Count == 0)
            AddReport("  No confirmed repair problem; one or more diagnostics could not complete.");
        else
            foreach (var problem in problems)
                AddReport($"  - {problem}");
        if (repairFailures.Count > 0)
        {
            AddReport("DIAGNOSTIC LIMITATIONS:");
            foreach (var failure in repairFailures)
                AddReport($"  - {failure}");
        }

        SetStatus("Problem Found — reviewing appropriate repair options...");
        SetProgress(70, "Problem Found");
        if (problems.Count > 0 &&
            MessageBox.Show(
                this,
                $"Winvexa found {problems.Count} potential issue(s):{Environment.NewLine}{Environment.NewLine}{string.Join(Environment.NewLine, problems.Select(problem => $"• {problem}"))}{Environment.NewLine}{Environment.NewLine}Winvexa will offer only repairs related to these findings. Each cleanup or significant repair still requires your confirmation.",
                "Problem Found",
                MessageBoxButton.OKCancel,
                MessageBoxImage.Information) != MessageBoxResult.OK)
        {
            userActions.Add("Repair actions were not started because the user cancelled after reviewing the diagnosis.");
        }
        else
        {
            SetStatus("Preparing repair...");
            var eligibleCleanup = cleanupScan is { FileCount: > 0 };
            if (eligibleCleanup)
            {
                if (ConfirmTemporaryCleanup(cleanupScan!))
                {
                    cleanupAttempted = true;
                    repairActions.Add("Remove only the confirmed stale files from Winvexa's whitelisted temporary/cache locations.");
                    SetStatus("Repairing approved temporary/cache files...");
                    SetProgress(74, "Repairing safe temporary/cache files");
                    try
                    {
                        var removed = await Task.Run(() => _service.CleanFiles(cleanupScan!));
                        AddReport($"Cleanup removed approximately {MaintenanceService.FormatBytes(removed)}.");
                    }
                    catch (Exception exception) when (!_stopRequested || exception is not OperationCanceledException)
                    {
                        WriteLog($"On-Demand PC Repair temporary cleanup failed: {exception}");
                        repairFailures.Add($"Temporary cleanup failed: {exception.Message}");
                    }
                }
                else
                {
                    userActions.Add("Temporary/cache cleanup was declined; no files were removed.");
                    unresolved.Add("Eligible temporary/cache files remain because cleanup was declined.");
                }

                if (MessageBox.Show(
                        this,
                        "Would you also like to open Microsoft's Windows Disk Cleanup for accessible drives? Winvexa will not choose categories; you review and control every item in the Windows dialogs.",
                        "Windows Cleanup",
                        MessageBoxButton.YesNo,
                        MessageBoxImage.Question) == MessageBoxResult.Yes)
                {
                    repairActions.Add("Opened Microsoft's Windows Disk Cleanup; category choices and deletion remain controlled in the Windows dialogs.");
                    var previousFailureCount = _workflowFailures.Count;
                    SetStatus("Opening Windows-supported cleanup options...");
                    try
                    {
                        await RunWindowsCleanupOnAllDrivesAsync();
                    }
                    catch (Exception exception) when (!_stopRequested || exception is not OperationCanceledException)
                    {
                        repairFailures.Add($"Windows Disk Cleanup could not complete: {exception.Message}");
                    }
                    foreach (var failure in _workflowFailures.Skip(previousFailureCount))
                        repairFailures.Add(failure);
                }
                else
                {
                    userActions.Add("Windows Disk Cleanup was not opened.");
                }
            }

            var dismRepairIndicated = systemChecks.Any(check => check.Name == "DISM ScanHealth" && check.RepairIndicated);
            var sfcRepairIndicated = systemChecks.Any(check => check.Name == "System File Checker VerifyOnly" && check.RepairIndicated);
            if (dismRepairIndicated || sfcRepairIndicated)
            {
                var actions = dismRepairIndicated
                    ? "run Microsoft's DISM RestoreHealth followed by System File Checker (SFC /scannow)"
                    : "run Microsoft's System File Checker (SFC /scannow)";
                if (MessageBox.Show(
                        this,
                        $"The read-only checks indicate possible Windows corruption. Winvexa can {actions}, then repeat read-only verification. This system-wide operation may take a long time. Continue?",
                        "Confirm Windows system repair",
                        MessageBoxButton.YesNo,
                        MessageBoxImage.Warning) == MessageBoxResult.Yes)
                {
                    if (MessageBox.Show(this,
                            "Create a Windows restore point before the system repair if Windows allows it?",
                            "Create a restore point",
                            MessageBoxButton.YesNo,
                            MessageBoxImage.Question) == MessageBoxResult.Yes)
                    {
                        try
                        {
                            await _service.CreateRestorePointAsync();
                            AddReport("A Windows restore point was created before system repair.");
                        }
                        catch (Exception exception) when (!_stopRequested || exception is not OperationCanceledException)
                        {
                            WriteLog($"On-Demand repair restore point could not be created: {exception}");
                            AddReport($"Restore point could not be created: {exception.Message}.");
                            if (MessageBox.Show(this,
                                    $"Windows could not create a restore point:{Environment.NewLine}{exception.Message}{Environment.NewLine}{Environment.NewLine}Continue with the separately approved Windows repair without a restore point?",
                                    "Restore point unavailable",
                                    MessageBoxButton.YesNo,
                                    MessageBoxImage.Warning) != MessageBoxResult.Yes)
                            {
                                userActions.Add("System repair was not started because a restore point was unavailable and the user declined to continue.");
                                unresolved.Add("Windows system/component corruption remains because repair was not started.");
                                actions = string.Empty;
                            }
                        }
                    }
                    else
                    {
                        AddReport("Restore point creation was declined; the separately approved repair may proceed without one.");
                    }

                    if (!string.IsNullOrEmpty(actions))
                    {
                        systemRepairAttempted = true;
                        repairActions.Add(actions + ".");
                        if (dismRepairIndicated)
                        {
                            SetStatus("Repairing the Windows component store with DISM...");
                            SetProgress(79, "DISM RestoreHealth");
                            var failed = await RunWindowsSystemRepairAsync("DISM RestoreHealth", _service.RunDismRestoreHealthAsync);
                            if (failed)
                                repairFailures.Add("DISM RestoreHealth failed.");

                            if (failed)
                            {
                                AddReport("SFC /scannow was not started because DISM repair or repair-source verification did not succeed.");
                                repairFailures.Add("System File Checker was not started because the preceding DISM repair did not succeed.");
                            }
                            else
                            {
                                SetStatus("Repairing Windows system files with SFC...");
                                SetProgress(83, "System File Checker");
                                var sfcFailed = await RunWindowsSystemRepairAsync("System File Checker /scannow", _service.RunSystemFileCheckerAsync);
                                if (sfcFailed)
                                    repairFailures.Add("System File Checker /scannow failed.");
                            }
                        }
                        else
                        {
                            SetStatus("Repairing Windows system files with SFC...");
                            SetProgress(83, "System File Checker");
                            var sfcFailed = await RunWindowsSystemRepairAsync("System File Checker /scannow", _service.RunSystemFileCheckerAsync);
                            if (sfcFailed)
                                repairFailures.Add("System File Checker /scannow failed.");
                        }
                    }
                }
                else
                {
                    userActions.Add("Windows system repair was declined; no system files were changed.");
                    unresolved.Add("Windows system/component corruption remains because repair was declined.");
                }
            }

            string[] repeatedUpdateFailures = updateDiagnostics is null
                ? Array.Empty<string>()
                : GetRepeatedUpdateFailures(updateDiagnostics);
            var updateProblem = updateDiagnostics is not null &&
                                (!updateDiagnostics.IsOperational || repeatedUpdateFailures.Length > 0);
            if (updateProblem || updateDiagnostics is { PendingUpdates.Count: > 0, IsOperational: true })
            {
                updateRepairAttempted = true;
                try
                {
                    if (updateProblem)
                    {
                        repairActions.Add("Run the existing Windows Update Loop repair workflow, which asks separately before cache changes, DISM/SFC repair, or update installation.");
                        SetStatus("Repairing the diagnosed Windows Update problem...");
                        SetProgress(86, "Windows Update repair");
                        await RunWindowsUpdateLoopRepairWorkflowAsync(updateDiagnostics);
                    }
                    else
                    {
                        repairActions.Add("Check available Windows updates and offer installation with explicit confirmation.");
                        SetStatus("Reviewing available Windows updates...");
                        SetProgress(86, "Windows Update");
                        await RunWindowsUpdateScanRepairWorkflowAsync();
                    }
                }
                catch (Exception exception) when (!_stopRequested || exception is not OperationCanceledException)
                {
                    WriteLog($"On-Demand Windows Update repair failed: {exception}");
                    repairFailures.Add($"Windows Update repair failed: {exception.Message}");
                }
            }
            else if (updateDiagnostics is { PendingUpdates.Count: > 0, IsOperational: true })
            {
                userActions.Add("Applicable Windows updates are available. Use Check / Repair to review and approve update installation.");
            }

            if (driveHealth is { Issues: > 0 })
            {
                unresolved.Add($"{driveHealth.Issues} drive/file-system health issue(s) remain for review. Winvexa ran status-only checks and did not run CHKDSK repair or another potentially destructive disk operation.");
                userActions.Add("Review the per-drive details in the activity log. If Windows recommends an offline repair, schedule it through Windows after backing up important data.");
            }
            if (updateDiagnostics is { RestartRequired: true })
                unresolved.Add("A restart is required before Windows Update can be fully verified. Winvexa will not restart the computer without confirmation.");
        }

        SetStatus("Verifying Repair...");
        SetProgress(90, "Verifying Repair");
        if (cleanupAttempted)
        {
            try
            {
                var afterCleanup = await Task.Run(_service.ScanCleanup);
                if (afterCleanup.FileCount == 0)
                {
                    AddReport("Cleanup verification succeeded: no eligible stale temporary/cache files remain.");
                    repairSuccesses.Add($"Safe temporary/cache cleanup verified; approximately {MaintenanceService.FormatBytes(cleanupScan!.Bytes)} had been eligible before cleanup.");
                }
                else
                {
                    unresolved.Add($"{afterCleanup.FileCount} eligible temporary/cache file(s) remain after cleanup.");
                }
            }
            catch (Exception exception) when (!_stopRequested || exception is not OperationCanceledException)
            {
                repairFailures.Add($"Cleanup verification failed: {exception.Message}");
            }
        }

        if (systemRepairAttempted)
        {
            var verificationSucceeded = true;
            foreach (var check in new[]
                     {
                         ("DISM ScanHealth", (Func<Task<WindowsSystemRepairResult>>)_service.RunDismScanHealthAsync),
                         ("System File Checker VerifyOnly", (Func<Task<WindowsSystemRepairResult>>)_service.RunSystemFileVerificationAsync)
                     })
            {
                try
                {
                    var result = await check.Item2();
                    var failed = result.ExitCode != 0 ||
                                 SystemCheckOutputIndicatesRepair(result.Output) ||
                                 SystemCheckOutputIndicatesRepair(result.Error);
                    AddReport($"Post-repair {check.Item1}: exit code {result.ExitCode}; {(failed ? "problem still indicated or verification failed" : "no repair indication reported")}.");
                    if (failed)
                        verificationSucceeded = false;
                }
                catch (Exception exception) when (!_stopRequested || exception is not OperationCanceledException)
                {
                    verificationSucceeded = false;
                    repairFailures.Add($"Post-repair {check.Item1} verification failed: {exception.Message}");
                }
            }
            if (verificationSucceeded)
                repairSuccesses.Add("Windows system/component repair verified by follow-up DISM and SFC checks.");
            else
                unresolved.Add("Windows system/component health could not be verified as repaired.");
        }
        else if (systemChecks.Any(check => check.RepairIndicated))
        {
            unresolved.Add("Windows system/component corruption was detected, but its repair was not completed.");
        }

        if (updateRepairAttempted)
        {
            try
            {
                SetStatus("Verifying Windows Update...");
                var finalUpdate = await _service.DiagnoseWindowsUpdateAsync();
                AddUpdateDiagnosticsToReport("Post-repair Windows Update verification", finalUpdate);
                var stillFailing = GetRepeatedUpdateFailures(finalUpdate);
                if (finalUpdate.IsOperational && !finalUpdate.RestartRequired && stillFailing.Length == 0 &&
                    finalUpdate.PendingUpdates.Count == 0)
                    repairSuccesses.Add("Windows Update follow-up verification succeeded; no repeated failure or applicable update remains.");
                else if (finalUpdate.RestartRequired)
                {
                    userActions.Add("Windows Update requires a restart before the final state can be verified. Use Verify Windows Update after restarting.");
                    unresolved.Add("Windows Update verification is pending a restart.");
                }
                else if (finalUpdate.IsOperational && finalUpdate.PendingUpdates.Count > 0 && stillFailing.Length == 0)
                {
                    unresolved.Add($"{finalUpdate.PendingUpdates.Count} applicable Windows Update(s) remain; review and approve their installation in Windows Update.");
                    userActions.Add($"{finalUpdate.PendingUpdates.Count} applicable update(s) remain after the update check.");
                }
                else
                    unresolved.Add($"Windows Update still reports an issue or repeated update failure ({FormatWindowsUpdateError(finalUpdate)}).");
            }
            catch (Exception exception) when (!_stopRequested || exception is not OperationCanceledException)
            {
                repairFailures.Add($"Post-repair Windows Update verification failed: {exception.Message}");
                unresolved.Add("Windows Update repair could not be verified.");
            }
        }

        AddReport("REPAIR ACTIONS RUN / ATTEMPTED:");
        if (repairActions.Count == 0)
            AddReport("  None.");
        else
            foreach (var repair in repairActions)
                AddReport($"  - {repair}");

        AddReport("REPAIRS THAT SUCCEEDED:");
        if (repairSuccesses.Count == 0)
            AddReport("  None verified.");
        else
            foreach (var success in repairSuccesses)
                AddReport($"  - {success}");

        AddReport("REPAIRS THAT FAILED:");
        if (repairFailures.Count == 0)
            AddReport("  None reported.");
        else
            foreach (var failure in repairFailures)
                AddReport($"  - {failure}");

        AddReport("ITEMS REQUIRING USER ACTION:");
        if (userActions.Count == 0)
            AddReport("  None reported.");
        else
            foreach (var action in userActions.Distinct(StringComparer.OrdinalIgnoreCase))
                AddReport($"  - {action}");

        AddReport("FINAL SYSTEM STATUS:");
        var incomplete = unresolved.Count > 0 || repairFailures.Count > 0 ||
                         (problems.Count > 0 && repairActions.Count == 0 && userActions.Count > 0);
        if (unresolved.Count > 0)
        {
            foreach (var issue in unresolved.Distinct(StringComparer.OrdinalIgnoreCase))
                AddReport($"  - {issue}");
            AddReport("Repair Could Not Be Completed. See the findings, user-action items, and detailed activity log.");
            SetStatus("Repair Could Not Be Completed — review the final report.");
            SetProgress(100, "Repair Could Not Be Completed");
        }
        else if (incomplete)
        {
            AddReport("Repair Could Not Be Completed. One or more diagnostics or approved operations failed; no failed operation is reported as repaired.");
            SetStatus("Repair Could Not Be Completed — review the final report.");
            SetProgress(100, "Repair Could Not Be Completed");
        }
        else
        {
            AddReport("Repair Complete. No remaining issue was reported by the available follow-up checks.");
            SetStatus("Repair Complete.");
            SetProgress(100, "Repair Complete");
        }

        ReportText.Text = string.Join(Environment.NewLine + Environment.NewLine, _report);
        WriteLog($"=== On-Demand PC Repair finished: {(incomplete ? "issues remain or checks failed" : "complete")} ===");
    }

    private async void Repair_Click(object sender, RoutedEventArgs e)
    {
        if (!EnsureSupported())
            return;

        if (!IsAdministrator())
        {
            RequestElevation(
                "--repair",
                "The complete repair workflow needs administrator access to create a restore point, run read-only system drive checks, and perform some Windows maintenance. Windows will show its standard UAC prompt; this app will not bypass it.");
            return;
        }

        await RunActionAsync("Repair My PC", RunRepairWorkflowAsync);
    }

    private async Task RunRepairWorkflowAsync()
    {
        _report.Clear();
        _workflowFailures.Clear();
        ReportText.Clear();
        WriteLog("=== Guided repair workflow started ===");
        if (!await EnsureVerifiedWindowsRepairSourceAsync())
            return;

        const int totalSteps = 10;
        var step = 0;

        await RunWorkflowStageAsync("Creating a restore point", _service.CreateRestorePointAsync, ++step, totalSteps, failureIsCritical: false);

        CleanupScan? scan = null;
        await RunWorkflowStageAsync("Scanning accessible drives and safe temporary files", async () =>
        {
            scan = await ScanAndReportAsync();
            ShowScanSummary(scan);
        }, ++step, totalSteps);

        if (scan is not null)
        {
            var cleanupApproved = ConfirmTemporaryCleanup(scan);
            if (cleanupApproved)
            {
                var cleanupScan = scan;
                await RunWorkflowStageAsync("Cleaning approved temporary files", async () =>
                {
                    var bytes = await Task.Run(() => _service.CleanFiles(cleanupScan));
                    AddReport($"Temporary-file cleanup recovered approximately {MaintenanceService.FormatBytes(bytes)}.");
                }, ++step, totalSteps);
            }
            else
            {
                WriteLog("Temporary-file cleanup declined; no scanned files were removed.");
                AddReport("Temporary-file cleanup was declined.");
                step++;
                SetProgress(step * 100 / totalSteps, "Temporary-file cleanup declined");
            }

            await OfferRecycleBinCleanupAsync();
        }
        else
        {
            step++;
            SetProgress(step * 100 / totalSteps, "Cleanup analysis unavailable; continuing safely");
        }

        await RunWorkflowStageAsync("Checking drive and file-system health", async () =>
        {
            var driveHealth = await CheckDriveHealthInBackgroundAsync();
            AddReport($"Drive health: {driveHealth.Checked} NTFS volume(s) checked, {driveHealth.Issues} issue(s), " +
                      $"{driveHealth.Failed} check(s) failed, {driveHealth.Skipped} skipped, " +
                      $"{driveHealth.PhysicalDisksChecked} physical disk(s) inspected.");
            if (driveHealth.Issues > 0 || driveHealth.Failed > 0)
            {
                var issue = $"Drive health reported {driveHealth.Issues} file-system or physical-disk issue(s) and {driveHealth.Failed} incomplete check(s).";
                _workflowFailures.Add(issue);
                WriteLog(issue);
            }
        }, ++step, totalSteps);

        if (MessageBox.Show(
                this,
                "Run Microsoft's read-only DISM component-store health scan and System File Checker verification? These checks may take several minutes and do not repair files. Any repair would require separate approval.",
                "Windows system health checks",
                MessageBoxButton.YesNo,
                MessageBoxImage.Question) == MessageBoxResult.Yes)
        {
            await RunWorkflowStageAsync("Checking Windows system files and component store", async () =>
            {
                var checks = new List<(string Name, WindowsSystemRepairResult Result)>
                {
                    ("DISM ScanHealth", await _service.RunDismScanHealthAsync()),
                    ("System File Checker VerifyOnly", await _service.RunSystemFileVerificationAsync())
                };
                var failures = new List<string>();
                foreach (var check in checks)
                {
                    AddReport($"{check.Name} exit code: {check.Result.ExitCode}.");
                    if (!string.IsNullOrWhiteSpace(check.Result.Output))
                        AddReport($"{check.Name}: {check.Result.Output.Trim()}");
                    if (!string.IsNullOrWhiteSpace(check.Result.Error))
                        AddReport($"{check.Name} diagnostic: {check.Result.Error.Trim()}");
                    if (check.Result.ExitCode != 0)
                        failures.Add($"{check.Name} exited with code {check.Result.ExitCode}.");
                }
                if (failures.Count > 0)
                    throw new InvalidOperationException(string.Join(" ", failures));
            }, ++step, totalSteps);
        }
        else
        {
            const string message = "Optional read-only Windows system/component checks were declined.";
            WriteLog(message);
            AddReport(message);
            step++;
            SetProgress(step * 100 / totalSteps, "System checks declined");
        }

        var defenderScanAvailable = false;
        await RunWorkflowStageAsync("Checking Microsoft Defender security and intelligence status", async () =>
        {
            defenderScanAvailable = await CheckDefenderForRepairWorkflowAsync();
        }, ++step, totalSteps);
        if (defenderScanAvailable)
        {
            await RunWorkflowStageAsync("Running Microsoft Defender Quick Scan", async () =>
            {
                var result = await _service.RunDefenderScanAsync(fullScan: false);
                AddReport($"Microsoft Defender Quick Scan: {result}");
            }, ++step, totalSteps);
        }
        else
        {
            const string message = "Microsoft Defender Quick Scan was not started because protection could not be verified as active.";
            WriteLog(message);
            AddReport(message);
            step++;
            SetProgress(step * 100 / totalSteps, "Defender scan skipped because protection is unavailable");
        }

        var cleanupWindows = MessageBox.Show(
            this,
            "Open Microsoft's Windows Disk Cleanup for every accessible local drive? Each drive will show its own supported categories. You control the selected items in each Windows dialog.",
            "Windows Cleanup",
            MessageBoxButton.YesNo,
            MessageBoxImage.Question) == MessageBoxResult.Yes;
        if (cleanupWindows)
            await RunWorkflowStageAsync("Running supported Windows Disk Cleanup", RunWindowsCleanupOnAllDrivesAsync, ++step, totalSteps);
        else
        {
            WriteLog("Windows Disk Cleanup declined.");
            AddReport("Windows Disk Cleanup was declined.");
            step++;
            SetProgress(step * 100 / totalSteps, "Windows cleanup declined");
        }

        await RunWorkflowStageAsync("Scanning, repairing, and verifying Windows Update", async () =>
        {
            var updateDiagnostics = await _service.DiagnoseWindowsUpdateAsync();
            var repeatedFailures = GetRepeatedUpdateFailures(updateDiagnostics);
            if (repeatedFailures.Length > 0)
            {
                AddUpdateDiagnosticsToReport("Windows Update loop diagnostic", updateDiagnostics);
                var titles = string.Join(Environment.NewLine, repeatedFailures.Take(5).Select(title => $"• {title}"));
                if (repeatedFailures.Length > 5)
                    titles += $"{Environment.NewLine}• and {repeatedFailures.Length - 5} more";
                var answer = MessageBox.Show(
                    this,
                    $"Recent update history shows repeated failures for the same update:{Environment.NewLine}{Environment.NewLine}{titles}{Environment.NewLine}{Environment.NewLine}Run the dedicated Windows Update loop repair and final verification now?",
                    "Repeated Windows Update failure detected",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Warning);
                if (answer == MessageBoxResult.Yes)
                {
                    await RunWindowsUpdateLoopRepairWorkflowAsync(updateDiagnostics);
                    return;
                }
            }
            await RunWindowsUpdateScanRepairWorkflowAsync();
        }, ++step, totalSteps);

        if (MessageBox.Show(
                this,
                "Would you like to scan for optional Windows 11 optimizations? The scan itself makes no changes. Any proposed change must be individually reviewed and approved.",
                "Optional Windows 11 optimization scan",
                MessageBoxButton.YesNo,
                MessageBoxImage.Question) == MessageBoxResult.Yes)
        {
            var optimizationWindow = new OptimizationWindow(_service, WriteLog) { Owner = this };
            optimizationWindow.ShowDialog();
            AddReport("Optional Windows 11 optimization scan was opened. Changes were not applied automatically; any selected actions required separate review and confirmation.");
        }
        else
        {
            AddReport("Optional Windows 11 optimization scan was declined.");
        }

        var completedWithIssues = _workflowFailures.Count > 0;
        SetProgress(100, completedWithIssues ? "Repair workflow completed with issues" : "Repair workflow complete");
        AddReport(completedWithIssues
            ? $"Repair workflow completed with {_workflowFailures.Count} issue(s). Review the report and activity log; Winvexa has not treated failed stages as successful."
            : "Repair workflow completed. Review the activity log for detailed results, any errors, and Windows Update/restart status.");
        ReportText.Text = string.Join(Environment.NewLine + Environment.NewLine, _report);
        SetStatus(completedWithIssues
            ? $"Repair workflow completed with {_workflowFailures.Count} issue(s). Review the final report and session log."
            : "Repair workflow complete. Review the final report and session log.");
        WriteLog(completedWithIssues
            ? $"=== Guided repair workflow completed with {_workflowFailures.Count} issue(s) ==="
            : "=== Guided repair workflow finished ===");
    }

    private async Task<bool> CheckDefenderForRepairWorkflowAsync()
    {
        DefenderSecurityStatus security;
        try
        {
            security = await _service.GetDefenderSecurityStatusAsync();
        }
        catch (Exception exception) when (!_stopRequested || exception is not OperationCanceledException)
        {
            const string message = "Microsoft Defender security status is unable to verify.";
            AddReport($"{message} No Defender update or scan was started.");
            _workflowFailures.Add(message);
            WriteLog($"{message} Details: {exception}");
            OfferOpenWindowsSecurity(message);
            return false;
        }

        AddReport(
            $"Microsoft Defender status: {security.OverallStatus}; antivirus active={security.AntivirusEnabled}; " +
            $"real-time protection={security.RealTimeProtectionEnabled}; mode={security.RunningMode}; " +
            $"security intelligence version={security.SignatureVersion}, age={security.SignatureAgeDays?.ToString() ?? "unavailable"} day(s); " +
            $"active threats={security.ActiveThreats.Count}.");

        var protectionActive = security.ServiceEnabled &&
                               security.AntivirusEnabled &&
                               security.RealTimeProtectionEnabled &&
                               security.RunningMode.Equals("Normal", StringComparison.OrdinalIgnoreCase);
        if (!protectionActive)
        {
            var message =
                $"Microsoft Defender protection requires attention (service={security.ServiceEnabled}, antivirus={security.AntivirusEnabled}, real-time={security.RealTimeProtectionEnabled}, mode={security.RunningMode}). Winvexa will not change protection settings.";
            _workflowFailures.Add(message);
            AddReport(message);
            OfferOpenWindowsSecurity(message);
            return false;
        }

        if (security.ActiveThreats.Count > 0)
        {
            var activeThreats = string.Join(Environment.NewLine, security.ActiveThreats
                .Select(threat => $"• {threat.ThreatName} (ID {threat.ThreatId})"));
            var message = $"Windows reports {security.ActiveThreats.Count} active Defender threat detection(s):{Environment.NewLine}{activeThreats}";
            AddReport(message);
            WriteLog(message);
            OfferOpenWindowsSecurity("Microsoft Defender reports active threat detections. Review the threat details in Windows Security.");
        }

        if (security.SignatureAgeDays is null || security.SignatureLastUpdated is null ||
            string.IsNullOrWhiteSpace(security.SignatureVersion) ||
            security.SignatureVersion.Equals("Unavailable", StringComparison.OrdinalIgnoreCase))
        {
            const string message = "Microsoft Defender security intelligence freshness could not be verified.";
            AddReport(message);
            _workflowFailures.Add(message);
            return false;
        }

        if (security.SignatureAgeDays > 7)
        {
            var answer = MessageBox.Show(
                this,
                $"Microsoft Defender security intelligence is {security.SignatureAgeDays} day(s) old (version {security.SignatureVersion}, last updated {security.SignatureLastUpdated.Value.LocalDateTime:g}). Winvexa can request the supported Microsoft Defender intelligence update. Continue? A scan will not be started if the update fails.",
                "Outdated Defender security intelligence",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning);
            if (answer != MessageBoxResult.Yes)
            {
                const string declined = "Defender intelligence update was declined; the reported signatures remain older than 7 days.";
                AddReport(declined);
                _workflowFailures.Add(declined);
                WriteLog(declined);
                return false;
            }

            try
            {
                SetStatus("Updating Microsoft Defender security intelligence...");
                await _service.UpdateDefenderSignaturesAsync();
                var verified = await _service.GetDefenderSecurityStatusAsync();
                if (verified.SignatureAgeDays is null ||
                    verified.SignatureLastUpdated is null ||
                    string.IsNullOrWhiteSpace(verified.SignatureVersion) ||
                    verified.SignatureVersion.Equals("Unavailable", StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException("Windows did not return verifiable security intelligence version and update time after the update request.");

                AddReport($"Defender security intelligence update succeeded and was verified: version {verified.SignatureVersion}, last updated {verified.SignatureLastUpdated.Value.LocalDateTime:g}, age {verified.SignatureAgeDays} day(s).");
                if (verified.SignatureAgeDays > 7)
                {
                    const string stillOld = "The update operation completed, but Windows still reports security intelligence older than 7 days. Review Windows Update/connectivity and Windows Security.";
                    AddReport(stillOld);
                    _workflowFailures.Add(stillOld);
                    OfferOpenWindowsSecurity(stillOld);
                    return false;
                }
            }
            catch (Exception exception) when (!_stopRequested || exception is not OperationCanceledException)
            {
                var failure = $"Defender security intelligence update failed or could not be verified: {exception.Message}";
                AddReport(failure);
                _workflowFailures.Add(failure);
                WriteLog($"{failure} Details: {exception}");
                return false;
            }
        }
        else
        {
            WriteLog($"Defender security intelligence is recent (version {security.SignatureVersion}, age {security.SignatureAgeDays} day(s)); no update was requested.");
            AddReport("Defender security intelligence was verified and is no more than 7 days old; no update was needed.");
        }

        return true;
    }

    private void OfferOpenWindowsSecurity(string issue)
    {
        if (MessageBox.Show(
                this,
                $"{issue}{Environment.NewLine}{Environment.NewLine}Open Windows Security to review the protection settings and history? Winvexa will not change antivirus settings.",
                "Review Windows Security",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning) != MessageBoxResult.Yes)
            return;

        try
        {
            Process.Start(new ProcessStartInfo("ms-settings:windowsdefender") { UseShellExecute = true });
            WriteLog("Opened Windows Security settings at the user's request.");
        }
        catch (Exception exception) when (exception is InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            var message = $"Windows Security could not be opened automatically: {exception.Message}. Open it from the Start menu.";
            AddReport(message);
            WriteLog(message);
        }
    }

    private async Task<CleanupScan> ScanAndReportAsync()
    {
        SetStatus("Scanning accessible local drives and approved temporary/cache folders...");
        await Task.Yield();
        var scan = await Task.Run(_service.ScanCleanup);
        AddReport($"Accessible local drives detected: {scan.DriveCount}.");
        foreach (var category in scan.Categories)
            AddReport($"{category.Name}: {category.Files.Count} file(s), {MaintenanceService.FormatBytes(category.Bytes)}.");
        AddReport($"Total potential temporary-file recovery: {MaintenanceService.FormatBytes(scan.Bytes)}. Personal folders were not scanned.");
        return scan;
    }

    private void ShowScanSummary(CleanupScan scan)
    {
        var summary = string.Join(Environment.NewLine, scan.Categories
            .Select(category => $"• {category.Name}: {category.Files.Count} file(s), {MaintenanceService.FormatBytes(category.Bytes)}"));
        if (string.IsNullOrWhiteSpace(summary))
            summary = "No approved temporary/cache locations were available.";
        MessageBox.Show(
            this,
            $"Accessible local drives: {scan.DriveCount}{Environment.NewLine}{Environment.NewLine}{summary}{Environment.NewLine}{Environment.NewLine}Approximately {MaintenanceService.FormatBytes(scan.Bytes)} may be recovered. Files are included only if both last access and last modification are at least 10 days old. Personal folders are never scanned.",
            "Safe cleanup analysis",
            MessageBoxButton.OK,
            MessageBoxImage.Information);
    }

    private bool ConfirmTemporaryCleanup(CleanupScan scan)
    {
        if (scan.FileCount == 0)
            return false;
        var categories = string.Join(Environment.NewLine, scan.Categories
            .Where(category => category.Files.Count > 0)
            .Select(category => $"• {category.Name}: {category.Files.Count} file(s), {MaintenanceService.FormatBytes(category.Bytes)}"));
        return MessageBox.Show(
            this,
            $"Review the items found:{Environment.NewLine}{categories}{Environment.NewLine}{Environment.NewLine}Potential recovery: approximately {MaintenanceService.FormatBytes(scan.Bytes)}.{Environment.NewLine}{Environment.NewLine}Only stale files in the listed temporary/cache folders will be removed. Continue?",
            "Confirm temporary-file cleanup",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning) == MessageBoxResult.Yes;
    }

    private async Task OfferRecycleBinCleanupAsync()
    {
        try
        {
            var (bytes, items) = _service.GetRecycleBinSize();
            if (items == 0)
            {
                WriteLog("Recycle Bin is empty.");
                return;
            }
            var answer = MessageBox.Show(
                this,
                $"Windows reports {items} item(s) in the Recycle Bin, approximately {MaintenanceService.FormatBytes(bytes)}. Empty the Recycle Bin? This cannot be undone.",
                "Confirm Recycle Bin emptying",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning);
            if (answer == MessageBoxResult.Yes)
            {
                await Task.Run(_service.EmptyRecycleBin);
                AddReport($"Recycle Bin emptied after confirmation ({items} item(s), approximately {MaintenanceService.FormatBytes(bytes)}).");
            }
            else
            {
                WriteLog("Recycle Bin cleanup declined.");
                AddReport("Recycle Bin contents were left unchanged.");
            }
        }
        catch (Exception exception) when (!_stopRequested || exception is not OperationCanceledException)
        {
            WriteLog($"Recycle Bin operation failed: {exception}");
            AddReport($"Recycle Bin operation failed: {exception.Message}");
            _workflowFailures.Add($"Recycle Bin cleanup failed: {exception.Message}");
        }
    }

    private async Task<bool> RunWindowsUpdateWorkflowAsync()
    {
        var search = await _service.SearchWindowsUpdatesAsync();
        OperationCancellationContext.ThrowIfCancellationRequested();
        if (search.Count == 0)
        {
            ReportNoAdditionalUpdates();
            return false;
        }

        for (var round = 1; ; round++)
        {
            if (round > 10)
            {
                var message = "Windows Update safety limit reached after 10 installation rounds. Run Windows Update again to continue.";
                WriteLog(message);
                AddReport(message);
                return false;
            }

            if (!ConfirmWindowsUpdateInstall(search, round))
            {
                WriteLog($"Windows Update installation for round {round} declined by the user.");
                AddReport($"{search.Count} applicable update(s) remain and were not installed (user declined).");
                return false;
            }
            if (!IsAdministrator())
            {
                RequestElevation(
                    "--windows-update-repair",
                    "Installing Windows Updates requires administrator access. Windows will show its standard UAC prompt; no update will be installed unless you approve it.");
                return false;
            }

            SetStatus($"Downloading/installing Windows Updates (round {round})...");
            (bool RebootRequired, int Installed, int Failed, string Details) installation;
            try
            {
                installation = await _service.InstallWindowsUpdatesAsync(search.Updates);
                AddReport($"Windows Update installation: {installation.Installed} installed successfully, {installation.Failed} failed or partial. {installation.Details}");
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception exception) when (!_stopRequested || exception is not OperationCanceledException)
            {
                WriteLog($"Windows Update installation failed: {exception}");
                AddReport($"Windows Update installation failed: {exception.Message}");
                try
                {
                    search = await _service.SearchWindowsUpdatesAsync();
                    AddReport(search.Count == 0
                        ? "Windows Update check complete. No additional applicable updates were found, although an installation error was reported."
                        : $"After the failed installation attempt, Windows Update reports {search.Count} applicable update(s) remaining.");
                }
                catch (Exception checkException) when (!_stopRequested || checkException is not OperationCanceledException)
                {
                    WriteLog($"Windows Update recheck after installation failure also failed: {checkException}");
                    AddReport($"Windows Update recheck after installation failure also failed: {checkException.Message}");
                }
                return false;
            }

            if (installation.RebootRequired)
            {
                const string message = "Windows Update requires a restart before the final update check can be completed. No restart was forced.";
                WriteLog(message);
                AddReport(message);
                return true;
            }

            OperationCancellationContext.ThrowIfCancellationRequested();
            search = await _service.SearchWindowsUpdatesAsync();
            if (installation.Failed > 0)
            {
                var message = $"Windows Update installed {installation.Installed} update(s), but {installation.Failed} failed or completed with errors. {search.Count} applicable update(s) remain; no further installation was attempted.";
                WriteLog(message);
                AddReport(message);
                return false;
            }

            if (search.Count == 0)
            {
                ReportNoAdditionalUpdates();
                return false;
            }

            if (installation.Installed == 0)
            {
                var message = $"No approved update was installed, and {search.Count} applicable update(s) remain. Run Windows Update again to review them.";
                WriteLog(message);
                AddReport(message);
                return false;
            }

            WriteLog($"{search.Count} follow-up update(s) found after installation round {round}; user confirmation is required before installing this new set.");
        }
    }

    private async Task RunWindowsUpdateScanRepairWorkflowAsync()
    {
        SetStatus("Checking Windows Update services, scan response, recent failures, pending updates, and restart state...");
        SetProgress(5, "Initial Windows Update diagnostics");
        var initial = await _service.DiagnoseWindowsUpdateAsync();
        AddUpdateDiagnosticsToReport("Initial diagnostic", initial);
        var current = initial;

        if (!current.IsOperational)
        {
            var disabled = current.Services
                .Where(service => service.Name is "wuauserv" or "bits" or "cryptsvc")
                .Where(service => service.StartMode.Equals("Disabled", StringComparison.OrdinalIgnoreCase))
                .Select(service => service.Name)
                .ToArray();

            if (current.SearchError is not null && disabled.Length == 0)
            {
                var answer = MessageBox.Show(
                    this,
                    $"Windows Update could not complete its initial scan.{Environment.NewLine}{Environment.NewLine}{FormatWindowsUpdateError(current)}{Environment.NewLine}{Environment.NewLine}Winvexa can attempt to start the Windows Update, Background Intelligent Transfer, and Cryptographic services without changing their startup configuration, then check again. Continue?",
                    "Repair Windows Update services",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Warning);
                if (answer == MessageBoxResult.Yes && !EnsureRepairElevation())
                    return;
                if (answer == MessageBoxResult.Yes)
                {
                    if (!await EnsureVerifiedWindowsRepairSourceAsync())
                        return;

                    SetStatus("Attempting to start eligible Windows Update services...");
                    SetProgress(15, "Starting Windows Update services");
                    try
                    {
                        var repair = await _service.StartWindowsUpdateServicesAsync();
                        foreach (var error in repair.Errors)
                            AddReport($"Service repair warning: {error}");
                    }
                    catch (Exception exception) when (!_stopRequested || exception is not OperationCanceledException)
                    {
                        WriteLog($"Windows Update service recovery failed: {exception}");
                        AddReport($"Windows Update service recovery failed: {exception.Message}");
                    }
                    current = await _service.DiagnoseWindowsUpdateAsync();
                    AddUpdateDiagnosticsToReport("After service recovery", current);
                }
                else
                {
                    AddReport("Windows Update service recovery was declined; no service configuration was changed.");
                }
            }
            else if (disabled.Length > 0)
            {
                var message = $"A required Windows Update service is configured as Disabled ({string.Join(", ", disabled)}). Winvexa will not change service startup settings; this may be controlled by an administrator or policy.";
                WriteLog(message);
                AddReport(message);
            }

            var cacheRepairIndicated = current.RecentFailures.Count > 0 || current.RecentEventErrors.Count > 0;
            if (!current.IsOperational && current.SearchError is not null && disabled.Length == 0 && cacheRepairIndicated)
            {
                var allowCacheRepair = MessageBox.Show(
                    this,
                    $"Windows Update is still not responding, and recent update failures/errors were found.{Environment.NewLine}{Environment.NewLine}{FormatWindowsUpdateError(current)}{Environment.NewLine}{Environment.NewLine}Winvexa can stop the related services, move only the Windows Update Download cache to a timestamped backup, restart services that were running, and verify Windows Update again. The backup will be retained and not deleted. Continue?",
                    "Confirm reversible Windows Update cache repair",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Warning) == MessageBoxResult.Yes;
                if (allowCacheRepair && !EnsureRepairElevation())
                    return;
                if (allowCacheRepair)
                {
                    if (!await EnsureVerifiedWindowsRepairSourceAsync())
                        return;

                    SetStatus("Moving the Windows Update Download cache to a retained backup...");
                    SetProgress(30, "Rebuilding Windows Update Download cache");
                    try
                    {
                        var repair = await _service.RebuildWindowsUpdateDownloadCacheAsync();
                        AddReport(string.IsNullOrWhiteSpace(repair.BackupPath)
                            ? "Windows Update Download cache did not exist; no cache files were changed."
                            : $"Windows Update Download cache was moved to the retained backup: {repair.BackupPath}. The backup was not deleted.");
                    }
                    catch (Exception exception) when (!_stopRequested || exception is not OperationCanceledException)
                    {
                        WriteLog($"Windows Update cache repair failed: {exception}");
                        AddReport($"Windows Update cache repair failed: {exception.Message}");
                    }
                    current = await _service.DiagnoseWindowsUpdateAsync();
                    AddUpdateDiagnosticsToReport("After Download cache repair", current);
                }
                else
                {
                    AddReport("Windows Update Download cache repair was declined; no cache files were changed.");
                }
            }
            else if (!current.IsOperational && current.SearchError is not null && disabled.Length == 0)
            {
                const string message = "No recent failed installations or Windows Update error events implicated the download cache; Winvexa skipped the cache rebuild.";
                WriteLog(message);
                AddReport(message);
            }

            if (!current.IsOperational && current.SearchError is not null && disabled.Length == 0)
            {
                var repairSystem = MessageBox.Show(
                    this,
                    $"Windows Update is still not responding after the supported service/cache checks.{Environment.NewLine}{Environment.NewLine}{FormatWindowsUpdateError(current)}{Environment.NewLine}{Environment.NewLine}Winvexa can run Microsoft's DISM component-store repair followed by System File Checker (SFC). These system-wide checks can take a long time and may contact Windows Update. They will run only with your approval. Continue?",
                    "Confirm Windows system-component repair",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Warning) == MessageBoxResult.Yes;
                if (repairSystem && !EnsureRepairElevation())
                    return;
                if (repairSystem)
                {
                    SetStatus("Running Microsoft's DISM component-store repair...");
                    SetProgress(45, "DISM RestoreHealth");
                    try
                    {
                        var dismFailed = await RunWindowsSystemRepairAsync(
                            "DISM RestoreHealth",
                            _service.RunDismRestoreHealthAsync);
                        if (dismFailed)
                        {
                            AddReport("SFC /scannow was not started because DISM repair or repair-source verification did not succeed.");
                        }
                        else
                        {
                            SetStatus("Running Microsoft's System File Checker...");
                            SetProgress(65, "System File Checker");
                            await RunWindowsSystemRepairAsync(
                                "System File Checker /scannow",
                                _service.RunSystemFileCheckerAsync);
                        }
                    }
                    catch (Exception exception) when (!_stopRequested || exception is not OperationCanceledException)
                    {
                        WriteLog($"Windows system repair failed: {exception}");
                        AddReport($"Windows system repair failed: {exception.Message}");
                    }
                }
                else
                {
                    AddReport("DISM and SFC were declined; no Windows system files were checked or repaired by Winvexa.");
                }
            }
        }

        SetStatus("Performing final Windows Update verification...");
        SetProgress(80, "Final Windows Update verification");
        var final = await _service.DiagnoseWindowsUpdateAsync();
        AddUpdateDiagnosticsToReport("Final verification", final);
        if (final.IsOperational)
        {
            var status = initial.IsOperational
                ? "Windows Update is healthy: the final scan succeeded and its critical services were verified."
                : "Windows Update repair was verified: the final scan succeeded and its critical services are available.";
            AddReport(status);
            WriteLog(status);
        }
        else
        {
            var error = FormatWindowsUpdateError(final);
            var message = $"Windows Update could not be completely repaired. {error} Review the repair report and activity log for details.";
            AddReport(message);
            WriteLog(message);
            SetStatus("Windows Update could not be completely repaired. Review the report and activity log.");
            throw new InvalidOperationException(message);
        }

        if (final.RestartRequired)
        {
            const string restartMessage = "Windows Update requires a restart before the final update check can be completed. Winvexa will not restart the computer without your separate confirmation.";
            AddReport(restartMessage);
            WriteLog(restartMessage);
            SetStatus("Windows Update requires a restart. No restart was forced.");
            return;
        }

        if (final.RecentFailures.Count > 0 || final.RecentEventErrors.Count > 0)
        {
            var historical = $"Recent Windows Update history still contains {final.RecentFailures.Count} failed installation(s) and {final.RecentEventErrors.Count} error event(s). These are historical records; the final Windows Update scan succeeded.";
            AddReport(historical);
            WriteLog(historical);
        }

        var search = new UpdateSearch(final.PendingUpdates, false, "Final diagnostic scan succeeded.");
        if (search.Count == 0)
        {
            ReportNoAdditionalUpdates();
            return;
        }

        AddReport($"Final Windows Update scan found {search.Count} applicable update(s).");
        if (await RunWindowsUpdateWorkflowAsync())
        {
            SetStatus("Windows Update requires a restart. No restart was forced.");
            return;
        }

        SetStatus("Verifying Windows Update after the installation decision...");
        SetProgress(95, "Post-installation Windows Update verification");
        var postInstall = await _service.DiagnoseWindowsUpdateAsync();
        AddUpdateDiagnosticsToReport("Post-installation verification", postInstall);
        if (!postInstall.IsOperational)
        {
            var message = $"Windows Update could not be completely repaired or verified after the update check. {FormatWindowsUpdateError(postInstall)}";
            AddReport(message);
            WriteLog(message);
            SetStatus("Windows Update could not be completely verified. Review the report and activity log.");
            throw new InvalidOperationException(message);
        }
        else if (postInstall.RestartRequired)
        {
            const string message = "Windows Update requires a restart before the final update check can be completed. No restart was forced.";
            AddReport(message);
            WriteLog(message);
            SetStatus("Windows Update requires a restart. No restart was forced.");
        }
        else if (postInstall.PendingUpdates.Count == 0)
        {
            const string message = "Final Windows Update verification succeeded. No additional applicable updates were found.";
            AddReport(message);
            WriteLog(message);
            SetStatus(message);
        }
        else
        {
            var message = $"Final Windows Update verification succeeded; {postInstall.PendingUpdates.Count} applicable update(s) remain.";
            AddReport(message);
            WriteLog(message);
            SetStatus(message);
        }
    }

    private bool EnsureRepairElevation(string workflowArgument = "--windows-update-repair")
    {
        if (IsAdministrator())
            return true;
        var restartedElevated = RequestElevation(
            workflowArgument,
            "Repairing Windows Update services/cache or running DISM and SFC requires administrator access. The requested operation will run only after you approve the standard Windows UAC prompt.");
        if (!restartedElevated)
        {
            const string message = "Windows Update repair did not continue because administrator access was not granted.";
            _workflowFailures.Add(message);
            AddReport(message);
        }
        return false;
    }

    private void AddUpdateDiagnosticsToReport(string heading, WindowsUpdateDiagnostics diagnostics)
    {
        AddReport($"{heading}: Windows Update scan {(diagnostics.SearchSucceeded ? "successful" : "failed")}; {diagnostics.PendingUpdates.Count} pending update(s); restart required: {(diagnostics.RestartRequired ? "yes" : "no")}.");
        foreach (var service in diagnostics.Services)
            AddReport($"Service {service.Name}: {service.State}, startup type {service.StartMode}.");
        if (diagnostics.SearchError is not null)
            AddReport(FormatWindowsUpdateError(diagnostics));
        if (diagnostics.RecentFailures.Count > 0)
        {
            AddReport($"{diagnostics.RecentFailures.Count} failed Windows Update installation(s) appear in the last 30 days of update history (historical; not by itself proof of a current failure).");
            foreach (var failure in diagnostics.RecentFailures.Take(10))
                AddReport($"Update history failure {failure.HResult}: {failure.Title} ({failure.Date}, result {failure.ResultCode}).");
        }
        if (diagnostics.RecentEventErrors.Count > 0)
        {
            AddReport($"{diagnostics.RecentEventErrors.Count} Windows Update error event(s) appear in the last 30 days (historical; the final scan result determines current operation).");
            foreach (var error in diagnostics.RecentEventErrors.Take(10))
                AddReport($"Windows Update event {error.EventId} {error.HResult}: {error.Date}.");
        }
        foreach (var warning in diagnostics.DiagnosticWarnings)
            AddReport($"Diagnostic warning: {warning}");
    }

    private static string FormatWindowsUpdateError(WindowsUpdateDiagnostics diagnostics)
    {
        var errorCode = string.IsNullOrWhiteSpace(diagnostics.SearchHResult) ? "HRESULT unavailable" : diagnostics.SearchHResult;
        var details = string.IsNullOrWhiteSpace(diagnostics.SearchError) ? "Windows Update service configuration is disabled or unavailable." : diagnostics.SearchError;
        return $"Windows Update error {errorCode}: {details}";
    }

    private bool ConfirmWindowsUpdateInstall(UpdateSearch search, int round)
    {
        var titleList = string.Join(Environment.NewLine, search.Titles.Take(12).Select(title => $"• {title}"));
        if (search.Titles.Count > 12)
            titleList += $"{Environment.NewLine}• and {search.Titles.Count - 12} more";
        return MessageBox.Show(
            this,
            $"Windows Update found {search.Count} applicable software update(s) for round {round}:{Environment.NewLine}{Environment.NewLine}{titleList}{Environment.NewLine}{Environment.NewLine}Download and install these updates? No restart will be forced.",
            "Confirm Windows Update installation",
            MessageBoxButton.YesNo,
            MessageBoxImage.Question) == MessageBoxResult.Yes;
    }

    private void ReportNoAdditionalUpdates()
    {
        const string message = "Windows Update check complete. No additional applicable updates were found.";
        AddReport(message);
        WriteLog(message);
        SetStatus(message);
    }

    private async Task RunWindowsCleanupOnAllDrivesAsync()
    {
        var drives = _service.GetLocalDrives();
        if (drives.Count == 0)
        {
            const string message = "Windows Disk Cleanup was not started because no accessible local drives were detected.";
            WriteLog(message);
            AddReport(message);
            return;
        }

        foreach (var drive in drives)
        {
            OperationCancellationContext.ThrowIfCancellationRequested();
            try
            {
                var recovered = await _service.LaunchWindowsCleanupAsync(drive.Name);
                AddReport(recovered.HasValue
                    ? $"{drive.Name} Windows Disk Cleanup free-space increase: approximately {MaintenanceService.FormatBytes(recovered.Value)} (estimate; background activity can affect it)."
                    : $"{drive.Name} Windows Disk Cleanup completed; its free-space change could not be measured.");
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception exception) when (!_stopRequested || exception is not OperationCanceledException)
            {
                WriteLog($"Windows Disk Cleanup failed for {drive.Name}: {exception}");
                AddReport($"Windows Disk Cleanup failed for {drive.Name}: {exception.Message}");
                _workflowFailures.Add($"Windows Disk Cleanup failed for {drive.Name}: {exception.Message}");
            }
        }
    }

    private async void StorageCleanup_Click(object sender, RoutedEventArgs e)
    {
        await RunActionAsync("Storage Cleanup", async () =>
        {
            var scan = await ScanAndReportAsync();
            ShowScanSummary(scan);
            if (ConfirmTemporaryCleanup(scan))
            {
                var recovered = await Task.Run(() => _service.CleanFiles(scan));
                AddReport($"Temporary-file cleanup recovered approximately {MaintenanceService.FormatBytes(recovered)}.");
            }
            else if (scan.FileCount == 0)
            {
                WriteLog("No eligible temporary files were found.");
                SetStatus("No eligible temporary files were found.");
            }
            else
            {
                WriteLog("Temporary-file cleanup was not approved; no scanned files were removed.");
                SetStatus("Cleanup cancelled or no eligible files found.");
            }
            await OfferRecycleBinCleanupAsync();
        });
    }

    private async void DriveHealth_Click(object sender, RoutedEventArgs e)
    {
        if (!IsAdministrator())
        {
            RequestElevation(
                "--drive-health",
                "Windows requires administrator access to run the status-only CHKDSK check on local volumes. Winvexa will not run an automatic repair command.");
            return;
        }
        await RunActionAsync("Drive Health", RunDriveHealthAsync);
    }

    private async Task RunDriveHealthAsync()
    {
        var result = await CheckDriveHealthInBackgroundAsync();
        AddReport($"Drive health check: {result.Checked} NTFS volume(s) checked, {result.Issues} issue(s), " +
                  $"{result.Failed} check(s) failed, {result.Skipped} skipped, " +
                  $"{result.PhysicalDisksChecked} physical disk(s) inspected. " +
                  "See the activity log for per-drive details.");
        SetStatus(result.Issues == 0 && result.Failed == 0
            ? "Drive health check complete. No file-system or physical-disk issue was reported."
            : result.Issues > 0
                ? $"Drive health check found {result.Issues} issue(s). Review the activity log for details."
                : $"Drive health check could not complete {result.Failed} check(s). Review the activity log for details.");
    }

    private Task<DriveHealthSummary> CheckDriveHealthInBackgroundAsync() =>
        Task.Run(() => _service.CheckDriveHealthAsync());

    private void Defender_Click(object sender, RoutedEventArgs e)
    {
        if (!EnsureSupported() || _busy)
            return;

        OpenSecurityWindow();
    }

    private void OpenSecurityWindow(string? startupAction = null, string? startupTarget = null)
    {
        var window = new SecurityWindow(
            _service,
            WriteLog,
            IsAdministrator(),
            RequestElevation,
            startupAction,
            startupTarget)
        {
            Owner = this
        };
        _securityWindow = window;
        window.Closed += (_, _) =>
        {
            if (ReferenceEquals(_securityWindow, window))
                _securityWindow = null;
        };
        window.ShowDialog();
    }

    private async Task OpenSecurityWindowForElevatedActionAsync(string argument)
    {
        if (!IsAdministrator())
        {
            WriteLog($"Security operation '{argument}' was not started because the process is not elevated.");
            SetStatus("The security operation could not obtain administrator permission.");
            return;
        }

        var action = string.Empty;
        string? target = null;
        try
        {
            if (argument.Equals("--security-action-quick", StringComparison.OrdinalIgnoreCase))
                action = "quick";
            else if (argument.Equals("--security-action-full", StringComparison.OrdinalIgnoreCase))
                action = "full";
            else if (argument.Equals("--security-action-update", StringComparison.OrdinalIgnoreCase))
                action = "update";
            else if (argument.StartsWith("--security-action-custom:", StringComparison.OrdinalIgnoreCase))
            {
                action = "custom";
                var encodedTarget = argument["--security-action-custom:".Length..];
                target = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(encodedTarget));
                if (string.IsNullOrWhiteSpace(target) ||
                    !(File.Exists(target) || Directory.Exists(target)))
                    throw new InvalidOperationException("The selected scan target is no longer available.");
            }
            else
            {
                throw new InvalidOperationException($"Unsupported security action '{argument}'.");
            }
        }
        catch (Exception exception) when (exception is FormatException or InvalidOperationException)
        {
            WriteLog($"Elevated security action could not be started: {exception}");
            SetStatus("The requested security action could not be validated.");
            return;
        }

        OpenSecurityWindow(action, target);
        await Task.CompletedTask;
    }

    private Task RunDefenderScanAsync(bool fullScan) =>
        RunActionAsync("Microsoft Defender", async () =>
        {
            await _service.UpdateDefenderSignaturesAsync();
            var result = await _service.RunDefenderScanAsync(fullScan);
            AddReport($"{(fullScan ? "Full" : "Quick")} Scan: {result}");
        });

    private async void WindowsCleanup_Click(object sender, RoutedEventArgs e)
    {
        if (MessageBox.Show(
                this,
                "Open Microsoft's Windows Disk Cleanup for every accessible local drive? Each drive will show its own supported categories; you choose what to remove.",
                "Windows Cleanup",
                MessageBoxButton.YesNo,
                MessageBoxImage.Question) != MessageBoxResult.Yes)
            return;
        await RunActionAsync("Windows Cleanup", async () =>
        {
            await RunWindowsCleanupOnAllDrivesAsync();
        });
    }

    private async void WindowsUpdate_Click(object sender, RoutedEventArgs e)
    {
        await RunActionAsync("Windows Update", async () =>
        {
            await RunWindowsUpdateScanRepairWorkflowAsync();
        });
    }

    private async void WindowsUpdateLoop_Click(object sender, RoutedEventArgs e)
    {
        if (!EnsureSupported())
            return;
        if (!IsAdministrator())
        {
            RequestElevation(
                "--windows-update-loop-repair",
                "Diagnosing and repairing a Windows Update loop requires administrator access for supported Windows service, DISM, and SFC operations. Windows will show its standard UAC prompt.");
            return;
        }
        await RunActionAsync("Fix Windows Update Loop", RunWindowsUpdateLoopRepairWorkflowAsync);
    }

    private async void VerifyWindowsUpdate_Click(object sender, RoutedEventArgs e)
    {
        if (!EnsureSupported())
            return;
        if (!IsAdministrator())
        {
            RequestElevation(
                "--verify-windows-update",
                "Verifying Windows Update and running read-only Windows component checks requires administrator access. Windows will show its standard UAC prompt.");
            return;
        }
        await RunActionAsync("Verify Windows Update", VerifyWindowsUpdateLoopAsync);
    }

    private Task RunWindowsUpdateLoopRepairWorkflowAsync() => RunWindowsUpdateLoopRepairWorkflowAsync(null);

    private async Task RunWindowsUpdateLoopRepairWorkflowAsync(WindowsUpdateDiagnostics? suppliedDiagnostics)
    {
        if (!await EnsureVerifiedWindowsRepairSourceAsync())
            return;

        var repairStarted = DateTimeOffset.UtcNow;
        SetStatus("Diagnosing update services, history, pending updates, restart state, and system health...");
        SetProgress(5, "Windows Update loop diagnostics");
        var initial = suppliedDiagnostics ?? await _service.DiagnoseWindowsUpdateAsync();
        AddUpdateDiagnosticsToReport("Windows Update loop diagnostic", initial);
        var repeatedFailureTitles = GetRepeatedUpdateFailures(initial);
        var updatesPendingAtStart = initial.PendingUpdates.Select(update => update.Title).ToArray();
        if (repeatedFailureTitles.Length > 0)
        {
            AddReport($"Repeated or reoffered failed updates detected for {repeatedFailureTitles.Length} update(s): {string.Join("; ", repeatedFailureTitles)}.");
        }
        else
        {
            AddReport("No repeated failure for the same update was confirmed from the available 30-day update history.");
        }

        try
        {
            var savedState = new WindowsUpdateLoopVerificationState(
                repairStarted,
                repeatedFailureTitles,
                FindMatchingUpdateTitles(
                    initial.PendingUpdates.Select(update => update.Title),
                    repeatedFailureTitles));
            SaveWindowsUpdateLoopVerificationState(savedState);
            AddReport("Pre-repair update evidence was saved so Verify Windows Update can compare results after a restart.");
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            WriteLog($"Could not save Windows Update loop verification context: {exception}");
            AddReport($"Could not save post-restart verification context: {exception.Message}. The current repair can continue, but a later verification cannot compare against this diagnostic snapshot.");
        }

        var systemChecksNeedRepair = await RunWindowsSystemHealthChecksAsync("Pre-repair Windows system health");
        var cacheRepairIndicated = repeatedFailureTitles.Length > 0 ||
                                   (!initial.IsOperational && (initial.RecentFailures.Count > 0 || initial.RecentEventErrors.Count > 0));
        if (cacheRepairIndicated)
        {
            var answer = MessageBox.Show(
                this,
                "The diagnostics show repeated update failures or recent update errors. Winvexa can stop the required update services, move only the Windows Update Download cache to a timestamped backup, restart services that were running, and verify their state. The backup will be retained. Continue?",
                "Confirm Windows Update cache repair",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning);
            if (answer == MessageBoxResult.Yes)
            {
                if (!EnsureRepairElevation("--windows-update-loop-repair"))
                    return;
                SetStatus("Rebuilding the Windows Update Download cache and restarting required services...");
                SetProgress(30, "Repairing update cache");
                try
                {
                    var repair = await _service.RebuildWindowsUpdateDownloadCacheAsync();
                    AddReport(string.IsNullOrWhiteSpace(repair.BackupPath)
                        ? "Windows Update Download cache was not present; no cache files were changed."
                        : $"Windows Update Download cache moved to retained backup: {repair.BackupPath}.");
                    foreach (var service in repair.Services)
                        AddReport($"Post-repair service: {service}.");
                }
                catch (Exception exception) when (!_stopRequested || exception is not OperationCanceledException)
                {
                    WriteLog($"Windows Update loop cache repair failed: {exception}");
                    AddReport($"Windows Update cache repair failed: {exception.Message}");
                }
            }
            else
            {
                AddReport("Windows Update cache repair was declined; no cache files were changed.");
            }
        }
        else
        {
            AddReport("No repeated update failure or recent update error indicated a cache rebuild; the update cache was left unchanged.");
        }

        if (repeatedFailureTitles.Length > 0 || systemChecksNeedRepair)
        {
            var answer = MessageBox.Show(
                this,
                "The diagnostics indicate repeated update failures or possible Windows system/component corruption. Winvexa can run Microsoft's DISM RestoreHealth followed by System File Checker (SFC /scannow). These system-wide repairs can take a long time. Continue?",
                "Confirm Windows system repair",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning);
            if (answer == MessageBoxResult.Yes)
            {
                if (!EnsureRepairElevation("--windows-update-loop-repair"))
                    return;
                SetStatus("Running Microsoft's DISM component-store repair...");
                SetProgress(45, "DISM RestoreHealth");
                var dismFailed = await RunWindowsSystemRepairAsync("DISM RestoreHealth", _service.RunDismRestoreHealthAsync);
                var sfcFailed = false;
                if (dismFailed)
                {
                    AddReport("SFC /scannow was not started because DISM repair or repair-source verification did not succeed.");
                }
                else
                {
                    SetStatus("Running Microsoft's System File Checker...");
                    SetProgress(60, "SFC /scannow");
                    sfcFailed = await RunWindowsSystemRepairAsync("System File Checker /scannow", _service.RunSystemFileCheckerAsync);
                }
                systemChecksNeedRepair = await RunWindowsSystemHealthChecksAsync("Post-repair Windows system health");
                systemChecksNeedRepair |= dismFailed || sfcFailed;
            }
            else
            {
                AddReport("DISM RestoreHealth and SFC /scannow were declined; no Windows system files were repaired.");
            }
        }

        SetStatus("Checking Windows Update again and offering installation only with confirmation...");
        SetProgress(72, "Windows Update rescan and repair");
        try
        {
            await RunWindowsUpdateScanRepairWorkflowAsync();
        }
        catch (Exception exception) when (!_stopRequested || exception is not OperationCanceledException)
        {
            WriteLog($"Windows Update loop follow-up repair/check failed: {exception}");
            AddReport($"Windows Update follow-up check or repair failed: {exception.Message}");
        }

        SetStatus("Performing final Windows Update loop verification...");
        SetProgress(90, "Final loop verification");
        var final = await _service.DiagnoseWindowsUpdateAsync();
        AddUpdateDiagnosticsToReport("Final Windows Update loop verification", final);
        var stillPending = FindMatchingUpdateTitles(final.PendingUpdates.Select(update => update.Title), repeatedFailureTitles);
        var newFailures = FindFailuresAfter(final, repeatedFailureTitles.Concat(updatesPendingAtStart), repairStarted);
        if (final.RestartRequired)
        {
            const string message = "WINDOWS UPDATE REPAIR REQUIRES A RESTART. Winvexa completed the available repairs; run Verify Windows Update after restarting. No restart was forced.";
            AddReport(message);
            WriteLog(message);
            SetStatus("Windows Update repair requires a restart. No restart was forced.");
            OfferConfirmedRestart();
            return;
        }

        if (!final.IsOperational || stillPending.Length > 0 || newFailures.Length > 0 || systemChecksNeedRepair)
        {
            var details = !final.IsOperational
                ? FormatWindowsUpdateError(final)
                : stillPending.Length > 0
                    ? $"The same update(s) remain applicable: {string.Join("; ", stillPending)}."
                    : newFailures.Length > 0
                        ? $"A repeated update failure was recorded again: {string.Join("; ", newFailures)}."
                        : "The read-only component/system checks indicated a possible issue that was not confirmed repaired.";
            var message = $"WINDOWS UPDATE LOOP NOT COMPLETELY RESOLVED. {details} Review the repair report and activity log.";
            AddReport(message);
            WriteLog(message);
            _workflowFailures.Add(message);
            SetStatus("Windows Update loop was not completely resolved. Review the final report and activity log.");
            return;
        }

        var success = repeatedFailureTitles.Length == 0
            ? "No repeated Windows Update loop was confirmed. Windows Update is functioning and the final scan succeeded."
            : "WINDOWS UPDATE LOOP REPAIRED. Windows Update is functioning, the final scan succeeded, and no repeated update failure is currently detected. Windows Update appears to be operating normally.";
        AddReport(success);
        WriteLog(success);
        SetStatus(repeatedFailureTitles.Length == 0
            ? "No repeated loop was detected; Windows Update scan and services are operational."
            : "Windows Update loop repair verified. Windows Update appears to be operating normally.");
    }

    private async Task VerifyWindowsUpdateLoopAsync()
    {
        SetStatus("Checking Windows Update services, pending updates, update history, restart state, and system health...");
        SetProgress(10, "Windows Update verification");
        var state = LoadWindowsUpdateLoopVerificationState();
        var diagnostics = await _service.DiagnoseWindowsUpdateAsync();
        AddUpdateDiagnosticsToReport("Windows Update verification", diagnostics);
        var systemChecksNeedRepair = await RunWindowsSystemHealthChecksAsync("Post-restart Windows system health");

        if (state is null)
        {
            const string noContext = "No saved Windows Update loop repair snapshot was found. This is a current health check only; Winvexa cannot determine whether a previous repeated-update problem was resolved.";
            AddReport(noContext);
            WriteLog(noContext);
            SetStatus(diagnostics.IsOperational && !diagnostics.RestartRequired && !systemChecksNeedRepair
                ? "Windows Update scan is operational; no previous loop repair snapshot is available."
                : "Windows Update verification found an issue. Review the final report.");
            return;
        }

        var stillPending = FindMatchingUpdateTitles(
            diagnostics.PendingUpdates.Select(update => update.Title),
            state.RepeatedFailureTitles.Concat(state.PendingUpdateTitles).Distinct(StringComparer.OrdinalIgnoreCase).ToArray());
        var newFailures = FindFailuresAfter(diagnostics, state.RepeatedFailureTitles, state.RepairStartedUtc);
        if (diagnostics.RestartRequired)
        {
            const string restart = "Windows Update still reports that a restart is required. Verify again after Windows restarts.";
            AddReport(restart);
            SetStatus(restart);
        }
        else if (!diagnostics.IsOperational || stillPending.Length > 0 || newFailures.Length > 0 || systemChecksNeedRepair)
        {
            var details = !diagnostics.IsOperational
                ? FormatWindowsUpdateError(diagnostics)
                : stillPending.Length > 0
                    ? $"The same update(s) remain applicable: {string.Join("; ", stillPending)}."
                    : newFailures.Length > 0
                        ? $"A new failure for the previously affected update was recorded: {string.Join("; ", newFailures)}."
                        : "The read-only component/system checks indicate a possible issue.";
            var message = $"WINDOWS UPDATE LOOP NOT COMPLETELY RESOLVED. {details}";
            AddReport(message);
            WriteLog(message);
            SetStatus("Windows Update loop verification found an unresolved problem. Review the report.");
        }
        else
        {
            const string success = "WINDOWS UPDATE LOOP REPAIRED. Windows Update is functioning, no restart is pending, and the previously affected update is no longer being offered or failing again.";
            AddReport(success);
            WriteLog(success);
            SetStatus("Windows Update loop verification succeeded. Windows Update appears to be operating normally.");
            try
            {
                DeleteWindowsUpdateLoopVerificationState();
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or System.Security.SecurityException)
            {
                WriteLog($"Could not remove the completed Windows Update verification context: {exception}");
                AddReport($"Verification succeeded, but the saved comparison context could not be removed: {exception.Message}. A later verification may refer to this completed repair.");
            }
        }
    }

    private async Task<bool> RunWindowsSystemHealthChecksAsync(string heading)
    {
        var needsRepair = false;
        foreach (var check in new[]
                 {
                     ("DISM ScanHealth", (Func<Task<WindowsSystemRepairResult>>)_service.RunDismScanHealthAsync),
                     ("System File Checker VerifyOnly", (Func<Task<WindowsSystemRepairResult>>)_service.RunSystemFileVerificationAsync)
                 })
        {
            SetStatus($"{heading}: running {check.Item1}...");
            try
            {
                var result = await check.Item2();
                AddReport($"{heading} — {check.Item1} exit code: {result.ExitCode}.");
                if (!string.IsNullOrWhiteSpace(result.Output))
                    AddReport($"{check.Item1} result: {result.Output.Trim()}");
                if (!string.IsNullOrWhiteSpace(result.Error))
                    AddReport($"{check.Item1} diagnostic: {result.Error.Trim()}");
                needsRepair |= result.ExitCode != 0 ||
                               SystemCheckOutputIndicatesRepair(result.Output) ||
                               SystemCheckOutputIndicatesRepair(result.Error);
            }
            catch (Exception exception) when (!_stopRequested || exception is not OperationCanceledException)
            {
                WriteLog($"{heading} — {check.Item1} failed: {exception}");
                AddReport($"{heading} — {check.Item1} could not complete: {exception.Message}");
                needsRepair = true;
            }
        }
        return needsRepair;
    }

    private async Task<bool> RunWindowsSystemRepairAsync(
        string name,
        Func<Task<WindowsSystemRepairResult>> operation)
    {
        try
        {
            if (!await EnsureVerifiedWindowsRepairSourceAsync())
            {
                var skipped = $"{name} was not started because no verified, compatible Microsoft Windows repair source is available.";
                AddReport(skipped);
                WriteLog(skipped);
                return true;
            }

            OperationCancellationContext.ThrowIfCancellationRequested();
            var result = await operation();
            AddReport($"{name} exit code: {result.ExitCode}.");
            if (!string.IsNullOrWhiteSpace(result.Output))
                AddReport($"{name} output: {result.Output.Trim()}");
            if (!string.IsNullOrWhiteSpace(result.Error))
                AddReport($"{name} diagnostic: {result.Error.Trim()}");
            return result.ExitCode != 0;
        }
        catch (Exception exception) when (!_stopRequested || exception is not OperationCanceledException)
        {
            WriteLog($"{name} failed: {exception}");
            AddReport($"{name} failed: {exception.Message}");
            return true;
        }
    }

    private async Task<bool> EnsureVerifiedWindowsRepairSourceAsync()
    {
        if (_windowsRepairSourceChecked)
        {
            if (!_windowsRepairSourceVerified)
                WriteLog($"Windows repair remains blocked by the earlier source-verification failure: {_windowsRepairSourceFailure}");
            return _windowsRepairSourceVerified;
        }

        _windowsRepairSourceChecked = true;
        try
        {
            OperationCancellationContext.ThrowIfCancellationRequested();
            SetStatus("Checking Windows installation...");
            SetProgress(70, "Checking Windows");
            WriteLog("Windows repair source preflight: detecting the installed Windows edition, architecture, release, build, servicing revision, and repair-source policy.");
            var installation = _service.GetWindowsInstallationInfo();
            var targetDetails =
                $"Windows 11 {installation.Edition}; {installation.Architecture}; version {installation.Version}; build {installation.Build}; servicing build {installation.ServicingBuild}.";
            AddReport($"Repair target: {targetDetails}");
            WriteLog($"Repair target: {targetDetails}");

            if (installation.RepairSourcePolicyOverridesWindowsUpdate)
            {
                throw new InvalidOperationException(
                    $"{installation.ConfiguredRepairSource} is configured to override the Microsoft Windows Update repair source. Winvexa will not change Windows servicing policy or use an unverified repair source. Ask your administrator to configure Windows Update as the repair-content source, then try again.");
            }

            SetStatus("Checking the official Microsoft Windows Update source...");
            SetProgress(72, "Checking Microsoft source");
            var microsoftSource = await _service.CheckMicrosoftWindowsUpdateSourceAsync();
            AddReport($"Microsoft repair-source check: {microsoftSource.Details}");
            WriteLog($"Microsoft repair-source check succeeded. Applicable software updates: {microsoftSource.ApplicableUpdateCount}.");

            OperationCancellationContext.ThrowIfCancellationRequested();
            SetStatus("Verifying the compatible Windows repair source...");
            SetProgress(74, "Verifying repair source");
            var verification = await _service.VerifyWindowsRepairSourceAsync(installation);
            AddReport($"Verified repair source: {verification.Details}");

            SetStatus("Preparing the Microsoft Windows Update repair source...");
            SetProgress(76, "Preparing repair source");
            AddReport("Windows servicing will obtain only applicable, Microsoft-authenticated repair payloads through its configured Windows Update source if DISM requires them. No Windows feature upgrade or complete Windows installation image will be downloaded.");
            WriteLog($"Windows repair source is verified and compatible. {verification.Details}");
            _windowsRepairSourceVerified = true;
            return true;
        }
        catch (OperationCanceledException) when (OperationCancellationContext.IsCancellationRequested)
        {
            WriteLog("Windows repair-source verification was canceled. No DISM RestoreHealth or SFC /scannow operation was started.");
            throw;
        }
        catch (Exception exception) when (!_stopRequested || exception is not OperationCanceledException)
        {
            _operationFailed = true;
            _windowsRepairSourceFailure = exception.Message;
            WriteLog($"Windows repair-source verification failed; system repair is blocked. {exception}");
            var message =
                $"Winvexa could not verify a compatible Microsoft Windows repair source, so it stopped before changing Windows.{Environment.NewLine}{Environment.NewLine}{exception.Message}{Environment.NewLine}{Environment.NewLine}" +
                "Connect to Windows Update and retry. If this PC is managed, ask your administrator to configure Microsoft Windows Update as the repair-content source. Winvexa does not have a separate verified offline Windows image to use.";
            AddReport("Windows repair was not started because source verification did not complete successfully.");
            AddReport($"Source verification details: {exception.Message}");
            SetStatus("Windows repair stopped: a compatible repair source could not be verified.");
            MessageBox.Show(this, message, "Windows repair source unavailable",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return false;
        }
    }

    private static bool SystemCheckOutputIndicatesRepair(string output)
    {
        var indicators = new[] { "component store is repairable", "found integrity violations", "found corrupt files", "unable to fix", "corruption was found" };
        return output.Split(["\r\n", "\n"], StringSplitOptions.RemoveEmptyEntries)
            .Any(line =>
                !line.TrimStart().StartsWith("No ", StringComparison.OrdinalIgnoreCase) &&
                indicators.Any(indicator => line.Contains(indicator, StringComparison.OrdinalIgnoreCase)));
    }

    private static string[] GetRepeatedUpdateFailures(WindowsUpdateDiagnostics diagnostics)
    {
        var repeated = diagnostics.RecentFailures
            .Where(failure => !string.IsNullOrWhiteSpace(failure.Title))
            .GroupBy(failure => failure.Title.Trim(), StringComparer.OrdinalIgnoreCase)
            .Where(group => group.Count() >= 2)
            .Select(group => group.Key)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var pendingAfterFailure = FindMatchingUpdateTitles(
            diagnostics.PendingUpdates.Select(update => update.Title),
            diagnostics.RecentFailures.Select(failure => failure.Title));
        repeated.UnionWith(pendingAfterFailure);
        return repeated.ToArray();
    }

    private static string[] FindMatchingUpdateTitles(IEnumerable<string> candidates, IEnumerable<string> targets)
    {
        var targetSet = targets.Where(title => !string.IsNullOrWhiteSpace(title))
            .Select(title => title.Trim())
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        return candidates.Where(title => targetSet.Contains(title.Trim()))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private static string[] FindFailuresAfter(
        WindowsUpdateDiagnostics diagnostics,
        IEnumerable<string> targetTitles,
        DateTimeOffset timestamp)
    {
        var targets = targetTitles.Where(title => !string.IsNullOrWhiteSpace(title))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        return diagnostics.RecentFailures
            .Where(failure =>
                targets.Contains(failure.Title.Trim()) &&
                DateTimeOffset.TryParse(failure.Date, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var failedAt) &&
                failedAt > timestamp)
            .Select(failure => failure.Title)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private static string WindowsUpdateLoopVerificationPath()
    {
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (string.IsNullOrWhiteSpace(appData))
            throw new IOException("The current user's local application data directory is unavailable.");
        return Path.Combine(appData, "Winvexa", "WindowsUpdateLoopVerification.json");
    }

    private void SaveWindowsUpdateLoopVerificationState(WindowsUpdateLoopVerificationState state)
    {
        var path = WindowsUpdateLoopVerificationPath();
        var directory = Path.GetDirectoryName(path)
            ?? throw new IOException("Could not determine the Windows Update verification data directory.");
        Directory.CreateDirectory(directory);
        var temporaryPath = path + ".tmp";
        File.WriteAllText(temporaryPath, JsonSerializer.Serialize(state, VerificationJsonOptions));
        File.Move(temporaryPath, path, overwrite: true);
        WriteLog($"Saved Windows Update loop verification context to '{path}'.");
    }

    private WindowsUpdateLoopVerificationState? LoadWindowsUpdateLoopVerificationState()
    {
        var path = WindowsUpdateLoopVerificationPath();
        if (!File.Exists(path))
            return null;
        try
        {
            return JsonSerializer.Deserialize<WindowsUpdateLoopVerificationState>(File.ReadAllText(path));
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException($"Saved Windows Update verification context is invalid: {exception.Message}", exception);
        }
    }

    private void DeleteWindowsUpdateLoopVerificationState()
    {
        var path = WindowsUpdateLoopVerificationPath();
        if (File.Exists(path))
            File.Delete(path);
    }

    private void OfferConfirmedRestart()
    {
        if (MessageBox.Show(
                this,
                "Windows Update repair requires a restart. Winvexa has completed the available repairs. Restart now? You can also choose Restart Later and use Verify Windows Update after restarting.",
                "Windows Update repair requires a restart",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning) != MessageBoxResult.Yes)
        {
            AddReport("Restart Later was selected. Winvexa will not restart the computer.");
            return;
        }

        var shutdown = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "shutdown.exe");
        try
        {
            using var process = Process.Start(new ProcessStartInfo(shutdown)
            {
                UseShellExecute = true,
                ArgumentList = { "/r", "/t", "0", "/c", "Restart requested by the user after Winvexa Windows Update repair." }
            }) ?? throw new InvalidOperationException("Windows did not start the restart request.");
            const string message = "Windows restart was requested after the user selected Restart Now.";
            AddReport(message);
            WriteLog(message);
        }
        catch (Exception exception) when (exception is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            AddReport($"Windows restart could not be started: {exception.Message}. Use Start > Power > Restart when convenient.");
            WriteLog($"Confirmed Windows restart request failed: {exception}");
        }
    }

    private void Optimization_Click(object sender, RoutedEventArgs e)
    {
        if (!EnsureSupported() || _busy)
            return;
        var window = new OptimizationWindow(_service, WriteLog) { Owner = this };
        window.ShowDialog();
    }

    private void About_Click(object sender, RoutedEventArgs e)
    {
        var about = new AboutWindow { Owner = this };
        about.ShowDialog();
    }

    private async Task RunActionAsync(string name, Func<Task> action)
    {
        if (!EnsureSupported() || _busy)
            return;

        var operationStopped = false;
        using var cancellation = new CancellationTokenSource();
        _operationCancellation = cancellation;
        _service.ResetWindowsRepairSourceVerification();
        _busy = true;
        _operationFailed = false;
        _stopRequested = false;
        _operationStopwatch.Restart();
        SetControlsEnabled(false);
        StopButton.Content = "Stop";
        StopButton.IsEnabled = true;
        StopButton.Visibility = Visibility.Visible;
        _report.Clear();
        ReportText.Clear();
        SetProgress(0, name);
        SetStatus($"{name} in progress...");
        _operationHeartbeat.Start();
        WriteLog($"=== {name} started ===");
        try
        {
            using (OperationCancellationContext.Enter(cancellation.Token))
            {
                _windowsRepairSourceChecked = false;
                _windowsRepairSourceVerified = false;
                _windowsRepairSourceFailure = string.Empty;
                await action();
                OperationCancellationContext.ThrowIfCancellationRequested();
            }
        }
        catch (OperationCanceledException) when (_stopRequested)
        {
            operationStopped = true;
            AddReport($"Operation Stopped. {name} was canceled; no further workflow stages were started. Any protected Windows operation already in progress was allowed to finish normally.");
            SetStatus("Operation Stopped", allowStopRequested: true);
            OperationProgress.IsIndeterminate = false;
            OperationProgress.Value = 0;
            ProgressText.Text = "Operation Stopped";
            WriteLog($"=== Operation Stopped: {name}. Active cancellable child processes were stopped; protected Windows operations were allowed to finish normally. ===");
        }
        catch (Exception exception) when (!_stopRequested || exception is not OperationCanceledException)
        {
            _operationFailed = true;
            WriteLog($"{name} failed: {exception}");
            var userMessage = GetUserFacingFailure(name);
            AddReport($"{userMessage} Details are recorded in the activity log.");
            SetStatus(userMessage);
            if (MessageBox.Show(
                    this,
                    $"{userMessage}{Environment.NewLine}{Environment.NewLine}The technical details are recorded in the activity log. View the technical details now?",
                    "Operation could not be completed",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Error) == MessageBoxResult.Yes)
            {
                MessageBox.Show(this, exception.ToString(), "Technical details",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        finally
        {
            _operationHeartbeat.Stop();
            _operationStopwatch.Stop();
            ReportText.Text = string.Join(Environment.NewLine + Environment.NewLine, _report);
            _busy = false;
            _operationCancellation = null;
            _service.ResetWindowsRepairSourceVerification();
            _windowsRepairSourceChecked = false;
            _windowsRepairSourceVerified = false;
            _windowsRepairSourceFailure = string.Empty;
            StopButton.Visibility = Visibility.Collapsed;
            StopButton.IsEnabled = false;
            _stopRequested = false;
            SetControlsEnabled(true);
            if (!operationStopped && OperationProgress.Value < 100)
                SetProgress(100, _operationFailed ? "Failed" : "Complete");
            WriteLog(operationStopped ? $"=== {name} stopped ===" : $"=== {name} finished ===");
        }
    }

    private void Stop_Click(object sender, RoutedEventArgs e)
    {
        if (!_busy || _stopRequested || _operationCancellation is null)
            return;

        _stopRequested = true;
        _operationCancellation.Cancel();
        StopButton.Content = "Stopping...";
        StopButton.IsEnabled = false;
        var current = string.IsNullOrWhiteSpace(_operationStatus) ? "The operation" : _operationStatus;
        var message = $"{current} — stop requested. Cancellable work and safe-to-stop child processes are stopping. DISM/SFC repair, Defender scans, Windows Update searches/installation, restore-point creation, Recycle Bin emptying, or drive optimization may need to finish before Winvexa returns to idle; no later stage will start.";
        StatusText.Text = message;
        WriteLog($"Cancellation requested by the user during '{current}'. Cancellable tasks and safe-to-stop Winvexa child processes will be canceled; protected Windows operations will finish their current safe step.");
    }

    private async Task RunWorkflowStageAsync(
        string name,
        Func<Task> operation,
        int step,
        int total,
        bool failureIsCritical = true)
    {
        SetStatus(name + "...");
        SetProgress((step - 1) * 100 / total, name);
        WriteLog($"Starting: {name}");
        try
        {
            await operation();
            AddReport($"{name}: completed.");
        }
        catch (OperationCanceledException) when (OperationCancellationContext.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (!_stopRequested || exception is not OperationCanceledException)
        {
            WriteLog($"{name} failed: {exception}");
            AddReport($"{name}: failed — {exception.Message}");
            if (failureIsCritical)
                _workflowFailures.Add($"{name}: {exception.Message}");
        }
        finally
        {
            SetProgress(step * 100 / total, name);
        }
    }

    private void OpenLog_Click(object sender, RoutedEventArgs e)
    {
        var history = new RepairHistoryWindow(Path.GetDirectoryName(_logPath) ?? Path.GetTempPath())
        {
            Owner = this
        };
        history.ShowDialog();
    }

    private void SaveReport_Click(object sender, RoutedEventArgs e)
    {
        var report = string.Join(Environment.NewLine + Environment.NewLine, _report);
        if (string.IsNullOrWhiteSpace(report))
        {
            MessageBox.Show(this, "There is no repair report to save yet.", "No report available",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var dialog = new Microsoft.Win32.SaveFileDialog
        {
            Title = "Save Winvexa repair report",
            FileName = $"Winvexa-Repair-Report-{DateTime.Now:yyyyMMdd-HHmmss}.txt",
            DefaultExt = ".txt",
            Filter = "Text report (*.txt)|*.txt|All files (*.*)|*.*",
            AddExtension = true,
            OverwritePrompt = true
        };
        if (dialog.ShowDialog(this) != true)
            return;

        try
        {
            File.WriteAllText(dialog.FileName, report);
            WriteLog($"Repair report saved to '{dialog.FileName}'.");
            MessageBox.Show(this, $"Repair report saved to:{Environment.NewLine}{dialog.FileName}",
                "Report saved", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            WriteLog($"Could not save the repair report to '{dialog.FileName}': {exception}");
            MessageBox.Show(this, $"Could not save the repair report:{Environment.NewLine}{exception.Message}",
                "Save report failed", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void Settings_Click(object sender, RoutedEventArgs e)
        => ShowSettingsDialog();

    internal void ShowSettingsDialog()
    {
        WriteLog("Opening application settings.");
        var settings = new SettingsWindow(_logPath, IsAdministrator(), GetWindowsVersion())
        {
            Owner = this
        };
        settings.ShowDialog();
        WriteLog("Application settings window closed.");
    }

    private void Exit_Click(object sender, RoutedEventArgs e) => Close();

    private void MainWindow_Closing(object? sender, CancelEventArgs e)
    {
        if (!_busy)
            return;

        e.Cancel = true;
        SetStatus($"{_operationStatus} is still running. Wait for the operation to finish before closing Winvexa.");
        WriteLog("Window close was deferred because a maintenance operation is still running.");
    }

    private void WriteLog(string message)
    {
        var line = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff zzz}] {message}";
        _securityWindow?.AppendLog(line);
        try
        {
            File.AppendAllText(_logPath, line + Environment.NewLine);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            if (!_logFailureNotified)
            {
                _logFailureNotified = true;
                var errorLine = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff zzz}] ERROR: Cannot write the persistent session log: {exception.Message}";
                if (!Dispatcher.CheckAccess())
                    Dispatcher.BeginInvoke(new Action(() => AppendLogLine(errorLine)));
                else
                    AppendLogLine(errorLine);
                if (Dispatcher.CheckAccess())
                    SetStatus("The log file is unavailable; details remain in the on-screen activity log.");
            }
        }

        if (!Dispatcher.CheckAccess())
        {
            Dispatcher.InvokeAsync(() => AppendLogLine(line));
            return;
        }
        AppendLogLine(line);
    }

    private void AppendLogLine(string line)
    {
        LogText.AppendText(line + Environment.NewLine);
        LogText.ScrollToEnd();
    }

    private void AddReport(string line)
    {
        _report.Add(line);
        ReportText.Text = string.Join(Environment.NewLine + Environment.NewLine, _report);
    }

    private static string GetUserFacingFailure(string operation)
    {
        if (operation.Contains("Windows Update", StringComparison.OrdinalIgnoreCase))
            return "Windows Update operation could not be completed.";
        if (operation.Contains("Defender", StringComparison.OrdinalIgnoreCase))
            return "Microsoft Defender operation could not be completed.";
        if (operation.Contains("Drive", StringComparison.OrdinalIgnoreCase))
            return "Drive health check could not be completed.";
        if (operation.Contains("Cleanup", StringComparison.OrdinalIgnoreCase))
            return "Cleanup could not be completed.";
        if (operation.Contains("Repair", StringComparison.OrdinalIgnoreCase) ||
            operation.Contains("Fix My PC", StringComparison.OrdinalIgnoreCase))
            return "Repair could not be completed.";
        return $"{operation} could not be completed.";
    }

    private void SetStatus(string message, bool allowStopRequested = false)
    {
        if (_busy && _stopRequested && !allowStopRequested)
        {
            StatusText.Text =
                $"Stop requested. Cancellable work is stopping; protected Windows operations may need to finish before Winvexa returns to idle. {_operationStatus}";
            return;
        }
        _operationStatus = message;
        StatusText.Text = message;
        var indicator = (System.Windows.Media.Brush)(message.Contains("fail", StringComparison.OrdinalIgnoreCase) ||
                                                       message.Contains("could not", StringComparison.OrdinalIgnoreCase) ||
                                                       message.Contains("not resolved", StringComparison.OrdinalIgnoreCase)
            ? FindResource("StatusErrorBrush")
            : message.Contains("restart", StringComparison.OrdinalIgnoreCase) ||
              message.Contains("problem found", StringComparison.OrdinalIgnoreCase) ||
              message.Contains("incomplete", StringComparison.OrdinalIgnoreCase)
                ? FindResource("StatusWarningBrush")
                : message.Contains("complete", StringComparison.OrdinalIgnoreCase) ||
                  message.Contains("healthy", StringComparison.OrdinalIgnoreCase) ||
                  message.Contains("no repair was identified", StringComparison.OrdinalIgnoreCase)
                    ? FindResource("StatusSuccessBrush")
                    : message.Contains("checking", StringComparison.OrdinalIgnoreCase) ||
                      message.Contains("repairing", StringComparison.OrdinalIgnoreCase) ||
                      message.Contains("verifying", StringComparison.OrdinalIgnoreCase)
                        ? FindResource("StatusActiveBrush")
                        : FindResource("StatusNeutralBrush"));
        StatusIndicator.Fill = indicator;
    }

    private void SetProgress(int value, string message, bool allowCancellation = false)
    {
        if (_busy && _stopRequested && !allowCancellation)
            OperationCancellationContext.ThrowIfCancellationRequested();
        var complete = value >= 100;
        OperationProgress.IsIndeterminate = !complete;
        OperationProgress.Value = complete ? 100 : 0;
        ProgressText.Text = complete ? message : $"In progress  •  {message}";
    }

    private void SetControlsEnabled(bool enabled)
    {
        FixMyPcButton.IsEnabled = enabled && _supportedWindows;
        ScanWindowsButton.IsEnabled = enabled && _supportedWindows;
        SystemHealthButton.IsEnabled = enabled && _supportedWindows;
        ScanButton.IsEnabled = enabled && _supportedWindows;
        RepairButton.IsEnabled = enabled && _supportedWindows;
        UpdateButton.IsEnabled = enabled && _supportedWindows;
        UpdateLoopButton.IsEnabled = enabled && _supportedWindows;
        VerifyUpdateButton.IsEnabled = enabled && _supportedWindows;
        StorageCleanupButton.IsEnabled = enabled && _supportedWindows;
        DriveHealthButton.IsEnabled = enabled && _supportedWindows;
        DefenderButton.IsEnabled = enabled && _supportedWindows;
        WindowsCleanupButton.IsEnabled = enabled && _supportedWindows;
        OptimizationButton.IsEnabled = enabled && _supportedWindows;
        ExitButton.IsEnabled = !_busy;
        StopButton.Visibility = _busy ? Visibility.Visible : Visibility.Collapsed;
        StopButton.IsEnabled = _busy && !_stopRequested;
    }

    private bool EnsureSupported()
    {
        if (_supportedWindows)
            return true;
        MessageBox.Show(this, "This utility supports Windows 11 (build 22000 or later).",
            "Unsupported Windows version", MessageBoxButton.OK, MessageBoxImage.Warning);
        return false;
    }

    private bool RequestElevation(string workflowArgument, string explanation)
    {
        var answer = MessageBox.Show(
            this,
            explanation + Environment.NewLine + Environment.NewLine + "Continue to the standard Windows UAC prompt?",
            "Administrator access required",
            MessageBoxButton.YesNo,
            MessageBoxImage.Information);
        if (answer != MessageBoxResult.Yes)
        {
            WriteLog($"Administrator access declined for {workflowArgument}.");
            SetStatus("Administrator access was declined. No elevated operation was run.");
            return false;
        }

        try
        {
            var processPath = Environment.ProcessPath
                ?? throw new InvalidOperationException("Windows did not provide the application path needed for UAC elevation.");
            var start = new ProcessStartInfo(processPath)
            {
                UseShellExecute = true,
                Verb = "runas"
            };
            if (string.Equals(Path.GetFileNameWithoutExtension(processPath), "dotnet", StringComparison.OrdinalIgnoreCase))
            {
                var assemblyPath = Assembly.GetEntryAssembly()?.Location;
                if (string.IsNullOrWhiteSpace(assemblyPath))
                    throw new InvalidOperationException("Could not locate the application assembly for elevation.");
                start.ArgumentList.Add(assemblyPath);
            }
            start.ArgumentList.Add("--gui");
            start.ArgumentList.Add(workflowArgument);
            if (Process.Start(start) is null)
                throw new InvalidOperationException("Windows did not start the elevated application.");
            WriteLog($"Started elevated workflow {workflowArgument} through the Windows UAC prompt.");
            Close();
            return true;
        }
        catch (System.ComponentModel.Win32Exception exception) when (exception.NativeErrorCode == 1223)
        {
            WriteLog("UAC elevation was cancelled by the user. No elevated operation was run.");
            SetStatus("Administrator access was cancelled. Nothing was changed.");
        }
        catch (Exception exception) when (!_stopRequested || exception is not OperationCanceledException)
        {
            WriteLog($"Could not start the elevated process: {exception}");
            SetStatus($"Could not request administrator access: {exception.Message}");
            MessageBox.Show(this, exception.Message, "Could not start elevated operation", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        return false;
    }

    private static IEnumerable<T> FindVisualChildren<T>(DependencyObject parent) where T : DependencyObject
    {
        for (var i = 0; i < System.Windows.Media.VisualTreeHelper.GetChildrenCount(parent); i++)
        {
            var child = System.Windows.Media.VisualTreeHelper.GetChild(parent, i);
            if (child is T match)
                yield return match;
            foreach (var descendant in FindVisualChildren<T>(child))
                yield return descendant;
        }
    }

    private static bool IsAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    private static string GetWindowsVersion()
    {
        var version = Environment.OSVersion.Version;
        var name = OperatingSystem.IsWindowsVersionAtLeast(10, 0, 22000) ? "Windows 11" : "Windows";
        return $"{name} (build {version.Build})";
    }
}
