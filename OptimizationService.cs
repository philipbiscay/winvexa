using Microsoft.Win32;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Text;
using System.Text.Json;

namespace Winvexa;

internal enum OptimizationActionKind
{
    RegistryValue,
    StartupFile,
    DriveOptimization,
    OpenSettings
}

internal sealed record OptimizationRecommendation(
    string Id,
    string Category,
    string Name,
    string Publisher,
    string CurrentSetting,
    string ProposedSetting,
    string Description,
    OptimizationActionKind ActionKind,
    bool Selectable,
    string? RegistryPath = null,
    string? RegistryValueName = null,
    string? RegistryValue = null,
    string? StartupPath = null,
    string? DriveLetter = null,
    string? SettingsUri = null,
    bool RequiresRestorePoint = false);

internal sealed record OptimizationScan(IReadOnlyList<OptimizationRecommendation> Recommendations)
{
    public int ActionableCount => Recommendations.Count(item => item.Selectable && item.ActionKind != OptimizationActionKind.OpenSettings);
}

internal sealed record OptimizationChange(
    OptimizationActionKind ActionKind,
    string Description,
    string? RegistryPath,
    string? RegistryValueName,
    bool PreviousValueExists,
    string? PreviousValue,
    string? PreviousValueKind,
    string? OriginalPath,
    string? DisabledPath,
    bool Undoable,
    bool PreviousKeyExists = true);

internal sealed record OptimizationTransaction(
    string Id,
    DateTime CreatedAt,
    bool Undone,
    IReadOnlyList<OptimizationChange> Changes);

internal sealed class OptimizationService(Action<string> log)
{
    private const string StartupRegistryPath = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string StartupFolderCategory = "Startup Apps";
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };
    private readonly string _historyPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Winvexa",
        "Optimizations",
        "history.json");

    public async Task<OptimizationScan> ScanAsync(Action<string>? status = null)
    {
        OperationCancellationContext.ThrowIfCancellationRequested();
        var recommendations = new List<OptimizationRecommendation>();
        SetScanStage("Scanning startup applications", status);
        ScanStartup(recommendations);
        SetScanStage("Scanning background app permissions", status);
        ScanBackgroundApps(recommendations);
        SetScanStage("Checking visual effects", status);
        ScanVisualEffects(recommendations);
        SetScanStage("Scanning app notification settings", status);
        ScanNotifications(recommendations);
        SetScanStage("Checking Windows suggestions", status);
        ScanSuggestions(recommendations);
        SetScanStage("Checking privacy and personalization settings", status);
        ScanPrivacy(recommendations);
        SetScanStage("Inventorying installed applications (use data is not inferred)", status);
        ScanUnusedApplications(recommendations);
        SetScanStage("Checking computer type and power mode", status);
        await ScanPowerModeAsync(recommendations);
        SetScanStage("Detecting fixed-drive media types", status);
        await ScanDrivesAsync(recommendations);
        SetScanStage("Reviewing gaming and graphics settings", status);
        ScanGaming(recommendations);
        OperationCancellationContext.ThrowIfCancellationRequested();

        log($"Windows 11 Optimization scan completed. {recommendations.Count(item => item.Selectable)} selectable recommendation(s) found across 10 categories.");
        foreach (var item in recommendations)
        {
            OperationCancellationContext.ThrowIfCancellationRequested();
            log($"Optimization scan [{item.Category}] {item.Name}: {item.CurrentSetting} -> {item.ProposedSetting}. {item.Description}");
        }
        return new OptimizationScan(recommendations);
    }

    private void SetScanStage(string message, Action<string>? status)
    {
        OperationCancellationContext.ThrowIfCancellationRequested();
        log($"Windows 11 Optimization: {message}.");
        status?.Invoke(message + "...");
    }

    public async Task ApplyAsync(IReadOnlyList<OptimizationRecommendation> selected, MaintenanceService maintenance)
    {
        OperationCancellationContext.ThrowIfCancellationRequested();
        var changes = selected.Where(item => item.ActionKind != OptimizationActionKind.OpenSettings).ToArray();
        if (changes.Length == 0)
            return;

        if (changes.Any(item => !item.Selectable))
            throw new InvalidOperationException("The selection contains a recommendation that is not eligible for automatic changes.");

        var transaction = new OptimizationTransaction(
            Guid.NewGuid().ToString("N"),
            DateTimeOffset.Now.LocalDateTime,
            false,
            []);
        var history = ReadHistory().ToList();
        history.Add(transaction);
        SaveHistory(history);

        for (var index = 0; index < changes.Length; index++)
        {
            OperationCancellationContext.ThrowIfCancellationRequested();
            var item = changes[index];
            var change = CaptureChange(item);
            var savedChanges = transaction.Changes.ToList();
            savedChanges.Add(change);
            transaction = transaction with { Changes = savedChanges };
            history[^1] = transaction;
            SaveHistory(history);

            switch (item.ActionKind)
            {
                case OptimizationActionKind.RegistryValue:
                    SetRegistryValue(item);
                    break;
                case OptimizationActionKind.StartupFile:
                    DisableStartupFile(item, change);
                    break;
                case OptimizationActionKind.DriveOptimization:
                    await OptimizeDriveAsync(item);
                    break;
                default:
                    throw new InvalidOperationException($"Unsupported optimization action: {item.ActionKind}.");
            }
            log($"Applied optimization [{item.Category}] {item.Name}: {item.ProposedSetting}. Undoable: {change.Undoable}.");
        }
        OperationCancellationContext.ThrowIfCancellationRequested();
    }

    public bool HasUndoableChanges => ReadHistory().Any(transaction =>
        !transaction.Undone && transaction.Changes.Any(change => change.Undoable));

    public string GetUndoSummary()
    {
        var transaction = ReadHistory().LastOrDefault(item =>
            !item.Undone && item.Changes.Any(change => change.Undoable));
        if (transaction is null)
            return "No previous reversible Winvexa optimization changes are available to undo.";
        var reversibleCount = transaction.Changes.Count(change => change.Undoable);
        var permanentCount = transaction.Changes.Count(change => !change.Undoable);
        return $"Restore {reversibleCount} saved setting(s) from {transaction.CreatedAt:g}." +
               (permanentCount > 0 ? $" {permanentCount} drive optimization operation(s) cannot be undone." : string.Empty);
    }

    public async Task UndoPreviousAsync()
    {
        OperationCancellationContext.ThrowIfCancellationRequested();
        var history = ReadHistory().ToList();
        var index = history.FindLastIndex(transaction =>
            !transaction.Undone && transaction.Changes.Any(change => change.Undoable));
        if (index < 0)
            throw new InvalidOperationException("No previous reversible Winvexa optimization changes are available to undo.");

        var transaction = history[index];
        foreach (var change in transaction.Changes.Reverse().Where(change => change.Undoable))
        {
            OperationCancellationContext.ThrowIfCancellationRequested();
            RestoreChange(change);
            log($"Undid optimization change: {change.Description}.");
        }

        OperationCancellationContext.ThrowIfCancellationRequested();
        history[index] = transaction with { Undone = true };
        SaveHistory(history);
        await Task.CompletedTask;
    }

    public static async Task OpenSettingsAsync(OptimizationRecommendation item)
    {
        if (item.ActionKind != OptimizationActionKind.OpenSettings || string.IsNullOrWhiteSpace(item.SettingsUri))
            throw new InvalidOperationException("This recommendation does not have a supported Windows Settings page.");
        var start = new ProcessStartInfo(item.SettingsUri) { UseShellExecute = true };
        if (Process.Start(start) is null)
            throw new InvalidOperationException($"Windows could not open Settings for '{item.Name}'.");
        await Task.CompletedTask;
    }

    private void ScanStartup(List<OptimizationRecommendation> recommendations)
    {
        using (var runKey = Registry.CurrentUser.OpenSubKey(StartupRegistryPath))
        {
            if (runKey is not null)
            {
                foreach (var name in runKey.GetValueNames())
                {
                    OperationCancellationContext.ThrowIfCancellationRequested();
                    var command = runKey.GetValue(name)?.ToString() ?? string.Empty;
                    var publisher = GetPublisher(command);
                    var critical = LooksCritical(name, command, publisher);
                    recommendations.Add(new OptimizationRecommendation(
                        $"startup-run:{name}",
                        StartupFolderCategory,
                        name,
                        publisher,
                        "Enabled at sign-in (current user)",
                        critical ? "Keep enabled (protected)" : "Disable at sign-in",
                        critical
                            ? "This entry resembles security software, a driver, or a Windows component; Winvexa will not disable it."
                            : "Windows does not expose startup-impact metadata through this inventory. This entry does not match Winvexa's known security/driver/system protections; disable it only if you recognize it. The previous current-user value and type are saved for undo.",
                        OptimizationActionKind.RegistryValue,
                        !critical,
                        StartupRegistryPath,
                        name,
                        null,
                        RequiresRestorePoint: true));
                }
            }
        }

        var startupFolder = Environment.GetFolderPath(Environment.SpecialFolder.Startup);
        if (!string.IsNullOrWhiteSpace(startupFolder) && Directory.Exists(startupFolder))
        {
            foreach (var path in Directory.EnumerateFiles(startupFolder, "*.lnk"))
            {
                OperationCancellationContext.ThrowIfCancellationRequested();
                var name = Path.GetFileNameWithoutExtension(path);
                var publisher = GetPublisher(path);
                var critical = LooksCritical(name, path, publisher);
                recommendations.Add(new OptimizationRecommendation(
                    $"startup-file:{path}",
                    StartupFolderCategory,
                    name,
                    publisher,
                    "Enabled at sign-in (current user startup folder)",
                    critical ? "Keep enabled (protected)" : "Disable at sign-in",
                    critical
                        ? "This item resembles security software, a driver, or a Windows component; Winvexa will not disable it."
                        : "Moves only this current-user startup item to a reversible sibling backup. It is not deleted.",
                    OptimizationActionKind.StartupFile,
                    !critical,
                    StartupPath: path,
                    RequiresRestorePoint: true));
            }
        }

        ScanMachineStartup(recommendations);
        if (!recommendations.Any(item => item.Category == StartupFolderCategory))
            AddInformation(recommendations, StartupFolderCategory, "No current-user startup entries were found.");
    }

    private static void ScanMachineStartup(List<OptimizationRecommendation> recommendations)
    {
        var machineRunPath = @"Software\Microsoft\Windows\CurrentVersion\Run";
        foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
            using var runKey = baseKey.OpenSubKey(machineRunPath);
            if (runKey is null)
                continue;
            foreach (var name in runKey.GetValueNames())
            {
                OperationCancellationContext.ThrowIfCancellationRequested();
                var command = runKey.GetValue(name)?.ToString() ?? string.Empty;
                var publisher = GetPublisher(command);
                var critical = LooksCritical(name, command, publisher);
                recommendations.Add(new OptimizationRecommendation(
                    $"startup-machine:{view}:{name}",
                    StartupFolderCategory,
                    $"{name} (all users)",
                    publisher,
                    "Enabled at sign-in (machine-wide)",
                    critical ? "Keep enabled (protected)" : "Review manually in Startup settings",
                    critical
                        ? "This machine-wide entry resembles security software, a driver, or a Windows component and is protected."
                        : "This startup entry applies to all users. Winvexa does not disable machine-wide startup entries; selecting it only opens Windows Startup settings.",
                    OptimizationActionKind.OpenSettings,
                    !critical,
                    SettingsUri: "ms-settings:startupapps"));
            }
        }

        var commonStartup = Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup);
        if (string.IsNullOrWhiteSpace(commonStartup) || !Directory.Exists(commonStartup))
            return;
        foreach (var path in Directory.EnumerateFiles(commonStartup, "*.lnk"))
        {
            OperationCancellationContext.ThrowIfCancellationRequested();
            var name = Path.GetFileNameWithoutExtension(path);
            var publisher = GetPublisher(path);
            var critical = LooksCritical(name, path, publisher);
            recommendations.Add(new OptimizationRecommendation(
                $"startup-machine-file:{path}",
                StartupFolderCategory,
                $"{name} (all users)",
                publisher,
                "Enabled at sign-in (common startup folder)",
                critical ? "Keep enabled (protected)" : "Review manually in Startup settings",
                critical
                    ? "This machine-wide shortcut resembles security software, a driver, or a Windows component and is protected."
                    : "This shortcut applies to all users. Winvexa does not move or disable machine-wide startup items.",
                OptimizationActionKind.OpenSettings,
                !critical,
                SettingsUri: "ms-settings:startupapps"));
        }
    }

    private void ScanBackgroundApps(List<OptimizationRecommendation> recommendations)
    {
        const string path = @"Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications";
        using var root = Registry.CurrentUser.OpenSubKey(path);
        var found = false;
        if (root is not null)
        {
            foreach (var appName in root.GetSubKeyNames())
            {
                OperationCancellationContext.ThrowIfCancellationRequested();
                using var app = root.OpenSubKey(appName);
                if (app?.GetValue("Disabled") is not int disabled || disabled != 0)
                    continue;
                found = true;
                recommendations.Add(new OptimizationRecommendation(
                    $"background:{appName}",
                    "Background Apps",
                    appName,
                    "Windows app package",
                    "Background activity allowed",
                    "Restrict background activity",
                    "Changes only this existing per-app background permission value. Apps that rely on background synchronization or notifications should be left enabled. The prior value is saved for undo.",
                    OptimizationActionKind.RegistryValue,
                    true,
                    $"{path}\\{appName}",
                    "Disabled",
                    "1",
                    RequiresRestorePoint: true));
            }
        }
        if (!found)
            AddInformation(recommendations, "Background Apps", "No per-app background permissions could be identified from Windows settings on this account.");
    }

    private void ScanVisualEffects(List<OptimizationRecommendation> recommendations)
    {
        AddDwordSetting(recommendations, "Visual Effects", "Transparency effects", "Windows appearance",
            @"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize", "EnableTransparency", 0,
            "Reduces window and surface transparency. This changes appearance only and can be restored by Winvexa.");
        AddDwordSetting(recommendations, "Visual Effects", "Taskbar animations", "Windows",
            @"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "TaskbarAnimations", 0,
            "Turns off taskbar animations only; it does not change accessibility animation settings.");
        AddInformation(recommendations, "Visual Effects", "Windows does not expose a safe, single reversible switch for all animation effects. Winvexa leaves accessibility and other visual-effect settings unchanged.");
    }

    private void ScanNotifications(List<OptimizationRecommendation> recommendations)
    {
        const string path = @"Software\Microsoft\Windows\CurrentVersion\Notifications\Settings";
        using var root = Registry.CurrentUser.OpenSubKey(path);
        var found = false;
        if (root is not null)
        {
            foreach (var appName in root.GetSubKeyNames())
            {
                OperationCancellationContext.ThrowIfCancellationRequested();
                using var app = root.OpenSubKey(appName);
                if (app?.GetValue("Enabled") is not int enabled || enabled == 0)
                    continue;
                found = true;
                var critical = LooksCritical(appName, appName, string.Empty);
                recommendations.Add(new OptimizationRecommendation(
                    $"notification:{appName}",
                    "Notifications",
                    appName,
                    "Windows notification source",
                    "Notifications enabled",
                    critical ? "Keep notifications enabled (protected)" : "Turn off notifications",
                    critical
                        ? "This source resembles Windows security or a system notification; Winvexa will not turn it off."
                        : "Changes only this notification source. Its previous setting is saved for undo.",
                    OptimizationActionKind.RegistryValue,
                    !critical,
                    $"{path}\\{appName}",
                    "Enabled",
                    "0",
                    RequiresRestorePoint: true));
            }
        }
        if (!found)
            AddInformation(recommendations, "Notifications", "No enabled per-app notification settings were exposed for review.");
    }

    private void ScanSuggestions(List<OptimizationRecommendation> recommendations)
    {
        AddDwordSetting(recommendations, "Windows Suggestions", "Windows welcome and tips suggestions", "Windows",
            @"Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager", "SoftLandingEnabled", 0,
            "Turns off Windows tips and suggestions. This is a content preference, not a security setting.");
        AddDwordSetting(recommendations, "Windows Suggestions", "Suggested content in Settings", "Windows",
            @"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "SystemPaneSuggestionsEnabled", 0,
            "Turns off suggested content in Settings. This is a content preference, not a security setting.");
        AddDwordSetting(recommendations, "Windows Suggestions", "Suggested apps in Start", "Windows",
            @"Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager", "SubscribedContent-338388Enabled", 0,
            "Turns off this specific suggested-app content preference. Other Windows components are not modified.");
    }

    private void ScanPrivacy(List<OptimizationRecommendation> recommendations)
    {
        AddDwordSetting(recommendations, "Privacy/Personalization Settings", "Track app launches to improve Start suggestions", "Windows",
            @"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "Start_TrackProgs", 0,
            "Stops Windows from tracking app launches for Start personalization. This is a personalization preference, not a security protection.");
    }

    private void ScanUnusedApplications(List<OptimizationRecommendation> recommendations)
    {
        var apps = GetInstalledApplications();
        if (apps.Count == 0)
        {
            recommendations.Add(new OptimizationRecommendation(
                "unused-apps-review",
                "Unused Applications",
                "No installed applications were returned by Windows uninstall registration",
                "Windows Settings",
                "Reliable last-use information is not available for all desktop apps",
                "Review installed applications manually",
                "Winvexa does not infer app usage from install dates, file timestamps, or unreliable telemetry and will not label or uninstall applications automatically.",
                OptimizationActionKind.OpenSettings,
                true,
                SettingsUri: "ms-settings:appsfeatures"));
        }
        else
        {
            foreach (var app in apps)
            {
                OperationCancellationContext.ThrowIfCancellationRequested();
                recommendations.Add(new OptimizationRecommendation(
                    $"installed-app:{app.Name}",
                    "Unused Applications",
                    app.Name,
                    app.Publisher,
                    $"Last known use: unavailable; registered size: {app.Size}",
                    "Review in Installed apps",
                    "Windows does not provide reliable last-use data for this application. This is not classified as unused; selecting it only opens Windows Settings. Winvexa will not uninstall it.",
                    OptimizationActionKind.OpenSettings,
                    true,
                    SettingsUri: "ms-settings:appsfeatures"));
            }
        }
    }

    private async Task ScanPowerModeAsync(List<OptimizationRecommendation> recommendations)
    {
        const string script = """
            $battery = @(Get-CimInstance Win32_Battery -ErrorAction SilentlyContinue).Count -gt 0
            $computer = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
            $chassis = @(Get-CimInstance Win32_SystemEnclosure -ErrorAction SilentlyContinue | ForEach-Object { $_.ChassisTypes })
            $mobileChassis = @($chassis | Where-Object { $_ -in 8, 9, 10, 14, 30, 31, 32 }).Count -gt 0
            $desktopChassis = @($chassis | Where-Object { $_ -in 3, 4, 5, 6, 7, 15, 16, 17 }).Count -gt 0
            $deviceType = 'Unknown'
            if ($battery -or [int]$computer.PCSystemType -in 2, 8, 9, 10, 14 -or $mobileChassis) {
              $deviceType = 'Laptop'
            } elseif ([int]$computer.PCSystemType -eq 1 -or $desktopChassis) {
              $deviceType = 'Desktop'
            }
            $plan = (& powercfg.exe /getactivescheme 2>&1 | Out-String).Trim()
            [pscustomobject]@{
              DeviceType = $deviceType
              ActivePlan = $plan
            } | ConvertTo-Json -Compress
            """;
        try
        {
            var output = await RunPowerShellAsync(script, TimeSpan.FromSeconds(30));
            using var document = JsonDocument.Parse(output.Output.Trim());
            var root = document.RootElement;
            var deviceType = root.GetProperty("DeviceType").GetString() ?? "Unknown";
            var plan = root.GetProperty("ActivePlan").GetString() ?? "Power plan could not be read";
            recommendations.Add(new OptimizationRecommendation(
                "power-mode",
                "Power Mode",
                $"{deviceType} power mode",
                "Windows",
                plan,
                deviceType.Equals("Laptop", StringComparison.OrdinalIgnoreCase)
                    ? "Review Best performance (higher heat and battery use)"
                    : deviceType.Equals("Desktop", StringComparison.OrdinalIgnoreCase)
                        ? "Review Best performance"
                        : "Review power mode (device type unconfirmed)",
                deviceType.Equals("Laptop", StringComparison.OrdinalIgnoreCase)
                    ? "Windows power mode is a user choice. Best performance can increase power consumption, heat, and battery drain; Winvexa will open Power settings rather than changing it."
                    : deviceType.Equals("Desktop", StringComparison.OrdinalIgnoreCase)
                        ? "Windows power mode is a user choice. Winvexa will open Power settings rather than changing the active plan."
                        : "Windows could not confidently identify this device as a laptop or desktop. Winvexa will not presume performance is appropriate and will open Power settings only.",
                OptimizationActionKind.OpenSettings,
                true,
                SettingsUri: "ms-settings:powersleep"));
        }
        catch (OperationCanceledException) when (OperationCancellationContext.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            log($"Could not inspect Windows power mode: {exception.Message}");
            AddInformation(recommendations, "Power Mode", $"Power mode could not be reliably identified: {exception.Message}");
        }
    }

    private async Task ScanDrivesAsync(List<OptimizationRecommendation> recommendations)
    {
        const string script = """
            $ErrorActionPreference = 'Stop'
            $result = @()
            $physicalDisks = @()
            $physicalDiskError = $null
            try { $physicalDisks = @(Get-PhysicalDisk -ErrorAction Stop) }
            catch { $physicalDiskError = $_.Exception.Message }
            foreach ($volume in Get-Volume -ErrorAction Stop | Where-Object { $_.DriveLetter -and $_.DriveType -eq 'Fixed' }) {
              $media = 'Unknown'
              $detail = 'Drive type could not be confirmed; no automatic optimization will be offered.'
              try {
                $partition = Get-Partition -DriveLetter $volume.DriveLetter -ErrorAction Stop | Select-Object -First 1
                $disk = Get-Disk -Number $partition.DiskNumber -ErrorAction Stop
                $physical = $physicalDisks | Where-Object { $_.DeviceId -eq $disk.Number } | Select-Object -First 1
                if ($null -ne $physical -and [string]$physical.MediaType -ne 'Unspecified') {
                  $media = [string]$physical.MediaType
                } elseif ([string]$disk.BusType -eq 'NVMe' -or [string]$disk.BusType -eq 'SSD') {
                  $media = 'SSD'
                }
                $detail = "$($disk.FriendlyName) ($($disk.BusType))"
                if ($physicalDiskError) { $detail += "; media type query warning: $physicalDiskError" }
              } catch {
                $detail = $_.Exception.Message
              }
              $result += [pscustomobject]@{ DriveLetter = [string]$volume.DriveLetter; FileSystem = [string]$volume.FileSystem; MediaType = $media; Detail = $detail }
            }
            ConvertTo-Json -InputObject @($result) -Compress -Depth 3
            """;
        try
        {
            var output = await RunPowerShellAsync(script, TimeSpan.FromSeconds(30));
            using var document = JsonDocument.Parse(output.Output.Trim());
            foreach (var drive in document.RootElement.EnumerateArray())
            {
                OperationCancellationContext.ThrowIfCancellationRequested();
                var letter = drive.GetProperty("DriveLetter").GetString();
                var media = drive.GetProperty("MediaType").GetString() ?? "Unknown";
                var detail = drive.GetProperty("Detail").GetString() ?? string.Empty;
                var canOptimize = media.Equals("SSD", StringComparison.OrdinalIgnoreCase) ||
                                  media.Equals("HDD", StringComparison.OrdinalIgnoreCase);
                var algorithm = media.Equals("SSD", StringComparison.OrdinalIgnoreCase)
                    ? "Windows ReTrim (SSD)"
                    : "Windows Optimize/defragment (HDD)";
                recommendations.Add(new OptimizationRecommendation(
                    $"drive:{letter}",
                    "Drive Optimization",
                    $"{letter}: ({media})",
                    $"{media} - {detail}",
                    $"{media} detected; optimization not run",
                    canOptimize ? algorithm : "Review drive type manually; no operation offered",
                    canOptimize
                        ? "Uses Windows Optimize-Volume with the media-appropriate operation. This maintenance operation does not have a practical undo."
                        : "Winvexa will not run an optimization when SSD/HDD type cannot be confirmed.",
                    OptimizationActionKind.DriveOptimization,
                    canOptimize,
                    DriveLetter: letter,
                    RequiresRestorePoint: false));
            }
            if (recommendations.All(item => item.Category != "Drive Optimization"))
                AddInformation(recommendations, "Drive Optimization", "No fixed local drives were reported by Windows Storage cmdlets.");
        }
        catch (OperationCanceledException) when (OperationCancellationContext.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            log($"Could not inspect drive media types: {exception}");
            AddInformation(recommendations, "Drive Optimization", $"Windows drive type detection failed. No drive optimization was offered: {exception.Message}");
        }
    }

    private void ScanGaming(List<OptimizationRecommendation> recommendations)
    {
        recommendations.Add(new OptimizationRecommendation(
            "gaming-settings",
            "Gaming/Graphics Settings",
            "Review Game Mode and graphics preferences",
            "Windows Settings",
            "Current per-game settings are not changed or exhaustively inferred",
            "Review Game Mode and per-app GPU preference",
            "Recommendations depend on the game and hardware. Winvexa does not disable Game Bar, Game Mode, or background capture automatically.",
            OptimizationActionKind.OpenSettings,
            true,
            SettingsUri: "ms-settings:display-advancedgraphics"));
        recommendations.Add(new OptimizationRecommendation(
            "gaming-gamebar",
            "Gaming/Graphics Settings",
            "Review Xbox Game Bar settings",
            "Windows Settings",
            "Not changed",
            "Review individually",
            "Keep gaming features enabled unless you decide a specific feature is unnecessary.",
            OptimizationActionKind.OpenSettings,
            true,
            SettingsUri: "ms-settings:gaming-gamebar"));
    }

    private void AddDwordSetting(
        List<OptimizationRecommendation> recommendations,
        string category,
        string name,
        string publisher,
        string path,
        string valueName,
        int proposed,
        string description)
    {
        using var key = Registry.CurrentUser.OpenSubKey(path);
        var current = key?.GetValue(valueName);
        if (current is not null && key!.GetValueKind(valueName) != RegistryValueKind.DWord)
        {
            AddInformation(recommendations, category, $"{name} was not changed because its stored value is not the expected DWORD type.");
            log($"Skipped optimization scan for {category}/{name}: registry value type was not DWORD.");
            return;
        }
        var currentValue = current is null ? 1 : Convert.ToInt32(current);
        var enabled = currentValue != 0;
        recommendations.Add(new OptimizationRecommendation(
            $"registry:{path}:{valueName}",
            category,
            name,
            publisher,
            current is null ? "Windows default (enabled)" : enabled ? "Enabled" : "Disabled",
            enabled ? "Turn off" : "Already off",
            description,
            OptimizationActionKind.RegistryValue,
            enabled && proposed == 0,
            path,
            valueName,
            proposed.ToString(),
            RequiresRestorePoint: true));
    }

    private static void AddInformation(List<OptimizationRecommendation> recommendations, string category, string message)
    {
        recommendations.Add(new OptimizationRecommendation(
            $"info:{category}:{message}",
            category,
            message,
            "Winvexa",
            "Informational",
            "No change proposed",
            "No setting will be changed.",
            OptimizationActionKind.OpenSettings,
            false));
    }

    private static bool LooksCritical(string name, string command, string publisher)
    {
        var value = $"{name} {command} {publisher}";
        return new[] { "defender", "antivirus", "security", "windows security", "windows defender",
            "driver", "intel", "amd", "nvidia", "realtek", "synaptics", "touchpad",
            "accessibility", "ease of access", "windows update", "microsoft windows" }
            .Any(term => value.Contains(term, StringComparison.OrdinalIgnoreCase));
    }

    private static string GetPublisher(string commandOrPath)
    {
        try
        {
            var match = System.Text.RegularExpressions.Regex.Match(commandOrPath, "\"(?<path>[^\\\"]+\\.exe)\"|(?<path>[A-Za-z]:\\\\[^,\\\"]+\\.exe)", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            var path = match.Success ? match.Groups["path"].Value : string.Empty;
            if (!File.Exists(path))
                return "Unknown publisher";
            return FileVersionInfo.GetVersionInfo(path).CompanyName ?? "Unknown publisher";
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException)
        {
            return "Unknown publisher";
        }
    }

    private static IReadOnlyList<InstalledApplication> GetInstalledApplications()
    {
        var apps = new List<InstalledApplication>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var uninstallPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
        foreach (var hive in new[] { RegistryHive.CurrentUser, RegistryHive.LocalMachine })
        {
            OperationCancellationContext.ThrowIfCancellationRequested();
            foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
            {
                OperationCancellationContext.ThrowIfCancellationRequested();
                using var baseKey = RegistryKey.OpenBaseKey(hive, view);
                using var root = baseKey.OpenSubKey(uninstallPath);
                if (root is null)
                    continue;
                foreach (var subKeyName in root.GetSubKeyNames())
                {
                    OperationCancellationContext.ThrowIfCancellationRequested();
                    using var appKey = root.OpenSubKey(subKeyName);
                    var name = appKey?.GetValue("DisplayName")?.ToString();
                    if (string.IsNullOrWhiteSpace(name) || !seen.Add(name) || IsSupportComponent(appKey!, name))
                        continue;
                    var publisher = appKey?.GetValue("Publisher")?.ToString();
                    var estimatedKb = appKey?.GetValue("EstimatedSize") is int sizeKb && sizeKb > 0 ? sizeKb : 0;
                    var size = estimatedKb == 0
                        ? "not provided by installer"
                        : estimatedKb >= 1024 * 1024
                            ? $"{estimatedKb / 1048576d:0.##} GB (installer estimate)"
                            : $"{estimatedKb / 1024d:0.##} MB (installer estimate)";
                    apps.Add(new InstalledApplication(name, string.IsNullOrWhiteSpace(publisher) ? "Unknown publisher" : publisher,
                        size));
                }
            }
        }
        return apps.OrderBy(app => app.Name, StringComparer.OrdinalIgnoreCase).ToArray();
    }

    private static bool IsSupportComponent(RegistryKey appKey, string name)
    {
        if (appKey.GetValue("SystemComponent") is int systemComponent && systemComponent == 1 ||
            appKey.GetValue("ParentKeyName") is not null ||
            appKey.GetValue("ReleaseType") is not null)
            return true;
        return new[]
        {
            "Windows Driver Package", "Update for ", "Security Update for ",
            "Microsoft Visual C++", ".NET Framework", "Targeting Pack",
            "Setup Configuration", "Windows SDK", "Windows Software Development Kit"
        }.Any(prefix => name.StartsWith(prefix, StringComparison.OrdinalIgnoreCase));
    }

    private static OptimizationChange CaptureChange(OptimizationRecommendation item)
    {
        if (item.ActionKind == OptimizationActionKind.RegistryValue)
        {
            var (exists, value, kind, keyExists) = ReadRegistryValue(item.RegistryPath!, item.RegistryValueName!);
            return new OptimizationChange(
                item.ActionKind,
                $"{item.Category}: {item.Name}",
                item.RegistryPath,
                item.RegistryValueName,
                exists,
                value,
                kind,
                null,
                null,
                true,
                keyExists);
        }
        if (item.ActionKind == OptimizationActionKind.StartupFile)
        {
            var path = item.StartupPath!;
            var disabled = path + $".WinvexaDisabled-{Guid.NewGuid():N}";
            return new OptimizationChange(item.ActionKind, $"{item.Category}: {item.Name}", null, null, false, null, null, path, disabled, true);
        }
        if (item.ActionKind == OptimizationActionKind.DriveOptimization)
            return new OptimizationChange(item.ActionKind, $"{item.Category}: {item.Name}", null, null, false, null, null, null, null, false);
        throw new InvalidOperationException($"Recommendation cannot be applied automatically: {item.Name}.");
    }

    private static void SetRegistryValue(OptimizationRecommendation item)
    {
        using var key = Registry.CurrentUser.CreateSubKey(item.RegistryPath!, writable: true)
            ?? throw new InvalidOperationException($"Could not open the current-user setting for '{item.Name}'.");
        if (item.RegistryValue is null)
            key.DeleteValue(item.RegistryValueName!, throwOnMissingValue: false);
        else if (int.TryParse(item.RegistryValue, out var number))
            key.SetValue(item.RegistryValueName!, number, RegistryValueKind.DWord);
        else
            key.DeleteValue(item.RegistryValueName!, throwOnMissingValue: false);
    }

    private static void DisableStartupFile(OptimizationRecommendation item, OptimizationChange change)
    {
        var original = change.OriginalPath!;
        var disabled = change.DisabledPath!;
        if (!File.Exists(original))
            throw new FileNotFoundException("The selected startup item no longer exists.", original);
        File.Move(original, disabled);
    }

    private async Task OptimizeDriveAsync(OptimizationRecommendation item)
    {
        var letter = item.DriveLetter;
        if (string.IsNullOrWhiteSpace(letter) || letter.Length != 1 ||
            !(item.Publisher.Contains("SSD", StringComparison.OrdinalIgnoreCase) ||
              item.Publisher.Contains("HDD", StringComparison.OrdinalIgnoreCase)))
            throw new InvalidOperationException("Drive optimization was refused because the drive type could not be confirmed.");
        var script = "$ErrorActionPreference = 'Stop'; " +
                     (item.ProposedSetting.Contains("SSD", StringComparison.OrdinalIgnoreCase)
                         ? $"Optimize-Volume -DriveLetter '{letter}' -ReTrim -Verbose"
                         : $"Optimize-Volume -DriveLetter '{letter}' -Defrag -Verbose");
        var output = await RunPowerShellAsync(
            script,
            TimeSpan.FromHours(2),
            ProcessStopPolicy.FinishCurrentOperation);
        if (output.ExitCode != 0)
            throw new InvalidOperationException($"Windows drive optimization failed for {letter}: {output.Error} {output.Output}".Trim());
        log($"Windows {item.ProposedSetting} completed for drive {letter}: {output.Output} {output.Error}".Trim());
    }

    private static (bool Exists, string? Value, string? Kind, bool KeyExists) ReadRegistryValue(string path, string name)
    {
        using var key = Registry.CurrentUser.OpenSubKey(path);
        if (key is null || !key.GetValueNames().Contains(name, StringComparer.OrdinalIgnoreCase))
            return (false, null, null, key is not null);
        var value = key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
        var kind = key.GetValueKind(name);
        var text = value switch
        {
            int number => number.ToString(),
            string stringValue => stringValue,
            _ => throw new InvalidOperationException($"Winvexa cannot safely save the '{kind}' value for undo.")
        };
        return (true, text, kind.ToString(), true);
    }

    private static void RestoreChange(OptimizationChange change)
    {
        if (change.ActionKind == OptimizationActionKind.RegistryValue)
        {
            using var key = Registry.CurrentUser.CreateSubKey(change.RegistryPath!, writable: true)
                ?? throw new InvalidOperationException($"Could not open the saved setting for undo: {change.Description}.");
            if (!change.PreviousValueExists)
            {
                key.DeleteValue(change.RegistryValueName!, throwOnMissingValue: false);
                if (!change.PreviousKeyExists && key.ValueCount == 0 && key.SubKeyCount == 0)
                {
                    key.Dispose();
                    Registry.CurrentUser.DeleteSubKey(change.RegistryPath!, throwOnMissingSubKey: false);
                }
                return;
            }
            var kind = Enum.Parse<RegistryValueKind>(change.PreviousValueKind!, ignoreCase: true);
            object value = kind == RegistryValueKind.DWord
                ? int.Parse(change.PreviousValue!)
                : change.PreviousValue!;
            key.SetValue(change.RegistryValueName!, value, kind);
            return;
        }

        if (change.ActionKind == OptimizationActionKind.StartupFile)
        {
            var originalExists = File.Exists(change.OriginalPath);
            var disabledExists = File.Exists(change.DisabledPath);
            if (originalExists && !disabledExists)
                return;
            if (originalExists)
                throw new IOException($"Cannot restore '{change.Description}' because the original startup path is already occupied.");
            if (!disabledExists)
                throw new FileNotFoundException($"The saved disabled startup item for '{change.Description}' is missing.", change.DisabledPath);
            File.Move(change.DisabledPath!, change.OriginalPath!);
            return;
        }

        throw new InvalidOperationException($"The change '{change.Description}' has no supported undo operation.");
    }

    private List<OptimizationTransaction> ReadHistory()
    {
        if (!File.Exists(_historyPath))
            return [];
        try
        {
            return JsonSerializer.Deserialize<List<OptimizationTransaction>>(File.ReadAllText(_historyPath)) ?? [];
        }
        catch (Exception exception) when (exception is IOException or JsonException or UnauthorizedAccessException)
        {
            throw new InvalidOperationException($"Could not read the saved optimization undo history '{_historyPath}': {exception.Message}", exception);
        }
    }

    private void SaveHistory(IReadOnlyList<OptimizationTransaction> history)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_historyPath)!);
            var temporaryPath = _historyPath + ".tmp";
            File.WriteAllText(temporaryPath, JsonSerializer.Serialize(history, JsonOptions));
            File.Move(temporaryPath, _historyPath, overwrite: true);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            throw new InvalidOperationException($"Could not save optimization undo history '{_historyPath}': {exception.Message}", exception);
        }
    }

    private async Task<CommandResult> RunPowerShellAsync(
        string script,
        TimeSpan? timeout = null,
        ProcessStopPolicy stopPolicy = ProcessStopPolicy.TerminateProcessTree)
    {
        OperationCancellationContext.ThrowIfCancellationRequested();
        var executable = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0", "powershell.exe");
        var start = new ProcessStartInfo(executable)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        start.ArgumentList.Add("-NoLogo");
        start.ArgumentList.Add("-NoProfile");
        start.ArgumentList.Add("-NonInteractive");
        start.ArgumentList.Add("-EncodedCommand");
        start.ArgumentList.Add(Convert.ToBase64String(Encoding.Unicode.GetBytes(script)));
        return await CancellableProcessRunner.RunAsync(
            start,
            "Windows 11 Optimization PowerShell operation",
            log,
            OperationCancellationContext.Token,
            stopPolicy,
            timeout);
    }

    private sealed record InstalledApplication(string Name, string Publisher, string Size);
}
