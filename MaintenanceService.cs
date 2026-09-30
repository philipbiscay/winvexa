using System.Diagnostics;
using System.IO;
using Microsoft.Win32;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;

namespace Winvexa;

internal sealed record CleanupFile(string Path, long Size);

internal sealed class CleanupCategory(string name, string path)
{
    public string Name { get; } = name;
    public string Path { get; } = path;
    public List<CleanupFile> Files { get; } = [];
    public long Bytes => Files.Sum(file => file.Size);
}

internal sealed record CleanupScan(IReadOnlyList<CleanupCategory> Categories, int DriveCount)
{
    public long Bytes => Categories.Sum(category => category.Bytes);
    public int FileCount => Categories.Sum(category => category.Files.Count);
}

internal sealed record CommandResult(int ExitCode, string Output, string Error);
internal sealed record UpdateCandidate(string Title, string UpdateId, int RevisionNumber);
internal sealed record UpdateServiceDiagnostic(string Name, string DisplayName, string State, string StartMode);
internal sealed record UpdateHistoryFailure(string Date, string Title, int ResultCode, string HResult);
internal sealed record UpdateEventError(string Date, int EventId, string HResult, string Message);
internal sealed record WindowsUpdateDiagnostics(
    IReadOnlyList<UpdateServiceDiagnostic> Services,
    IReadOnlyList<UpdateHistoryFailure> RecentFailures,
    IReadOnlyList<UpdateEventError> RecentEventErrors,
    IReadOnlyList<UpdateCandidate> PendingUpdates,
    IReadOnlyList<string> DiagnosticWarnings,
    bool RestartRequired,
    string? SearchError,
    string? SearchHResult)
{
    public bool SearchSucceeded => SearchError is null;
    public bool DisabledServices => Services.Any(service =>
        service.Name is "wuauserv" or "bits" or "cryptsvc" &&
        service.StartMode.Equals("Disabled", StringComparison.OrdinalIgnoreCase));
    public bool ServiceChecksSucceeded =>
        new[] { "wuauserv", "bits", "cryptsvc" }.All(name =>
            Services.Any(service =>
                service.Name.Equals(name, StringComparison.OrdinalIgnoreCase) &&
                !service.State.Equals("Unavailable", StringComparison.OrdinalIgnoreCase) &&
                !service.State.Equals("QueryFailed", StringComparison.OrdinalIgnoreCase) &&
                !service.StartMode.Equals("Unknown", StringComparison.OrdinalIgnoreCase)));
    public bool IsOperational => SearchSucceeded && ServiceChecksSucceeded && !DisabledServices;
}
internal sealed record WindowsUpdateServiceRepairResult(
    IReadOnlyList<UpdateServiceDiagnostic> Services,
    IReadOnlyList<string> Errors);
internal sealed record WindowsUpdateCacheRepairResult(string BackupPath, IReadOnlyList<string> Services);
internal sealed record WindowsSystemRepairResult(int ExitCode, string Output, string Error);
internal sealed record WindowsInstallationInfo(
    string Edition,
    string Architecture,
    string Version,
    string Build,
    string ServicingBuild,
    string? ConfiguredRepairSource,
    bool RepairSourcePolicyOverridesWindowsUpdate);
internal sealed record MicrosoftRepairSourceCheck(int ApplicableUpdateCount, string Details);
internal sealed record WindowsRepairSourceVerification(string DismSigner, string SfcSigner, string Details);
internal sealed record DriveHealthSummary(int Checked, int Issues, int Skipped, int PhysicalDisksChecked, int Failed);
internal sealed record DefenderThreatInfo(
    string ThreatId,
    string ThreatName,
    string Severity,
    DateTimeOffset? DetectedAt,
    bool? ActionSucceeded,
    string Resource);
internal sealed record DefenderSecurityStatus(
    bool AntivirusEnabled,
    bool AntispywareEnabled,
    bool ServiceEnabled,
    bool RealTimeProtectionEnabled,
    bool BehaviorMonitorEnabled,
    bool IoavProtectionEnabled,
    bool NetworkInspectionEnabled,
    bool IsTamperProtected,
    string RunningMode,
    string EngineVersion,
    string SignatureVersion,
    int? SignatureAgeDays,
    DateTimeOffset? SignatureLastUpdated,
    DateTimeOffset? LastQuickScan,
    DateTimeOffset? LastFullScan,
    IReadOnlyList<DefenderThreatInfo> ActiveThreats,
    IReadOnlyList<DefenderThreatInfo> RecentDetections)
{
    public string OverallStatus =>
        ActiveThreats.Count > 0 ? "Threat detected" :
        SignatureAgeDays is null ||
        SignatureLastUpdated is null ||
        SignatureVersion.Equals("Unavailable", StringComparison.OrdinalIgnoreCase) ||
        RunningMode.Equals("Unavailable", StringComparison.OrdinalIgnoreCase)
            ? "Unable to verify" :
        !ServiceEnabled || !AntivirusEnabled || !RealTimeProtectionEnabled ||
        !RunningMode.Equals("Normal", StringComparison.OrdinalIgnoreCase) ||
        SignatureAgeDays is > 7
            ? "Attention required"
            : "Protected";
}
internal sealed record UpdateSearch(IReadOnlyList<UpdateCandidate> Updates, bool RebootRequired, string Details)
{
    public int Count => Updates.Count;
    public IReadOnlyList<string> Titles => Updates.Select(update => update.Title).ToArray();
}

internal sealed class MaintenanceService(Action<string> log)
{
    private static readonly TimeSpan MinimumAge = TimeSpan.FromDays(10);
    private const string WindowsUpdateServiceId = "9482f4b4-e343-43b6-b170-9a65bc822c77";
    private bool _windowsRepairSourceVerified;

    public void ResetWindowsRepairSourceVerification() =>
        _windowsRepairSourceVerified = false;

    public WindowsInstallationInfo GetWindowsInstallationInfo()
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("Windows repair-source verification is available only on Windows.");

        using var key = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64)
            .OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
        if (key is null)
            throw new InvalidOperationException("Windows installation version information is unavailable.");

        var edition = ReadRegistryString(key, "EditionID");
        var version = ReadRegistryString(key, "DisplayVersion");
        var build = ReadRegistryString(key, "CurrentBuildNumber");
        var revision = key.GetValue("UBR") is int updateBuildRevision
            ? updateBuildRevision.ToString(System.Globalization.CultureInfo.InvariantCulture)
            : "unknown";
        var servicingBuild = ReadRegistryString(key, "BuildLabEx");
        if (string.IsNullOrWhiteSpace(edition) ||
            !int.TryParse(build, out var buildNumber) ||
            buildNumber < 22000)
        {
            throw new InvalidOperationException(
                $"The installed Windows edition/build could not be confirmed as a supported Windows 11 installation (edition '{edition}', build '{build}'). No repair was started.");
        }

        var architecture = System.Runtime.InteropServices.RuntimeInformation.OSArchitecture.ToString();
        if (architecture is not ("X64" or "Arm64"))
            throw new InvalidOperationException($"Windows architecture '{architecture}' is not supported for this Windows 11 repair workflow.");

        var servicingKeyPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Servicing";
        using var servicingPolicy = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64)
            .OpenSubKey(servicingKeyPath);
        var localSource = servicingPolicy?.GetValue("LocalSourcePath") as string;
        var repairContentSource = servicingPolicy?.GetValue("RepairContentServerSource") is int source
            ? source
            : 0;
        var repairSourcePolicyOverridesWindowsUpdate =
            !string.IsNullOrWhiteSpace(localSource) && repairContentSource != 2;
        if (repairSourcePolicyOverridesWindowsUpdate)
            localSource = "A Windows servicing policy-configured local source";
        else if (repairContentSource == 1)
        {
            repairSourcePolicyOverridesWindowsUpdate = true;
            localSource = "The organization-managed Windows Server Update Services repair source";
        }
        else if (repairContentSource is not (0 or 2))
        {
            repairSourcePolicyOverridesWindowsUpdate = true;
            localSource = $"An unrecognized Windows servicing repair-source policy ({repairContentSource})";
        }

        using var updatePolicy = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64)
            .OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU");
        var usesManagedUpdateServer = updatePolicy?.GetValue("UseWUServer") is int useWuServer && useWuServer == 1;
        if (usesManagedUpdateServer && repairContentSource != 2)
        {
            repairSourcePolicyOverridesWindowsUpdate = true;
            localSource = "An organization-managed Windows Update/WSUS repair source";
        }

        var info = new WindowsInstallationInfo(
            edition,
            architecture,
            string.IsNullOrWhiteSpace(version) ? "unknown" : version,
            $"{build}.{revision}",
            string.IsNullOrWhiteSpace(servicingBuild) ? "unavailable" : servicingBuild,
            localSource,
            repairSourcePolicyOverridesWindowsUpdate);
        log($"Windows repair target: Windows 11 {info.Edition}, {info.Architecture}, version {info.Version}, build {info.Build}, servicing build {info.ServicingBuild}.");
        return info;
    }

    public async Task<MicrosoftRepairSourceCheck> CheckMicrosoftWindowsUpdateSourceAsync()
    {
        var script = $$"""
            $ErrorActionPreference = 'Stop'
            try {
              $session = New-Object -ComObject Microsoft.Update.Session
              $searcher = $session.CreateUpdateSearcher()
              $searcher.ServerSelection = 2
              $searcher.ServiceID = '{{WindowsUpdateServiceId}}'
              $result = $searcher.Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
              $serviceId = [string]$searcher.ServiceID
              if ($serviceId -ne '{{WindowsUpdateServiceId}}' -or [int]$searcher.ServerSelection -ne 2) {
                throw "Windows Update Agent did not use the explicitly selected Microsoft Windows Update service."
              }
              [pscustomobject]@{
                Success = ([int]$result.ResultCode -eq 2)
                ResultCode = [int]$result.ResultCode
                HResult = '0x00000000'
                ApplicableUpdateCount = [int]$result.Updates.Count
                ServiceId = $serviceId
                Error = $null
              } | ConvertTo-Json -Compress
            } catch {
              $hr = '0x{0:X8}' -f ($_.Exception.HResult -band 0xffffffffL)
              [pscustomobject]@{
                Success = $false
                ResultCode = -1
                HResult = $hr
                ApplicableUpdateCount = 0
                ServiceId = '{{WindowsUpdateServiceId}}'
                Error = $_.Exception.Message
              } | ConvertTo-Json -Compress
              exit 1
            }
            """;
        log("Checking the official Microsoft Windows Update service using the Windows Update Agent and its explicitly selected Microsoft service ID.");
        var result = await RunPowerShellAsync(
            script,
            timeout: TimeSpan.FromMinutes(5),
            stopPolicy: ProcessStopPolicy.TerminateProcessTree);
        if (result.ExitCode != 0)
            throw new InvalidOperationException($"Microsoft Windows Update could not verify the repair source. {result.Output} {result.Error}".Trim());

        try
        {
            using var document = JsonDocument.Parse(result.Output.Trim());
            var root = document.RootElement;
            var success = root.GetProperty("Success").GetBoolean();
            var serviceId = root.GetProperty("ServiceId").GetString() ?? string.Empty;
            var resultCode = root.GetProperty("ResultCode").GetInt32();
            var hresult = root.GetProperty("HResult").GetString() ?? "unknown";
            var error = root.GetProperty("Error").ValueKind == JsonValueKind.Null
                ? null
                : root.GetProperty("Error").GetString();
            if (!success ||
                resultCode != 2 ||
                !serviceId.Equals(WindowsUpdateServiceId, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    $"The official Microsoft Windows Update source check did not succeed (result {resultCode}, HRESULT {hresult}). {error} {result.Output} {result.Error}".Trim());
            }

            var updateCount = root.GetProperty("ApplicableUpdateCount").GetInt32();
            var details = $"Microsoft Windows Update Agent successfully queried the official Windows Update service over Windows' secure update channel. The source reports {updateCount} applicable software update(s); no Windows feature upgrade was requested or started. WUA verifies update applicability and signature/catalog integrity when servicing payloads are acquired.";
            log(details);
            return new MicrosoftRepairSourceCheck(updateCount, details);
        }
        catch (JsonException exception)
        {
            throw new InvalidOperationException(
                $"Microsoft Windows Update returned an unreadable source-verification result. {result.Output} {result.Error}".Trim(),
                exception);
        }
    }

    public async Task<WindowsRepairSourceVerification> VerifyWindowsRepairSourceAsync(
        WindowsInstallationInfo installation)
    {
        if (installation.RepairSourcePolicyOverridesWindowsUpdate)
        {
            throw new InvalidOperationException(
                $"{installation.ConfiguredRepairSource} overrides Microsoft Windows Update. Winvexa will not change Windows servicing policy or proceed with this repair source.");
        }

        var script = """
            $ErrorActionPreference = 'Stop'
            try {
              $paths = @(
                (Join-Path $env:SystemRoot 'System32\dism.exe'),
                (Join-Path $env:SystemRoot 'System32\sfc.exe')
              )
              $signatures = @()
              foreach ($path in $paths) {
                if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
                  throw "Required Windows servicing binary is missing: $path"
                }
                $signature = Get-AuthenticodeSignature -LiteralPath $path
                if ($signature.Status -ne 'Valid' -or
                    $null -eq $signature.SignerCertificate -or
                    $signature.SignerCertificate.Subject -notmatch 'Microsoft Windows|Microsoft Corporation') {
                  throw "Windows servicing binary did not pass Microsoft Authenticode verification: $path; status=$($signature.Status); signer=$($signature.SignerCertificate.Subject)"
                }
                $signatures += [pscustomobject]@{
                  Path = $path
                  Status = [string]$signature.Status
                  Signer = [string]$signature.SignerCertificate.Subject
                }
              }
              [pscustomobject]@{ Success = $true; Signatures = $signatures; Error = $null } | ConvertTo-Json -Compress -Depth 3
            } catch {
              [pscustomobject]@{ Success = $false; Signatures = @(); Error = $_.Exception.Message } | ConvertTo-Json -Compress
              exit 1
            }
            """;
        var result = await RunPowerShellAsync(script, timeout: TimeSpan.FromMinutes(2));
        if (result.ExitCode != 0)
            throw new InvalidOperationException($"Windows repair-source signature verification failed. {result.Output} {result.Error}".Trim());

        string dismSigner;
        string sfcSigner;
        try
        {
            using var document = JsonDocument.Parse(result.Output.Trim());
            var root = document.RootElement;
            if (!root.GetProperty("Success").GetBoolean())
                throw new InvalidOperationException(root.GetProperty("Error").GetString() ?? "Microsoft signature verification failed.");
            var signatures = root.GetProperty("Signatures").EnumerateArray()
                .ToDictionary(
                    item => Path.GetFileName(item.GetProperty("Path").GetString() ?? string.Empty),
                    item => item.GetProperty("Signer").GetString() ?? "unknown",
                    StringComparer.OrdinalIgnoreCase);
            if (!signatures.TryGetValue("dism.exe", out dismSigner!) ||
                !signatures.TryGetValue("sfc.exe", out sfcSigner!))
            {
                throw new InvalidOperationException("The Microsoft signatures for DISM and SFC could not both be verified.");
            }
        }
        catch (JsonException exception)
        {
            throw new InvalidOperationException(
                $"Windows repair-source signature verification returned unreadable data. {result.Output} {result.Error}".Trim(),
                exception);
        }

        var health = await RunDismCheckHealthAsync();
        var healthOutput = $"{health.Output}\n{health.Error}";
        var nonRepairable = healthOutput.Contains("non-repairable", StringComparison.OrdinalIgnoreCase) ||
                            healthOutput.Contains("not repairable", StringComparison.OrdinalIgnoreCase) ||
                            healthOutput.Contains("cannot be repaired", StringComparison.OrdinalIgnoreCase);
        if (health.ExitCode != 0 || nonRepairable)
        {
            throw new InvalidOperationException(
                $"The running Windows component store failed its read-only source compatibility check (DISM CheckHealth exit code {health.ExitCode}). {healthOutput.Trim()}");
        }

        var details = $"The online repair target matches the detected Windows 11 {installation.Edition} {installation.Architecture} installation, version {installation.Version}, build {installation.Build}. The local Microsoft-signed DISM/SFC binaries and component-store state passed verification. DISM RestoreHealth will use the Windows servicing repair source selected by Windows policy (Windows Update by default); Windows Update supplies only payloads applicable to this installation. No Windows installation image will be downloaded and no feature upgrade will be started.";
        log($"Verified Windows repair source. DISM signer: {dismSigner}. SFC signer: {sfcSigner}. {details}");
        _windowsRepairSourceVerified = true;
        return new WindowsRepairSourceVerification(dismSigner, sfcSigner, details);
    }

    private static string ReadRegistryString(RegistryKey key, string name) =>
        key.GetValue(name)?.ToString()?.Trim() ?? string.Empty;

    public IReadOnlyList<DriveInfo> GetLocalDrives()
    {
        return DriveInfo.GetDrives()
            .Where(drive => drive.DriveType is DriveType.Fixed or DriveType.Removable)
            .Where(drive =>
            {
                try { return drive.IsReady; }
                catch (IOException) { return false; }
                catch (UnauthorizedAccessException) { return false; }
            })
            .OrderBy(drive => drive.Name, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    public CleanupScan ScanCleanup()
    {
        OperationCancellationContext.ThrowIfCancellationRequested();
        var drives = GetLocalDrives();
        log($"Detected {drives.Count} accessible local drive(s): {string.Join(", ", drives.Select(drive => drive.Name))}");

        var categories = new List<CleanupCategory>();
        AddCategory(categories, "User temporary files", Path.GetTempPath());

        var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (!string.IsNullOrWhiteSpace(local))
            AddCategory(categories, "User Internet cache", Path.Combine(local, "Microsoft", "Windows", "INetCache"));

        var cutoff = DateTime.UtcNow - MinimumAge;
        foreach (var category in categories)
        {
            OperationCancellationContext.ThrowIfCancellationRequested();
            if (!Directory.Exists(category.Path))
            {
                log($"Cleanup location not available; skipped: {category.Path}");
                continue;
            }

            ScanDirectory(category, cutoff);
            log($"{category.Name}: {category.Files.Count} eligible file(s), {FormatBytes(category.Bytes)}");
        }

        log("Manual cleanup scan only considers the current user's whitelisted temp/cache folders and files with both access and modification times at least 10 days old. System-wide Windows temp and update cleanup are left to Windows Disk Cleanup. Personal folders are never scanned.");
        return new CleanupScan(categories, drives.Count);
    }

    private static void AddCategory(List<CleanupCategory> categories, string name, string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return;

        var fullPath = Path.GetFullPath(path);
        if (categories.All(category => !string.Equals(category.Path, fullPath, StringComparison.OrdinalIgnoreCase)))
            categories.Add(new CleanupCategory(name, fullPath));
    }

    private void ScanDirectory(CleanupCategory category, DateTime cutoffUtc)
    {
        var pending = new Stack<string>();
        pending.Push(category.Path);

        while (pending.Count > 0)
        {
            OperationCancellationContext.ThrowIfCancellationRequested();
            var directory = pending.Pop();
            try
            {
                if ((File.GetAttributes(directory) & FileAttributes.ReparsePoint) != 0)
                    continue;
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                log($"Skipped cleanup directory that could not be inspected '{directory}': {exception.Message}");
                continue;
            }

            try
            {
                foreach (var child in Directory.EnumerateFileSystemEntries(directory))
                {
                    OperationCancellationContext.ThrowIfCancellationRequested();
                    try
                    {
                        var attributes = File.GetAttributes(child);
                        if ((attributes & FileAttributes.ReparsePoint) != 0)
                            continue;

                        if ((attributes & FileAttributes.Directory) != 0)
                        {
                            pending.Push(child);
                            continue;
                        }

                        var info = new FileInfo(child);
                        if (info.LastAccessTimeUtc <= cutoffUtc && info.LastWriteTimeUtc <= cutoffUtc)
                            category.Files.Add(new CleanupFile(info.FullName, info.Length));
                    }
                    catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException)
                    {
                        log($"Skipped file that could not be inspected '{child}': {exception.Message}");
                    }
                }
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                log($"Skipped inaccessible cleanup directory '{directory}': {exception.Message}");
            }
        }
    }

    public long CleanFiles(CleanupScan scan)
    {
        long removedBytes = 0;
        var cutoff = DateTime.UtcNow - MinimumAge;
        foreach (var category in scan.Categories)
        {
            foreach (var candidate in category.Files)
            {
                OperationCancellationContext.ThrowIfCancellationRequested();
                try
                {
                    var fullPath = Path.GetFullPath(candidate.Path);
                    var root = Path.GetFullPath(category.Path).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
                    if (!fullPath.StartsWith(root, StringComparison.OrdinalIgnoreCase))
                    {
                        log($"Safety check rejected a path outside its cleanup folder: {fullPath}");
                        continue;
                    }
                    if (HasReparsePointInParentPath(category.Path, fullPath))
                    {
                        log($"Skipped file whose parent path contains a reparse point: {fullPath}");
                        continue;
                    }

                    var attributes = File.GetAttributes(fullPath);
                    if ((attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
                        continue;

                    var info = new FileInfo(fullPath);
                    if (info.LastAccessTimeUtc > cutoff || info.LastWriteTimeUtc > cutoff)
                    {
                        log($"Skipped file that no longer meets the age check: {fullPath}");
                        continue;
                    }
                    if (info.IsReadOnly)
                    {
                        log($"Skipped read-only temporary file: {fullPath}");
                        continue;
                    }

                    var size = info.Length;
                    File.Delete(fullPath);
                    removedBytes += size;
                }
                catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException)
                {
                    log($"Could not remove '{candidate.Path}': {exception.Message}");
                }
            }

            log($"Cleanup finished for {category.Name}; removed {FormatBytes(removedBytes)} total so far.");
        }

        log($"Temporary-file cleanup recovered approximately {FormatBytes(removedBytes)}.");
        return removedBytes;
    }

    private static bool HasReparsePointInParentPath(string root, string filePath)
    {
        var current = Path.GetFullPath(root);
        if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
            return true;

        var parent = Path.GetDirectoryName(filePath)
            ?? throw new IOException($"Could not determine the parent folder of '{filePath}'.");
        var relative = Path.GetRelativePath(current, parent);
        if (relative == ".")
            return false;
        foreach (var segment in relative.Split([Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar], StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, segment);
            if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                return true;
        }
        return false;
    }

    public async Task CreateRestorePointAsync()
    {
        OperationCancellationContext.ThrowIfCancellationRequested();
        const string script = """
            $ErrorActionPreference = 'Stop'
            Checkpoint-Computer -Description 'Winvexa before maintenance' -RestorePointType MODIFY_SETTINGS
            'Restore point created.'
            """;
        var result = await RunPowerShellAsync(script, stopPolicy: ProcessStopPolicy.FinishCurrentOperation);
        EnsureSuccess("Restore point", result);
        log(result.Output.Trim());
    }

    public async Task<DriveHealthSummary> CheckDriveHealthAsync()
    {
        OperationCancellationContext.ThrowIfCancellationRequested();
        var drives = GetLocalDrives();
        var checkedDrives = 0;
        var issues = 0;
        var skipped = 0;
        var failed = 0;
        foreach (var drive in drives)
        {
            OperationCancellationContext.ThrowIfCancellationRequested();
            try
            {
                OperationCancellationContext.ThrowIfCancellationRequested();
                log($"Drive {drive.Name}: capacity {FormatBytes(drive.TotalSize)}, free {FormatBytes(drive.TotalFreeSpace)}");
                if (!string.Equals(drive.DriveFormat, "NTFS", StringComparison.OrdinalIgnoreCase))
                {
                    log($"Drive {drive.Name}: Windows online scan is not run because the file system is '{drive.DriveFormat}'. No repair command was started.");
                    skipped++;
                    continue;
                }

                var result = await RunProcessAsync(
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "chkdsk.exe"),
                    [drive.Name]);
                if (result.ExitCode is 0 or 1)
                    checkedDrives++;
                if (result.ExitCode == 1)
                    issues++;
                else if (result.ExitCode != 0)
                    failed++;
                log(result.ExitCode == 0
                    ? $"Drive {drive.Name} Healthy — no file-system error was reported by the read-only scan."
                    : result.ExitCode == 1
                        ? $"Drive {drive.Name} reported a file-system issue (CHKDSK exit code 1); review the output. No repair was attempted."
                        : $"Drive {drive.Name} could not be checked (CHKDSK exit code {result.ExitCode}); this does not confirm a file-system error. No repair was attempted.");
                if (!string.IsNullOrWhiteSpace(result.Output))
                    log(result.Output.Trim());
                if (!string.IsNullOrWhiteSpace(result.Error))
                    log($"Drive {drive.Name} diagnostic: {result.Error.Trim()}");
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or InvalidOperationException or System.ComponentModel.Win32Exception)
            {
                failed++;
                log($"Drive {drive.Name}: health check failed and no repair was attempted: {exception.Message}");
            }
        }

        OperationCancellationContext.ThrowIfCancellationRequested();
        const string diskScript = """
            $ErrorActionPreference = 'Stop'
            try {
              $disks = @(Get-PhysicalDisk -ErrorAction Stop | Select-Object FriendlyName, HealthStatus, OperationalStatus)
              [pscustomobject]@{ Available = $true; Disks = $disks; Error = $null } | ConvertTo-Json -Compress -Depth 4
            } catch {
              [pscustomobject]@{ Available = $false; Disks = @(); Error = $_.Exception.Message } | ConvertTo-Json -Compress -Depth 4
            }
            """;
        var health = await RunPowerShellAsync(diskScript);
        var physicalDisksChecked = 0;
        if (health.ExitCode == 0 && !string.IsNullOrWhiteSpace(health.Output))
        {
            try
            {
                using var document = JsonDocument.Parse(health.Output.Trim());
                var root = document.RootElement;
                if (!root.GetProperty("Available").GetBoolean())
                {
                    log($"Windows physical-disk health is unavailable: {root.GetProperty("Error").GetString()}");
                }
                else
                {
                    foreach (var disk in root.GetProperty("Disks").EnumerateArray())
                    {
                        physicalDisksChecked++;
                        var name = disk.GetProperty("FriendlyName").GetString() ?? "Unknown disk";
                        var status = disk.GetProperty("HealthStatus").ToString();
                        var operational = disk.GetProperty("OperationalStatus").ToString();
                        log($"Physical disk '{name}': health={status}, operational={operational}.");
                        if (!status.Equals("Healthy", StringComparison.OrdinalIgnoreCase) &&
                            !status.Equals("Unknown", StringComparison.OrdinalIgnoreCase))
                        {
                            issues++;
                            log($"Physical disk '{name}' reports a non-healthy status; review its health before relying on the drive.");
                        }
                    }
                    if (physicalDisksChecked == 0)
                        log("Windows reports no physical disks through its Storage provider.");
                }
            }
            catch (JsonException exception)
            {
                failed++;
                log($"Windows physical-disk health returned unreadable data: {exception.Message}");
            }
        }
        else
        {
            failed++;
            log($"Windows physical-disk health could not be queried: {health.Error} {health.Output}".Trim());
        }
        return new DriveHealthSummary(checkedDrives, issues, skipped, physicalDisksChecked, failed);
    }

    public async Task<DefenderSecurityStatus> GetDefenderSecurityStatusAsync()
    {
        OperationCancellationContext.ThrowIfCancellationRequested();
        log("Checking Microsoft Defender Antivirus and Windows Security-reported protection status.");
        const string script = """
            $ErrorActionPreference = 'Stop'
            $ProgressPreference = 'SilentlyContinue'
            $status = Get-MpComputerStatus -ErrorAction Stop
            $threats = @(Get-MpThreat -ErrorAction Stop)
            $activeThreats = @($threats |
              Where-Object { $_.IsActive -eq $true } |
              Select-Object -First 20 ThreatID, ThreatName, SeverityID, IsActive)
            $recentRaw = @(Get-MpThreatDetection -ErrorAction Stop |
              Sort-Object -Property InitialDetectionTime -Descending |
              Select-Object -First 20 ThreatID, InitialDetectionTime, ActionSuccess, Resources)
            $recentDetections = @(foreach ($detection in $recentRaw) {
              $threat = $threats | Where-Object { $_.ThreatID -eq $detection.ThreatID } | Select-Object -First 1
              $threatName = 'Name unavailable'
              $severity = 'Unavailable'
              if ($null -ne $threat) {
                $threatName = $threat.ThreatName
                $severity = $threat.SeverityID
              }
              [pscustomobject]@{
                ThreatID = $detection.ThreatID
                ThreatName = $threatName
                SeverityID = $severity
                InitialDetectionTime = $detection.InitialDetectionTime
                ActionSuccess = $detection.ActionSuccess
                Resources = $detection.Resources -join '; '
              }
            })
            $result = [pscustomobject]@{
              AntivirusEnabled = $status.AntivirusEnabled
              AntispywareEnabled = $status.AntispywareEnabled
              ServiceEnabled = $status.AMServiceEnabled
              RealTimeProtectionEnabled = $status.RealTimeProtectionEnabled
              BehaviorMonitorEnabled = $status.BehaviorMonitorEnabled
              IoavProtectionEnabled = $status.IoavProtectionEnabled
              NetworkInspectionEnabled = $status.NISEnabled
              IsTamperProtected = $status.IsTamperProtected
              RunningMode = $status.AMRunningMode
              EngineVersion = $status.AMEngineVersion
              SignatureVersion = $status.AntivirusSignatureVersion
              SignatureAgeDays = $status.AntivirusSignatureAge
              SignatureLastUpdated = $status.AntivirusSignatureLastUpdated
              LastQuickScan = $status.QuickScanEndTime
              LastFullScan = $status.FullScanEndTime
              ActiveThreats = $activeThreats
              RecentDetections = $recentDetections
            }
            $result | ConvertTo-Json -Compress -Depth 5
            """;
        var result = await RunPowerShellAsync(script);
        EnsureSuccess("Microsoft Defender security status check", result);

        try
        {
            using var document = JsonDocument.Parse(result.Output.Trim());
            var root = document.RootElement;
            var activeThreats = ParseDefenderThreats(root.GetProperty("ActiveThreats"), true);
            var recentDetections = ParseDefenderThreats(root.GetProperty("RecentDetections"), false);
            var status = new DefenderSecurityStatus(
                GetBoolean(root, "AntivirusEnabled"),
                GetBoolean(root, "AntispywareEnabled"),
                GetBoolean(root, "ServiceEnabled"),
                GetBoolean(root, "RealTimeProtectionEnabled"),
                GetBoolean(root, "BehaviorMonitorEnabled"),
                GetBoolean(root, "IoavProtectionEnabled"),
                GetBoolean(root, "NetworkInspectionEnabled"),
                GetBoolean(root, "IsTamperProtected"),
                GetString(root, "RunningMode"),
                GetString(root, "EngineVersion"),
                GetString(root, "SignatureVersion"),
                GetNullableInt32(root, "SignatureAgeDays"),
                GetNullableDateTimeOffset(root, "SignatureLastUpdated"),
                GetNullableDateTimeOffset(root, "LastQuickScan"),
                GetNullableDateTimeOffset(root, "LastFullScan"),
                activeThreats,
                recentDetections);
            log($"Microsoft Defender verification: overall={status.OverallStatus}; service={status.ServiceEnabled}; antivirus={status.AntivirusEnabled}; real-time={status.RealTimeProtectionEnabled}; mode={status.RunningMode}; intelligence version={status.SignatureVersion}; age={status.SignatureAgeDays?.ToString() ?? "unavailable"} day(s); active threats={status.ActiveThreats.Count}; recent detections={status.RecentDetections.Count}.");
            return status;
        }
        catch (Exception exception) when (exception is JsonException or InvalidOperationException or FormatException)
        {
            throw new InvalidOperationException(
                $"Windows returned incomplete or unreadable Microsoft Defender status data. Security status is unable to verify. Details: {exception.Message} Output: {result.Output}",
                exception);
        }
    }

    public async Task CheckDefenderAsync()
    {
        OperationCancellationContext.ThrowIfCancellationRequested();
        const string script = """
            $ErrorActionPreference = 'Stop'
            $status = Get-MpComputerStatus
            if (-not $status.AMServiceEnabled -or -not $status.AntivirusEnabled) {
              throw 'Microsoft Defender Antivirus is not active or available. No scan was started.'
            }
            if ($status.AMRunningMode -ne 'Normal') {
              throw "Microsoft Defender Antivirus is not in active mode (mode: $($status.AMRunningMode)). No scan was started."
            }
            [pscustomobject]@{
              AMServiceEnabled = $status.AMServiceEnabled
              AntivirusEnabled = $status.AntivirusEnabled
              RealTimeProtectionEnabled = $status.RealTimeProtectionEnabled
              AMRunningMode = $status.AMRunningMode
              AntivirusSignatureLastUpdated = $status.AntivirusSignatureLastUpdated
            } | ConvertTo-Json -Compress
            """;
        var result = await RunPowerShellAsync(script);
        EnsureSuccess("Microsoft Defender status check", result);
        log($"Microsoft Defender status: {result.Output.Trim()}");
    }

    public async Task UpdateDefenderSignaturesAsync()
    {
        OperationCancellationContext.ThrowIfCancellationRequested();
        await CheckDefenderAsync();
        OperationCancellationContext.ThrowIfCancellationRequested();
        const string script = """
            $ErrorActionPreference = 'Stop'
            Update-MpSignature
            $status = Get-MpComputerStatus
            "Security intelligence update command succeeded. Windows reports signature $($status.AntivirusSignatureVersion), last updated $($status.AntivirusSignatureLastUpdated)."
            """;
        var result = await RunPowerShellAsync(script, stopPolicy: ProcessStopPolicy.FinishCurrentOperation);
        EnsureSuccess("Microsoft Defender signature update", result);
        log(result.Output.Trim());
    }

    public async Task<string> RunDefenderScanAsync(bool fullScan)
        => await RunDefenderScanAsync(fullScan, null);

    public async Task<string> RunDefenderScanAsync(bool fullScan, string? targetPath)
    {
        OperationCancellationContext.ThrowIfCancellationRequested();
        await CheckDefenderAsync();
        OperationCancellationContext.ThrowIfCancellationRequested();
        var executable = FindDefenderCommand();
        var scanStartedUtc = DateTime.UtcNow;
        var scanType = string.IsNullOrWhiteSpace(targetPath) ? fullScan ? "Full" : "Quick" : "Custom";
        log($"Starting Microsoft Defender {scanType} Scan{(string.IsNullOrWhiteSpace(targetPath) ? string.Empty : $" for '{targetPath}'")}.");
        var arguments = string.IsNullOrWhiteSpace(targetPath)
            ? new[] { "-Scan", "-ScanType", fullScan ? "2" : "1" }
            : new[] { "-Scan", "-ScanType", "3", "-File", targetPath };
        CommandResult result;
        try
        {
            result = await RunProcessAsync(
                executable,
                arguments,
                stopPolicy: ProcessStopPolicy.FinishCurrentOperation,
                stopAction: () => CancelDefenderScanAsync(executable));
        }
        catch (ProcessStopRequestedException)
        {
            const string stopped = "Scan stopped — Microsoft Defender accepted the cancellation request and its scan process exited. The result is incomplete; review Protection history in Windows Security.";
            log(stopped);
            return stopped;
        }
        if (OperationCancellationContext.IsCancellationRequested)
        {
            const string completed = "Microsoft Defender scan process completed before the Stop request could be sent. Its finding summary was not collected; review Protection history in Windows Security.";
            log(completed);
            return completed;
        }
        if (result.ExitCode != 0)
            throw new InvalidOperationException($"Microsoft Defender scan failed with exit code {result.ExitCode}. {result.Error} {result.Output}".Trim());
        log($"Microsoft Defender {scanType} Scan completed. MpCmdRun exit code: {result.ExitCode}.");
        if (!string.IsNullOrWhiteSpace(result.Output))
            log(result.Output.Trim());
        var scanStartedText = scanStartedUtc.ToString("O", System.Globalization.CultureInfo.InvariantCulture);
        var resultScript = $$"""
            $ErrorActionPreference = 'Stop'
            $scanStarted = [DateTime]::Parse('{{scanStartedText}}', [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind)
            $detections = @(Get-MpThreatDetection | Where-Object {
              $_.InitialDetectionTime -and ([DateTime]$_.InitialDetectionTime).ToUniversalTime() -ge $scanStarted
            })
            if ($detections.Count -eq 0) {
              [pscustomobject]@{ Count = 0; Detections = @() } | ConvertTo-Json -Compress
            } else {
              $items = @()
              foreach ($detection in $detections) {
                $threat = Get-MpThreat -ThreatID $detection.ThreatID -ErrorAction SilentlyContinue
                $items += [pscustomobject]@{
                  ThreatId = $detection.ThreatID
                  ThreatName = ($threat.ThreatName -join ', ')
                  ActionSuccess = $detection.ActionSuccess
                  ThreatStatusId = $detection.ThreatStatusID
                }

              }
              [pscustomobject]@{ Count = $items.Count; Detections = $items } | ConvertTo-Json -Compress -Depth 4
            }
            """;
        var scanResult = await RunPowerShellAsync(resultScript);
        if (scanResult.ExitCode != 0)
        {
            var unavailable = $"Defender scan completed, but its finding summary is unavailable (exit code {scanResult.ExitCode}): {scanResult.Error} {scanResult.Output}".Trim();
            log(unavailable);
            return unavailable;
        }

        try
        {
            using var document = JsonDocument.Parse(scanResult.Output.Trim());
            var count = document.RootElement.GetProperty("Count").GetInt32();
            if (count == 0)
            {
                const string clean = "Microsoft Defender completed the scan and reported no new detections during the scan window.";
                log(clean);
                return clean;
            }
            log($"Microsoft Defender reported {count} detection(s) from this scan:");
            foreach (var detection in document.RootElement.GetProperty("Detections").EnumerateArray())
                log($"Threat {detection.GetProperty("ThreatId")}: {detection.GetProperty("ThreatName").GetString()}, action successful: {detection.GetProperty("ActionSuccess")}.");
            return $"Microsoft Defender completed the scan and reported {count} detection(s). Review the activity log for threat names and remediation status.";
        }
        catch (JsonException exception)
        {
            var unavailable = $"Defender scan completed, but the finding summary could not be read: {exception.Message}. Output: {scanResult.Output}";
            log(unavailable);
            return unavailable;
        }
    }

    private async Task CancelDefenderScanAsync(string executable)
    {
        var startInfo = new ProcessStartInfo(executable)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        startInfo.ArgumentList.Add("-Scan");
        startInfo.ArgumentList.Add("-Cancel");
        var result = await CancellableProcessRunner.RunAsync(
            startInfo,
            "Microsoft Defender scan cancellation",
            log,
            CancellationToken.None,
            ProcessStopPolicy.TerminateProcessTree,
            TimeSpan.FromSeconds(45));
        EnsureSuccess("Microsoft Defender scan cancellation request", result);
        log("Microsoft Defender accepted the scan cancellation request; waiting for its scan process to exit.");
    }

    private static IReadOnlyList<DefenderThreatInfo> ParseDefenderThreats(JsonElement items, bool active)
    {
        if (items.ValueKind == JsonValueKind.Null)
            return [];
        IEnumerable<JsonElement> values = items.ValueKind == JsonValueKind.Array
            ? items.EnumerateArray().ToArray()
            : [items];
        return values.Select(item => new DefenderThreatInfo(
                GetString(item, "ThreatID"),
                GetString(item, "ThreatName"),
                GetString(item, "SeverityID"),
                GetNullableDateTimeOffset(item, "InitialDetectionTime"),
                item.TryGetProperty("ActionSuccess", out var actionSucceeded) &&
                actionSucceeded.ValueKind is not (JsonValueKind.Null or JsonValueKind.Undefined)
                    ? actionSucceeded.GetBoolean()
                    : null,
                GetString(item, "Resources")))
            .Select(threat => active ? threat with { ActionSucceeded = null } : threat)
            .ToArray();
    }

    private static bool GetBoolean(JsonElement element, string propertyName) =>
        element.GetProperty(propertyName).ValueKind switch
        {
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            _ => throw new InvalidOperationException($"Windows did not return a Boolean value for {propertyName}.")
        };

    private static string GetString(JsonElement element, string propertyName)
    {
        if (!element.TryGetProperty(propertyName, out var property) ||
            property.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined)
            return "Unavailable";
        return property.ValueKind == JsonValueKind.String ? property.GetString() ?? "Unavailable" : property.ToString();
    }

    private static int? GetNullableInt32(JsonElement element, string propertyName)
    {
        if (!element.TryGetProperty(propertyName, out var property) ||
            property.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined)
            return null;
        if (property.TryGetInt32(out var value))
            return value;
        return int.TryParse(property.ToString(), out value) ? value : null;
    }

    private static DateTimeOffset? GetNullableDateTimeOffset(JsonElement element, string propertyName)
    {
        if (!element.TryGetProperty(propertyName, out var property) ||
            property.ValueKind is JsonValueKind.Null or JsonValueKind.Undefined)
            return null;
        var text = property.ValueKind == JsonValueKind.String ? property.GetString() : property.ToString();
        if (text is not null &&
            text.StartsWith("/Date(", StringComparison.Ordinal) &&
            text.EndsWith(")/", StringComparison.Ordinal))
        {
            var dateValue = text[6..^2];
            var offsetIndex = dateValue.AsSpan(1).IndexOfAny('+', '-');
            if (offsetIndex >= 0)
                dateValue = dateValue[..(offsetIndex + 1)];
            if (long.TryParse(
                    dateValue,
                    System.Globalization.NumberStyles.Integer,
                    System.Globalization.CultureInfo.InvariantCulture,
                    out var milliseconds))
            {
                try
                {
                    return DateTimeOffset.FromUnixTimeMilliseconds(milliseconds);
                }
                catch (ArgumentOutOfRangeException)
                {
                    return null;
                }
            }
        }
        return DateTimeOffset.TryParse(
            text,
            System.Globalization.CultureInfo.InvariantCulture,
            System.Globalization.DateTimeStyles.AssumeLocal,
            out var value)
            ? value
            : null;
    }

    private static string FindDefenderCommand()
    {
        var defender = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Windows Defender", "MpCmdRun.exe");
        if (File.Exists(defender))
            return defender;

        var platform = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Microsoft", "Windows Defender", "Platform");
        if (Directory.Exists(platform))
        {
            var candidates = Directory.GetDirectories(platform)
                .OrderByDescending(path => Path.GetFileName(path), StringComparer.OrdinalIgnoreCase);
            foreach (var candidate in candidates)
            {
                var path = Path.Combine(candidate, "MpCmdRun.exe");
                if (File.Exists(path))
                    return path;
            }
        }

        throw new FileNotFoundException("Microsoft Defender's MpCmdRun.exe was not found. Defender scan is unavailable.");
    }

    public async Task<long?> LaunchWindowsCleanupAsync(string drive = "")
    {
        OperationCancellationContext.ThrowIfCancellationRequested();
        var executable = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cleanmgr.exe");
        if (!File.Exists(executable))
            throw new FileNotFoundException("Windows Disk Cleanup (cleanmgr.exe) is not available on this system.");

        var target = string.IsNullOrWhiteSpace(drive)
            ? Environment.GetEnvironmentVariable("SystemDrive") ?? "C:"
            : drive;
        long? freeBefore = null;
        try
        {
            var volume = new DriveInfo(target.TrimEnd('\\', '/') + Path.DirectorySeparatorChar);
            if (volume.IsReady)
                freeBefore = volume.AvailableFreeSpace;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException)
        {
            log($"Could not measure free space before Windows Disk Cleanup on {target}: {exception.Message}");
        }

        using var process = new Process
        {
            StartInfo = new ProcessStartInfo(executable)
            {
                UseShellExecute = true,
                ArgumentList = { "/d", target }
            }
        };
        try
        {
            if (!process.Start())
                throw new InvalidOperationException("Windows Disk Cleanup did not start.");
            log($"Started Windows Disk Cleanup for {target} (process {process.Id}).");
            var exitTask = process.WaitForExitAsync();
            var cancellationToken = OperationCancellationContext.Token;
            if (cancellationToken.CanBeCanceled)
            {
                var cancellationTask = Task.Delay(System.Threading.Timeout.InfiniteTimeSpan, cancellationToken);
                if (await Task.WhenAny(exitTask, cancellationTask) == cancellationTask)
                {
                    log($"Stop requested during Windows Disk Cleanup for {target}; terminating the Winvexa-launched cleanup process.");
                    CancellableProcessRunner.TerminateProcessTree(process, $"Windows Disk Cleanup for {target}", log);
                }
            }
            await exitTask;
            cancellationToken.ThrowIfCancellationRequested();
        }
        catch (Exception exception) when (exception is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            throw new InvalidOperationException($"Could not run Windows Disk Cleanup: {exception.Message}", exception);
        }
        if (process.ExitCode != 0)
            throw new InvalidOperationException($"Windows Disk Cleanup exited with code {process.ExitCode}.");
        long? recovered = null;
        if (freeBefore.HasValue)
        {
            try
            {
                var volume = new DriveInfo(target.TrimEnd('\\', '/') + Path.DirectorySeparatorChar);
                if (volume.IsReady && volume.AvailableFreeSpace > freeBefore.Value)
                    recovered = volume.AvailableFreeSpace - freeBefore.Value;
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException)
            {
                log($"Could not measure free space after Windows Disk Cleanup on {target}: {exception.Message}");
            }
        }
        log(recovered.HasValue
            ? $"Windows Disk Cleanup completed for {target}. Free space increased by approximately {FormatBytes(recovered.Value)}; background disk activity may affect this estimate."
            : $"Windows Disk Cleanup completed for {target}. No free-space increase could be measured. Windows presented its supported cleanup choices; selected categories are controlled in the Windows dialog.");
        return recovered;
    }

    public async Task<WindowsUpdateDiagnostics> DiagnoseWindowsUpdateAsync()
    {
        const string script = """
            $ErrorActionPreference = 'Stop'
            $serviceNames = @('wuauserv', 'bits', 'cryptsvc', 'usosvc')
            $services = @()
            $warnings = @()
            foreach ($name in $serviceNames) {
              try {
                $service = Get-CimInstance Win32_Service -Filter "Name='$name'" -ErrorAction Stop
                if ($null -ne $service) {
                  $services += [pscustomobject]@{
                    Name = $service.Name
                    DisplayName = $service.DisplayName
                    State = $service.State
                    StartMode = $service.StartMode
                  }
                } else {
                  $services += [pscustomobject]@{ Name = $name; DisplayName = $name; State = 'Unavailable'; StartMode = 'Unknown' }
                }
              } catch {
                $warnings += "$name could not be inspected: $($_.Exception.Message)"
                $services += [pscustomobject]@{ Name = $name; DisplayName = $name; State = 'QueryFailed'; StartMode = 'Unknown' }
              }
            }

            $restartRequired = $false
            $restartPaths = @(
              'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
              'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
            )
            foreach ($path in $restartPaths) {
              if (Test-Path -LiteralPath $path) { $restartRequired = $true }
            }
            try {
              $sessionManager = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction Stop
              if ($sessionManager.PendingFileRenameOperations) { $restartRequired = $true }
            } catch {
              if ($_.Exception.Message -notmatch 'cannot find path|does not exist|cannot find.*property') {
                $warnings += "Pending restart state could not be fully inspected: $($_.Exception.Message)"
              }
            }

            $pendingUpdates = @()
            $searchError = $null
            $searchHResult = $null
            $session = $null
            $searcher = $null
            try {
              $session = New-Object -ComObject Microsoft.Update.Session
              $searcher = $session.CreateUpdateSearcher()
              $search = $searcher.Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
              for ($i = 0; $i -lt $search.Updates.Count; $i++) {
                $update = $search.Updates.Item($i)
                $pendingUpdates += [pscustomobject]@{
                  Title = $update.Title
                  UpdateId = $update.Identity.UpdateID
                  RevisionNumber = [int]$update.Identity.RevisionNumber
                }
              }
              if ([int]$search.ResultCode -ne 2) {
                $searchError = "Windows Update Agent search returned result code $([int]$search.ResultCode)."
              } else {
                $searchHResult = '0x00000000'
              }
              try {
                if ((New-Object -ComObject Microsoft.Update.SystemInfo).RebootRequired) { $restartRequired = $true }
              } catch {
                $warnings += "Windows Update restart state could not be queried: $($_.Exception.Message)"
              }
            } catch {
              $searchError = $_.Exception.Message
              $searchHResult = '0x{0:X8}' -f ($_.Exception.HResult -band 0xffffffffL)
            }

            $recentFailures = @()
            if ($null -ne $searcher) {
              try {
                $history = $searcher.QueryHistory(0, 100)
                $cutoff = (Get-Date).AddDays(-30)
                for ($i = 0; $i -lt $history.Count; $i++) {
                  $entry = $history.Item($i)
                  if ($entry.Date -ge $cutoff -and [int]$entry.Operation -eq 1 -and [int]$entry.ResultCode -in 4, 5) {
                    $recentFailures += [pscustomobject]@{
                      Date = $entry.Date.ToString('o')
                      Title = $entry.Title
                      ResultCode = [int]$entry.ResultCode
                      HResult = '0x{0:X8}' -f ($entry.HResult -band 0xffffffffL)
                    }
                  }
                }
              } catch {
                $warnings += "Windows Update history could not be read: $($_.Exception.Message)"
              }
            }

            $recentEventErrors = @()
            try {
              $events = Get-WinEvent -FilterHashtable @{
                LogName = 'Microsoft-Windows-WindowsUpdateClient/Operational'
                Level = 2
                StartTime = (Get-Date).AddDays(-30)
              } -MaxEvents 25 -ErrorAction Stop
              foreach ($event in $events) {
                $message = [string]$event.Message
                $match = [regex]::Match($message, '0x[0-9A-Fa-f]{8}')
                $hresult = if ($match.Success) { $match.Value.ToUpperInvariant() } else { '' }
                $recentEventErrors += [pscustomobject]@{
                  Date = $event.TimeCreated.ToString('o')
                  EventId = [int]$event.Id
                  HResult = $hresult
                  Message = $message
                }
              }
            } catch {
              $warnings += "Windows Update event log could not be read (it may be empty or unavailable): $($_.Exception.Message)"
            }

            [pscustomobject]@{
              Services = $services
              RecentFailures = $recentFailures
              RecentEventErrors = $recentEventErrors
              PendingUpdates = $pendingUpdates
              DiagnosticWarnings = $warnings
              RestartRequired = $restartRequired
              SearchError = $searchError
              SearchHResult = $searchHResult
            } | ConvertTo-Json -Compress -Depth 6
            """;
        var result = await RunPowerShellAsync(script, stopPolicy: ProcessStopPolicy.FinishCurrentOperation);
        EnsureSuccess("Windows Update diagnostics", result);

        try
        {
            using var document = JsonDocument.Parse(result.Output.Trim());
            var root = document.RootElement;
            var services = root.GetProperty("Services").EnumerateArray()
                .Select(item => new UpdateServiceDiagnostic(
                    item.GetProperty("Name").GetString() ?? "Unknown",
                    item.GetProperty("DisplayName").GetString() ?? "Unknown",
                    item.GetProperty("State").GetString() ?? "Unknown",
                    item.GetProperty("StartMode").GetString() ?? "Unknown"))
                .ToArray();
            var failures = root.GetProperty("RecentFailures").EnumerateArray()
                .Select(item => new UpdateHistoryFailure(
                    item.GetProperty("Date").GetString() ?? string.Empty,
                    item.GetProperty("Title").GetString() ?? "(untitled update)",
                    item.GetProperty("ResultCode").GetInt32(),
                    item.GetProperty("HResult").GetString() ?? string.Empty))
                .ToArray();
            var eventErrors = root.GetProperty("RecentEventErrors").EnumerateArray()
                .Select(item => new UpdateEventError(
                    item.GetProperty("Date").GetString() ?? string.Empty,
                    item.GetProperty("EventId").GetInt32(),
                    item.GetProperty("HResult").GetString() ?? string.Empty,
                    item.GetProperty("Message").GetString() ?? string.Empty))
                .ToArray();
            var pendingUpdates = root.GetProperty("PendingUpdates").EnumerateArray()
                .Select(item => new UpdateCandidate(
                    item.GetProperty("Title").GetString() ?? "(untitled update)",
                    item.GetProperty("UpdateId").GetString() ?? string.Empty,
                    item.GetProperty("RevisionNumber").GetInt32()))
                .ToArray();
            var warnings = root.GetProperty("DiagnosticWarnings").EnumerateArray()
                .Select(item => item.GetString() ?? "An update diagnostic could not be completed.")
                .ToArray();
            var diagnostics = new WindowsUpdateDiagnostics(
                services,
                failures,
                eventErrors,
                pendingUpdates,
                warnings,
                root.GetProperty("RestartRequired").GetBoolean(),
                root.GetProperty("SearchError").ValueKind == JsonValueKind.Null ? null : root.GetProperty("SearchError").GetString(),
                root.GetProperty("SearchHResult").ValueKind == JsonValueKind.Null ? null : root.GetProperty("SearchHResult").GetString());

            log($"Windows Update diagnostic summary: service/search operational={diagnostics.IsOperational}, {failures.Length} recent failed installation(s), {eventErrors.Length} recent Windows Update event-log error(s), {pendingUpdates.Length} pending update(s), restart required={diagnostics.RestartRequired}.");
            foreach (var service in services)
                log($"Windows Update service {service.Name}: state={service.State}, start mode={service.StartMode}.");
            foreach (var failure in failures)
                log($"Recent update installation failure [{failure.HResult}] {failure.Date}: {failure.Title} (result {failure.ResultCode}).");
            foreach (var eventError in eventErrors)
                log($"Windows Update event {eventError.EventId} [{eventError.HResult}] {eventError.Date}: {eventError.Message}");
            foreach (var warning in warnings)
                log($"Windows Update diagnostic warning: {warning}");
            if (diagnostics.SearchError is not null)
                log($"Windows Update scan failed [{diagnostics.SearchHResult}]: {diagnostics.SearchError}");
            return diagnostics;
        }
        catch (JsonException exception)
        {
            throw new InvalidOperationException($"Windows Update diagnostics returned unreadable data: {result.Output} {result.Error}", exception);
        }
    }

    public async Task<WindowsUpdateServiceRepairResult> StartWindowsUpdateServicesAsync()
    {
        const string script = """
            $ErrorActionPreference = 'Stop'
            $serviceNames = @('wuauserv', 'bits', 'cryptsvc')
            $errors = @()
            foreach ($name in $serviceNames) {
              try {
                $service = Get-CimInstance Win32_Service -Filter "Name='$name'" -ErrorAction Stop
                if ($null -eq $service) {
                  $errors += "$name is unavailable."
                  continue
                }
                if ($service.StartMode -eq 'Disabled') {
                  $errors += "$name is disabled by Windows or policy; its configuration was not changed."
                  continue
                }
                if ($service.State -ne 'Running') {
                  Start-Service -Name $name -ErrorAction Stop
                  (Get-Service -Name $name -ErrorAction Stop).WaitForStatus('Running', [TimeSpan]::FromSeconds(20))
                }
              } catch {
                $errors += "$name could not be started: $($_.Exception.Message)"
              }
            }
            $services = @()
            foreach ($name in $serviceNames) {
              try {
                $service = Get-CimInstance Win32_Service -Filter "Name='$name'" -ErrorAction Stop
                if ($null -ne $service) {
                  $services += [pscustomobject]@{ Name = $service.Name; DisplayName = $service.DisplayName; State = $service.State; StartMode = $service.StartMode }
                }
              } catch {
                $errors += "$name status could not be verified: $($_.Exception.Message)"
              }
            }
            [pscustomobject]@{ Services = $services; Errors = $errors } | ConvertTo-Json -Compress -Depth 4
            """;
        var result = await RunPowerShellAsync(script, stopPolicy: ProcessStopPolicy.FinishCurrentOperation);
        EnsureSuccess("Windows Update service startup", result);
        using var document = JsonDocument.Parse(result.Output.Trim());
        var root = document.RootElement;
        var services = root.GetProperty("Services").EnumerateArray()
            .Select(item => new UpdateServiceDiagnostic(
                item.GetProperty("Name").GetString() ?? "Unknown",
                item.GetProperty("DisplayName").GetString() ?? "Unknown",
                item.GetProperty("State").GetString() ?? "Unknown",
                item.GetProperty("StartMode").GetString() ?? "Unknown"))
            .ToArray();
        var errors = root.GetProperty("Errors").EnumerateArray()
            .Select(item => item.GetString() ?? "Unknown service error.")
            .ToArray();
        foreach (var service in services)
            log($"Windows Update service verification {service.Name}: state={service.State}, start mode={service.StartMode}.");
        foreach (var error in errors)
            log($"Windows Update service repair: {error}");
        return new WindowsUpdateServiceRepairResult(services, errors);
    }

    public async Task<WindowsUpdateCacheRepairResult> RebuildWindowsUpdateDownloadCacheAsync()
    {
        const string script = """
            $ErrorActionPreference = 'Stop'
            $cache = Join-Path $env:windir 'SoftwareDistribution\Download'
            if (-not (Test-Path -LiteralPath $cache -PathType Container)) {
              [pscustomobject]@{ Success = $true; BackupPath = ''; Services = @(); Error = 'Download cache folder does not exist; no cache changes were made.' } | ConvertTo-Json -Compress
              exit 0
            }
            $parent = Join-Path $env:windir 'SoftwareDistribution'
            $resolvedParent = (Resolve-Path -LiteralPath $parent -ErrorAction Stop).Path
            $resolvedCache = (Resolve-Path -LiteralPath $cache -ErrorAction Stop).Path
            if (-not $resolvedCache.StartsWith($resolvedParent + '\', [StringComparison]::OrdinalIgnoreCase)) {
              throw 'Safety validation rejected a download cache path outside SoftwareDistribution.'
            }
            $backup = Join-Path $resolvedParent ('Download.WinvexaBackup-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
            $restoreNames = @()
            $errors = @()
            $success = $false
            try {
              foreach ($name in @('bits', 'wuauserv')) {
                $service = Get-CimInstance Win32_Service -Filter "Name='$name'" -ErrorAction Stop
                if ($null -eq $service) { throw "Required service $name is unavailable." }
                if ($service.State -eq 'Running') { $restoreNames += $name }
                if ($service.StartMode -eq 'Disabled') { throw "Service $name is disabled; its configuration was not changed." }
                if ($service.State -eq 'Running') {
                  Stop-Service -Name $name -Force -ErrorAction Stop
                  (Get-Service -Name $name -ErrorAction Stop).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(20))
                }
              }
              Move-Item -LiteralPath $resolvedCache -Destination $backup -ErrorAction Stop
              $success = $true
            } catch {
              $errors += $_.Exception.Message
              if ((Test-Path -LiteralPath $backup -PathType Container) -and -not (Test-Path -LiteralPath $resolvedCache)) {
                try { Move-Item -LiteralPath $backup -Destination $resolvedCache -ErrorAction Stop }
                catch { $errors += "Cache rollback failed: $($_.Exception.Message)" }
              }
            } finally {
              foreach ($name in $restoreNames) {
                try {
                  Start-Service -Name $name -ErrorAction Stop
                  (Get-Service -Name $name -ErrorAction Stop).WaitForStatus('Running', [TimeSpan]::FromSeconds(20))
                } catch { $errors += "$name could not be restarted: $($_.Exception.Message)" }
              }
            }
            $states = @()
            foreach ($name in @('bits', 'wuauserv')) {
              try {
                $service = Get-CimInstance Win32_Service -Filter "Name='$name'" -ErrorAction Stop
                if ($null -ne $service) { $states += [pscustomobject]@{ Name = $name; State = $service.State } }
              } catch { $errors += "$name status could not be verified: $($_.Exception.Message)" }
            }
            [pscustomobject]@{
              Success = $success
              BackupPath = $(if ($success) { $backup } else { '' })
              Services = $states
              Error = ($errors -join ' ')
            } | ConvertTo-Json -Compress -Depth 4
            """;
        var result = await RunPowerShellAsync(script, stopPolicy: ProcessStopPolicy.FinishCurrentOperation);
        EnsureSuccess("Windows Update download-cache repair", result);
        using var document = JsonDocument.Parse(result.Output.Trim());
        var root = document.RootElement;
        var success = root.GetProperty("Success").GetBoolean();
        var backup = root.GetProperty("BackupPath").GetString() ?? string.Empty;
        var services = root.GetProperty("Services").EnumerateArray()
            .Select(item => $"{item.GetProperty("Name").GetString()}: {item.GetProperty("State").GetString()}")
            .ToArray();
        var error = root.GetProperty("Error").GetString();
        if (!success)
            throw new InvalidOperationException($"Windows Update download cache was not rebuilt. {error}");
        if (!string.IsNullOrWhiteSpace(error))
            log($"Windows Update download cache was moved to '{backup}', but a service restart/status warning occurred: {error}");
        else
            log($"Windows Update download cache was moved to '{backup}'. The preserved backup was not deleted. Services: {string.Join(", ", services)}.");
        return new WindowsUpdateCacheRepairResult(backup, services);
    }

    public async Task<WindowsSystemRepairResult> RunDismRestoreHealthAsync()
    {
        RequireVerifiedWindowsRepairSource();
        var executable = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "dism.exe");
        var result = await RunProcessAsync(
            executable,
            ["/Online", "/Cleanup-Image", "/RestoreHealth"],
            stopPolicy: ProcessStopPolicy.FinishCurrentOperation);
        log($"DISM RestoreHealth exit code: {result.ExitCode}.");
        if (!string.IsNullOrWhiteSpace(result.Output))
            log($"DISM output: {result.Output.Trim()}");
        if (!string.IsNullOrWhiteSpace(result.Error))
            log($"DISM diagnostic: {result.Error.Trim()}");
        return new WindowsSystemRepairResult(result.ExitCode, result.Output, result.Error);
    }

    public async Task<WindowsSystemRepairResult> RunSystemFileCheckerAsync()
    {
        RequireVerifiedWindowsRepairSource();
        var executable = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "sfc.exe");
        var result = await RunProcessAsync(
            executable,
            ["/scannow"],
            stopPolicy: ProcessStopPolicy.FinishCurrentOperation);
        log($"System File Checker exit code: {result.ExitCode}.");
        if (!string.IsNullOrWhiteSpace(result.Output))
            log($"System File Checker output: {result.Output.Trim()}");
        if (!string.IsNullOrWhiteSpace(result.Error))
            log($"System File Checker diagnostic: {result.Error.Trim()}");
        return new WindowsSystemRepairResult(result.ExitCode, result.Output, result.Error);
    }

    private void RequireVerifiedWindowsRepairSource()
    {
        OperationCancellationContext.ThrowIfCancellationRequested();
        if (!_windowsRepairSourceVerified)
        {
            log("Blocked a Windows repair command because the Microsoft repair source has not been verified for this operation.");
            throw new InvalidOperationException(
                "Windows repair was blocked because the Microsoft repair source has not been verified. Run the Windows repair-source preflight before DISM RestoreHealth or SFC /scannow.");
        }
    }

    public async Task<WindowsSystemRepairResult> RunDismScanHealthAsync()
    {
        var executable = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "dism.exe");
        var result = await RunProcessAsync(executable, ["/Online", "/Cleanup-Image", "/ScanHealth"]);
        log($"DISM ScanHealth exit code: {result.ExitCode}.");
        if (!string.IsNullOrWhiteSpace(result.Output))
            log($"DISM ScanHealth output: {result.Output.Trim()}");
        if (!string.IsNullOrWhiteSpace(result.Error))
            log($"DISM ScanHealth diagnostic: {result.Error.Trim()}");
        return new WindowsSystemRepairResult(result.ExitCode, result.Output, result.Error);
    }

    public async Task<WindowsSystemRepairResult> RunDismCheckHealthAsync()
    {
        var executable = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "dism.exe");
        var result = await RunProcessAsync(executable, ["/Online", "/Cleanup-Image", "/CheckHealth"]);
        log($"DISM CheckHealth exit code: {result.ExitCode}.");
        if (!string.IsNullOrWhiteSpace(result.Output))
            log($"DISM CheckHealth output: {result.Output.Trim()}");
        if (!string.IsNullOrWhiteSpace(result.Error))
            log($"DISM CheckHealth diagnostic: {result.Error.Trim()}");
        return new WindowsSystemRepairResult(result.ExitCode, result.Output, result.Error);
    }

    public async Task<WindowsSystemRepairResult> RunSystemFileVerificationAsync()
    {
        var executable = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "sfc.exe");
        var result = await RunProcessAsync(executable, ["/verifyonly"]);
        log($"System File Checker VerifyOnly exit code: {result.ExitCode}.");
        if (!string.IsNullOrWhiteSpace(result.Output))
            log($"System File Checker VerifyOnly output: {result.Output.Trim()}");
        if (!string.IsNullOrWhiteSpace(result.Error))
            log($"System File Checker VerifyOnly diagnostic: {result.Error.Trim()}");
        return new WindowsSystemRepairResult(result.ExitCode, result.Output, result.Error);
    }

    public async Task<UpdateSearch> SearchWindowsUpdatesAsync()
    {
        const string script = """
            $ErrorActionPreference = 'Stop'
            try {
              $session = New-Object -ComObject Microsoft.Update.Session
              $searcher = $session.CreateUpdateSearcher()
              $result = $searcher.Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
              $updates = @()
              for ($i = 0; $i -lt $result.Updates.Count; $i++) {
                $update = $result.Updates.Item($i)
                $updates += [pscustomobject]@{
                  Title = $update.Title
                  UpdateId = $update.Identity.UpdateID
                  RevisionNumber = [int]$update.Identity.RevisionNumber
                }
              }
              [pscustomobject]@{
                Count = $result.Updates.Count
                Updates = $updates
                ResultCode = [int]$result.ResultCode
                HResult = '0x00000000'
                RebootRequired = $false
                Error = $null
              } | ConvertTo-Json -Compress -Depth 4
            } catch {
              $hr = '0x{0:X8}' -f ($_.Exception.HResult -band 0xffffffffL)
              [pscustomobject]@{ Count = 0; Updates = @(); ResultCode = -1; HResult = $hr; RebootRequired = $false; Error = $_.Exception.Message } | ConvertTo-Json -Compress
              exit 1
            }
            """;
        var result = await RunPowerShellAsync(script, stopPolicy: ProcessStopPolicy.FinishCurrentOperation);
        if (result.ExitCode != 0)
            throw new InvalidOperationException($"Windows Update search failed. {result.Output} {result.Error}".Trim());

        try
        {
            using var document = JsonDocument.Parse(result.Output.Trim());
            var root = document.RootElement;
            var updates = root.GetProperty("Updates").EnumerateArray()
                .Select(item => new UpdateCandidate(
                    item.GetProperty("Title").GetString() ?? "(untitled update)",
                    item.GetProperty("UpdateId").GetString() ?? string.Empty,
                    item.GetProperty("RevisionNumber").GetInt32()))
                .ToArray();
            var search = new UpdateSearch(
                updates,
                root.GetProperty("RebootRequired").GetBoolean(),
                $"Search result code {root.GetProperty("ResultCode").GetInt32()}, HRESULT {root.GetProperty("HResult").GetString()}.");
            if (root.GetProperty("ResultCode").GetInt32() != 2)
                throw new InvalidOperationException($"Windows Update search was not successful. {search.Details} {result.Output} {result.Error}".Trim());
            log($"Windows Update search: {search.Count} applicable update(s). {search.Details}");
            return search;
        }
        catch (JsonException exception)
        {
            throw new InvalidOperationException($"Windows Update returned an unreadable result: {result.Output} {result.Error}", exception);
        }
    }

    public async Task<(bool RebootRequired, int Installed, int Failed, string Details)> InstallWindowsUpdatesAsync(
        IReadOnlyList<UpdateCandidate> approvedUpdates)
    {
        var approvedJson = JsonSerializer.Serialize(approvedUpdates.Select(update => new
        {
            update.UpdateId,
            update.RevisionNumber
        }));
        var approvedBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(approvedJson));
        var script = """
            $ErrorActionPreference = 'Stop'
            try {
              $approvedUpdates = @([System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__APPROVED_UPDATES__')) | ConvertFrom-Json)
              $session = New-Object -ComObject Microsoft.Update.Session
              $searcher = $session.CreateUpdateSearcher()
              $search = $searcher.Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
              $collection = New-Object -ComObject Microsoft.Update.UpdateColl
              for ($i = 0; $i -lt $search.Updates.Count; $i++) {
                $update = $search.Updates.Item($i)
                $approved = $false
                foreach ($candidate in $approvedUpdates) {
                  if ($update.Identity.UpdateID -eq $candidate.UpdateId -and [int]$update.Identity.RevisionNumber -eq [int]$candidate.RevisionNumber) {
                    $approved = $true
                    break
                  }
                }
                if (-not $approved) { continue }
                if (-not $update.EulaAccepted) { $update.AcceptEula() }
                [void]$collection.Add($update)
              }
              if ($collection.Count -eq 0) {
                [pscustomobject]@{ Count = 0; Successful = 0; Failed = 0; ResultCode = 2; HResult = '0x00000000'; RebootRequired = $false; UpdateResults = @(); Error = $null } | ConvertTo-Json -Compress
                exit 0
              }
              $downloader = $session.CreateUpdateDownloader()
              $downloader.Updates = $collection
              $download = $downloader.Download()
              if ([int]$download.ResultCode -notin 2, 3) {
                throw "Update download failed with result code $([int]$download.ResultCode), HRESULT $('0x{0:X8}' -f ($download.HResult -band 0xffffffffL))."
              }
              $installer = $session.CreateUpdateInstaller()
              $installer.Updates = $collection
              $installer.AllowSourcePrompts = $false
              $install = $installer.Install()
              $updateResults = @()
              $successful = 0
              $failed = 0
              for ($i = 0; $i -lt $collection.Count; $i++) {
                $itemResult = $install.GetUpdateResult($i)
                if ([int]$itemResult.ResultCode -eq 2) { $successful++ } else { $failed++ }
                $updateResults += [pscustomobject]@{
                  Title = $collection.Item($i).Title
                  ResultCode = [int]$itemResult.ResultCode
                  HResult = ('0x{0:X8}' -f ($itemResult.HResult -band 0xffffffffL))
                }
              }
              if ([int]$install.ResultCode -notin 2, 3 -and $failed -eq 0) { $failed = $collection.Count }
              [pscustomobject]@{
                Count = $collection.Count
                Successful = $successful
                Failed = $failed
                ResultCode = [int]$install.ResultCode
                HResult = ('0x{0:X8}' -f ($install.HResult -band 0xffffffffL))
                RebootRequired = [bool]$install.RebootRequired
                UpdateResults = $updateResults
                Error = $null
              } | ConvertTo-Json -Compress -Depth 5
            } catch {
              $hr = '0x{0:X8}' -f ($_.Exception.HResult -band 0xffffffffL)
              [pscustomobject]@{ Count = 0; Successful = 0; Failed = 0; ResultCode = -1; HResult = $hr; RebootRequired = $false; UpdateResults = @(); Error = $_.Exception.Message } | ConvertTo-Json -Compress
              exit 1
            }
            """;
        script = script.Replace("__APPROVED_UPDATES__", approvedBase64, StringComparison.Ordinal);
        var result = await RunPowerShellAsync(script, stopPolicy: ProcessStopPolicy.FinishCurrentOperation);
        if (result.ExitCode != 0)
            throw new InvalidOperationException($"Windows Update installation failed. {result.Output} {result.Error}".Trim());

        try
        {
            using var document = JsonDocument.Parse(result.Output.Trim());
            var root = document.RootElement;
            var details = $"Windows Update installation result code {root.GetProperty("ResultCode").GetInt32()}, HRESULT {root.GetProperty("HResult").GetString()}.";
            var rebootRequired = root.GetProperty("RebootRequired").GetBoolean();
            var installed = root.GetProperty("Successful").GetInt32();
            var failed = root.GetProperty("Failed").GetInt32();
            log($"{details} Updates processed: {root.GetProperty("Count").GetInt32()}, installed successfully: {installed}, failed or partial: {failed}. Restart required: {rebootRequired}.");
            foreach (var update in root.GetProperty("UpdateResults").EnumerateArray())
            {
                var title = update.GetProperty("Title").GetString();
                var resultCode = update.GetProperty("ResultCode").GetInt32();
                var hresult = update.GetProperty("HResult").GetString();
                log($"Update '{title}': result code {resultCode}, HRESULT {hresult}.");
            }
            return (rebootRequired, installed, failed, details);
        }
        catch (JsonException exception)
        {
            throw new InvalidOperationException($"Windows Update returned an unreadable installation result: {result.Output} {result.Error}", exception);
        }
    }

    public (long Bytes, long Items) GetRecycleBinSize()
    {
        var info = new RecycleBinInfo { StructureSize = Marshal.SizeOf<RecycleBinInfo>() };
        var result = SHQueryRecycleBin(null, ref info);
        if (result != 0)
            throw new InvalidOperationException($"Windows could not inspect the Recycle Bin (HRESULT 0x{result:X8}).");
        return (info.Size, info.Items);
    }

    public void EmptyRecycleBin()
    {
        OperationCancellationContext.ThrowIfCancellationRequested();
        const uint noConfirmation = 0x00000001;
        const uint noProgressUi = 0x00000002;
        const uint noSound = 0x00000004;
        var result = SHEmptyRecycleBin(IntPtr.Zero, null, noConfirmation | noProgressUi | noSound);
        if (result != 0)
            throw new InvalidOperationException($"Windows could not empty the Recycle Bin (HRESULT 0x{result:X8}).");
        log("Recycle Bin emptied after explicit user confirmation.");
    }

    public static string FormatBytes(long bytes)
    {
        string[] units = ["B", "KB", "MB", "GB", "TB"];
        double size = Math.Max(0, bytes);
        var unit = 0;
        while (size >= 1024 && unit < units.Length - 1)
        {
            size /= 1024;
            unit++;
        }
        return $"{size:0.##} {units[unit]}";
    }

    private static string EncodePowerShell(string script) =>
        Convert.ToBase64String(Encoding.Unicode.GetBytes(script));

    private async Task<CommandResult> RunPowerShellAsync(
        string script,
        TimeSpan? timeout = null,
        ProcessStopPolicy stopPolicy = ProcessStopPolicy.TerminateProcessTree,
        Func<Task>? stopAction = null)
    {
        var powershell = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0", "powershell.exe");
        return await RunProcessAsync(
            powershell,
            ["-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", EncodePowerShell(script)],
            timeout,
            stopPolicy,
            stopAction);
    }

    private async Task<CommandResult> RunProcessAsync(
        string executable,
        IReadOnlyList<string> arguments,
        TimeSpan? timeout = null,
        ProcessStopPolicy stopPolicy = ProcessStopPolicy.TerminateProcessTree,
        Func<Task>? stopAction = null)
    {
        OperationCancellationContext.ThrowIfCancellationRequested();
        var startInfo = new ProcessStartInfo(executable)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        foreach (var argument in arguments)
            startInfo.ArgumentList.Add(argument);

        return await CancellableProcessRunner.RunAsync(
            startInfo,
            Path.GetFileName(executable),
            log,
            OperationCancellationContext.Token,
            stopPolicy,
            timeout,
            stopAction);
    }

    private static void EnsureSuccess(string operation, CommandResult result)
    {
        if (result.ExitCode != 0)
            throw new InvalidOperationException($"{operation} failed with exit code {result.ExitCode}. {result.Error} {result.Output}".Trim());
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct RecycleBinInfo
    {
        public int StructureSize;
        public long Size;
        public long Items;
    }

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    private static extern int SHQueryRecycleBin(string? rootPath, ref RecycleBinInfo info);

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    private static extern int SHEmptyRecycleBin(IntPtr owner, string? rootPath, uint flags);
}
