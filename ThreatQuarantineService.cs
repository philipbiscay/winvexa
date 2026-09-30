using System.Diagnostics;
using System.IO;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;

namespace Winvexa;

internal sealed class ThreatQuarantineService(
    string quarantineDirectory,
    Action<string> log,
    Action<string>? protectQuarantinedFile = null)
{
    private const string StoreMutexName = @"Local\Winvexa.ThreatQuarantine.Store";
    private readonly string _quarantineDirectory = Path.GetFullPath(quarantineDirectory);
    private readonly string _recordsPath = Path.Combine(Path.GetFullPath(quarantineDirectory), "records.json");
    private readonly string _eventsPath = Path.Combine(Path.GetFullPath(quarantineDirectory), "security-events.jsonl");
    private readonly Action<string> _protectQuarantinedFile = protectQuarantinedFile ?? ApplyQuarantineProtection;
    private readonly object _gate = new();

    public QuarantineRecord RecordDetection(ThreatAnalysisFinding finding)
    {
        ArgumentNullException.ThrowIfNull(finding);
        var record = new QuarantineRecord(
            Guid.NewGuid().ToString("N"),
            Path.GetFullPath(finding.FilePath),
            string.Empty,
            finding.Sha256,
            finding.DetectionName,
            finding.ScannedAtUtc,
            Restored: false)
        {
            FileName = Path.GetFileName(finding.FilePath),
            MalwareFamily = finding.Classification == ThreatClassification.KnownMalicious
                ? finding.DetectionName
                : "Not attributed",
            Category = finding.Category,
            Severity = finding.Severity,
            DetectionMethod = finding.DetectionSource,
            Classification = finding.DisplayClassification,
            KnownCapabilities = finding.KnownFamilyCapabilities,
            ObservedCapabilities = finding.ObservedCapabilities,
            Status = finding.Classification switch
            {
                ThreatClassification.KnownMalicious => "Confirmed Threat",
                ThreatClassification.PotentiallyUnwanted => "Potentially Unwanted",
                ThreatClassification.Suspicious or ThreatClassification.HighConfidenceSuspicious or ThreatClassification.NeedsInvestigation => "Suspicious",
                ThreatClassification.KnownLegitimate => "Known Legitimate",
                ThreatClassification.LikelyLegitimate => "Likely Legitimate",
                ThreatClassification.NoThreatDetected => "Unknown",
                _ => "Unknown"
            },
            DetectedAtUtc = finding.ScannedAtUtc
        };
        SaveRecord(record);
        WriteEvent("Detection", record, $"{finding.DisplayClassification}: {finding.Reason}");
        return record;
    }

    public QuarantineRecord MarkDetectionAllowed(string id)
    {
        var record = FindRecord(id) ?? throw new InvalidOperationException("The detection record no longer exists.");
        var updated = record with { Status = "User Allowed", UserAllowed = true, AllowedSha256 = record.Sha256 };
        SaveRecord(updated);
        WriteEvent("User Allow", updated, "Existing exact file-path and SHA-256 allowance matched; this file was not quarantined again.");
        return updated;
    }

    public QuarantineRecord RecordContainmentFailure(string id, string details)
    {
        var record = FindRecord(id) ?? throw new InvalidOperationException("The detection record no longer exists.");
        if (record.Status == "Containment Failed" &&
            record.ContainmentResult.Equals(details, StringComparison.Ordinal))
            return record;
        var updated = record with { Status = "Containment Failed", ContainmentResult = details };
        SaveRecord(updated);
        WriteEvent("Containment failure", updated, details);
        return updated;
    }

    public void RecordSecurityEvent(string eventType, string details) =>
        WriteEvent(eventType, new QuarantineRecord(
            Guid.NewGuid().ToString("N"),
            string.Empty,
            string.Empty,
            string.Empty,
            "Winvexa local security",
            DateTimeOffset.UtcNow,
            Restored: false)
        {
            FileName = string.Empty,
            Status = "Informational"
        }, details);

    public void RecordWatchlistEvent(string eventType, string filePath, string details)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(eventType);
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);
        var fullPath = Path.GetFullPath(filePath);
        var record = new QuarantineRecord(
            Guid.NewGuid().ToString("N"),
            fullPath,
            string.Empty,
            string.Empty,
            "Unknown Threat Watchlist",
            DateTimeOffset.UtcNow,
            Restored: false)
        {
            FileName = Path.GetFileName(fullPath),
            Status = "Informational"
        };
        WriteEvent(eventType, record, details);
    }

    public bool RecordDatabaseVersion(string version, int familyCount)
    {
        var lastUpdate = LoadEvents()
            .Where(item => item.EventType == "Detection database update")
            .OrderByDescending(item => item.OccurredAtUtc)
            .FirstOrDefault();
        if (lastUpdate?.Details.StartsWith($"Version {version} ", StringComparison.OrdinalIgnoreCase) == true)
            return false;
        RecordSecurityEvent(
            "Detection database update",
            $"Version {version} validated with {familyCount} family records. No online update was performed.");
        return true;
    }

    public void RecordScanCompletion(string recordId, string details)
    {
        var record = FindRecord(recordId) ?? throw new InvalidOperationException("The scan detection record no longer exists.");
        WriteEvent("Scan completion", record, details);
    }

    public IReadOnlyList<QuarantineRecord> LoadDetectionRecords()
    {
        lock (_gate)
        {
            using var storeLock = AcquireStoreLock();
            return LoadRecordsCore();
        }
    }

    public IReadOnlyList<SecurityEventRecord> LoadEvents()
    {
        lock (_gate)
        {
            using var storeLock = AcquireStoreLock();
            if (!File.Exists(_eventsPath))
                return [];
            var events = new List<SecurityEventRecord>();
            foreach (var line in File.ReadLines(_eventsPath))
            {
                if (string.IsNullOrWhiteSpace(line))
                    continue;
                var item = JsonSerializer.Deserialize<SecurityEventRecord>(line)
                           ?? throw new InvalidDataException("A Winvexa security event record is invalid.");
                events.Add(item);
            }
            return events;
        }
    }

    public async Task<QuarantineRecord> QuarantineAsync(
        ThreatAnalysisFinding finding,
        string? detectionId = null,
        bool attemptProcessTermination = false,
        CancellationToken cancellationToken = default,
        bool allowCorrelatedBehaviorContainment = false)
    {
        ArgumentNullException.ThrowIfNull(finding);
        if (finding.IsDemo)
            throw new InvalidOperationException("TEST/DEMO results cannot be quarantined.");
        if (!finding.CanQuarantine ||
            finding.Classification is not (ThreatClassification.KnownMalicious or ThreatClassification.HighConfidenceSuspicious))
            throw new InvalidOperationException("This assessment is not eligible for quarantine.");
        if (attemptProcessTermination && finding.Classification != ThreatClassification.KnownMalicious)
        {
            if (!allowCorrelatedBehaviorContainment ||
                !ThreatAnalysisService.MeetsAutomaticContainmentThreshold(finding))
                throw new InvalidOperationException("Automatic process containment requires a confirmed hash match or the validated high-confidence behavior rule.");
        }
        if (allowCorrelatedBehaviorContainment &&
            !ThreatAnalysisService.MeetsAutomaticContainmentThreshold(finding))
            throw new InvalidOperationException("Rule-based containment requires all validated high-confidence behavior indicators.");
        var record = detectionId is null
            ? RecordDetection(finding)
            : FindRecord(detectionId) ?? throw new InvalidOperationException("The detection record no longer exists.");
        string sourcePath;
        try
        {
            if (ThreatAnalysisService.IsProtectedLocation(finding.FilePath) ||
                ThreatAnalysisService.IsWinvexaPath(finding.FilePath))
                throw new InvalidOperationException("Windows, installed-program, and Winvexa files are protected from quarantine.");

            sourcePath = Path.GetFullPath(finding.FilePath);
            var sourceInfo = new FileInfo(sourcePath);
            if (!sourceInfo.Exists)
                throw new FileNotFoundException("The selected file no longer exists.", sourcePath);
            if ((sourceInfo.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new InvalidOperationException("Reparse-point files cannot be quarantined.");
            if (!string.Equals(Path.GetPathRoot(sourcePath), Path.GetPathRoot(_quarantineDirectory), StringComparison.OrdinalIgnoreCase))
                throw new IOException("Safe quarantine currently requires the file and quarantine folder to be on the same volume. The file was not changed.");

            cancellationToken.ThrowIfCancellationRequested();
            var currentHash = await ComputeSha256Async(sourcePath, cancellationToken).ConfigureAwait(false);
            if (!currentHash.Equals(finding.Sha256, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("The file changed since analysis. Analyze it again before considering quarantine.");
            cancellationToken.ThrowIfCancellationRequested();
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or InvalidOperationException or System.Security.SecurityException)
        {
            var failure = record with { Status = "Containment Failed", ContainmentResult = exception.Message };
            SaveRecord(failure);
            WriteEvent("Containment failure", failure, exception.Message);
            throw;
        }

        var processContainment = attemptProcessTermination
            ? StopProcessesForExactImage(sourcePath)
            : new ProcessContainmentResult(true, "No process termination attempted; file isolation was requested.");
        if (attemptProcessTermination)
            WriteEvent("Containment attempt", record, processContainment.Details);

        var applicationDataRoot = Path.GetDirectoryName(_quarantineDirectory)
                                  ?? throw new InvalidOperationException("The quarantine directory has no parent path.");
        Directory.CreateDirectory(applicationDataRoot);
        EnsureNotReparsePoint(applicationDataRoot);
        Directory.CreateDirectory(_quarantineDirectory);
        EnsureNotReparsePoint(_quarantineDirectory);
        var targetPath = Path.Combine(_quarantineDirectory, Guid.NewGuid().ToString("N") + ".quarantined");
        try
        {
            File.Move(sourcePath, targetPath);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            var failedRecord = record with
            {
                Status = "Containment Failed",
                ContainmentResult = $"{processContainment.Details} File quarantine failed: {exception.Message}"
            };
            SaveRecord(failedRecord);
            WriteEvent("Containment failure", failedRecord, failedRecord.ContainmentResult);
            throw new IOException($"Winvexa could not quarantine '{sourcePath}'. {exception.Message}", exception);
        }

        string movedHash;
        try
        {
            movedHash = await ComputeSha256Async(targetPath, CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            ReturnMovedFileOrReport(targetPath, sourcePath, exception);
            throw;
        }
        if (!movedHash.Equals(finding.Sha256, StringComparison.OrdinalIgnoreCase))
        {
            ReturnMovedFileOrReport(targetPath, sourcePath, null);
            throw new IOException("The moved file did not match the analyzed SHA-256. It was returned to its original path; no quarantine record was created.");
        }

        record = record with
        {
            QuarantinedPath = targetPath,
            QuarantinedAtUtc = DateTimeOffset.UtcNow,
            Restored = false,
            Status = processContainment.Verified ? "Quarantined" : "Containment Failed",
            ContainmentResult = processContainment.Details
        };
        try
        {
            _protectQuarantinedFile(targetPath);
            SaveRecord(record);
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or System.Security.SecurityException or InvalidOperationException)
        {
            var failureDetails =
                $"File moved to '{targetPath}', but Winvexa could not verify protected quarantine storage: {exception.Message}";
            var failureRecord = record with
            {
                Status = "Containment Failed",
                ContainmentResult = failureDetails
            };
            try
            {
                SaveRecord(failureRecord);
            }
            catch (Exception persistenceException) when (
                persistenceException is IOException or UnauthorizedAccessException or System.Security.SecurityException or InvalidOperationException)
            {
                log($"Quarantine protection and detection-record persistence failed for '{targetPath}': {exception}; {persistenceException}");
                throw new IOException(
                    $"The file was moved to '{targetPath}', but quarantine protection and the detection record could not be verified. Do not execute this file.",
                    new AggregateException(exception, persistenceException));
            }

            try
            {
                WriteEvent("Containment failure", failureRecord, failureDetails);
            }
            catch (Exception eventException) when (
                eventException is IOException or UnauthorizedAccessException or System.Security.SecurityException)
            {
                log($"Quarantine protection failed for '{targetPath}'. The detection record was saved, but the security event could not be written: {eventException}");
                throw new IOException(
                    $"The file was moved to '{targetPath}' and its failed-containment detection record was saved, but the security event could not be written. Do not execute this file.",
                    new AggregateException(exception, eventException));
            }

            log($"Quarantine protection failed for '{targetPath}'; the file remains isolated by its quarantine location and extension: {failureDetails}");
            throw new IOException(
                $"The file was moved to '{targetPath}' and the detection was recorded as Containment Failed, but Winvexa could not verify protected quarantine permissions. Do not execute this file.",
                exception);
        }

        WriteEvent(
            processContainment.Verified ? "Quarantine" : "Containment failure",
            record,
            processContainment.Verified
                ? $"File moved to protected quarantine storage. SHA-256 {movedHash}."
                : $"File was quarantined, but process termination could not be verified. {processContainment.Details}");
        log($"Quarantined '{sourcePath}' as '{targetPath}'; SHA-256 {movedHash}; assessment {finding.Classification}; containment: {processContainment.Details}.");
        return record;
    }

    public IReadOnlyList<QuarantineRecord> LoadRecords()
    {
        lock (_gate)
        {
            using var storeLock = AcquireStoreLock();
            return LoadRecordsCore().Where(record =>
                record.Status is "Quarantined" or "Containment Failed" &&
                !string.IsNullOrWhiteSpace(record.QuarantinedPath)).ToArray();
        }
    }

    public QuarantineRecord KeepQuarantined(string id)
    {
        var record = FindQuarantineRecord(id);
        if (!File.Exists(record.QuarantinedPath))
            throw new FileNotFoundException("The quarantined file is missing.", record.QuarantinedPath);
        WriteEvent("Keep quarantined", record, "User confirmed that this item should remain isolated.");
        return record;
    }

    public async Task<QuarantineRecord> RestoreAsync(
        string id,
        bool allowExactFile,
        CancellationToken cancellationToken = default)
    {
        var record = FindQuarantineRecord(id);
        var quarantinedPath = GetValidatedQuarantinePath(record);
        var hash = await ComputeSha256Async(quarantinedPath, cancellationToken).ConfigureAwait(false);
        if (!hash.Equals(record.Sha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("The quarantined content hash changed. Restore was blocked.");
        var originalDirectory = Path.GetDirectoryName(record.OriginalPath)
                                ?? throw new InvalidOperationException("The original file path is invalid.");
        if (ThreatAnalysisService.IsProtectedLocation(record.OriginalPath) ||
            ThreatAnalysisService.IsWinvexaPath(record.OriginalPath))
            throw new InvalidOperationException("Restore to Windows, installed-program, or Winvexa paths is blocked.");
        Directory.CreateDirectory(originalDirectory);
        if (File.Exists(record.OriginalPath))
            throw new IOException("A file already exists at the original location. It was not overwritten.");
        cancellationToken.ThrowIfCancellationRequested();

        RemoveQuarantineProtection(quarantinedPath);
        File.Move(quarantinedPath, record.OriginalPath);
        var restoredHash = await ComputeSha256Async(record.OriginalPath, CancellationToken.None).ConfigureAwait(false);
        if (!restoredHash.Equals(record.Sha256, StringComparison.OrdinalIgnoreCase))
        {
            File.Move(record.OriginalPath, quarantinedPath);
            ApplyQuarantineProtection(quarantinedPath);
            throw new IOException("The restored file hash differed from the recorded content; it was returned to quarantine.");
        }

        var updated = record with
        {
            Restored = true,
            Status = allowExactFile ? "User Allowed" : "Restored",
            UserAllowed = allowExactFile,
            AllowedSha256 = allowExactFile ? restoredHash : null
        };
        SaveRecord(updated);
        WriteEvent(allowExactFile ? "User Allow" : "Restore", updated,
            allowExactFile
                ? $"User explicitly allowed this one restored file at '{record.OriginalPath}' with SHA-256 {restoredHash}. A different hash is not allowed."
                : $"Restored selected file to '{record.OriginalPath}'. No automatic execution occurred.");
        return updated;
    }

    public QuarantineRecord RemoveAllowance(string id)
    {
        var record = FindRecord(id) ?? throw new InvalidOperationException("The detection record no longer exists.");
        if (!record.UserAllowed)
            throw new InvalidOperationException("This detection record has no active user allowance.");
        var updated = record with { UserAllowed = false, AllowedSha256 = null, Status = "Restored" };
        SaveRecord(updated);
        WriteEvent("Allowance removal", updated, "User removed the file-specific allowance.");
        return updated;
    }

    public async Task<QuarantineRecord> DeletePermanentlyAsync(
        string id,
        CancellationToken cancellationToken = default)
    {
        var record = FindQuarantineRecord(id);
        var path = GetValidatedQuarantinePath(record);
        var currentHash = await ComputeSha256Async(path, cancellationToken).ConfigureAwait(false);
        if (!currentHash.Equals(record.Sha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("The quarantined content hash changed. Permanent deletion was blocked.");
        RemoveQuarantineProtection(path);
        File.Delete(path);
        var updated = record with { Status = "Deleted", Restored = false };
        SaveRecord(updated);
        WriteEvent("Permanent deletion", updated, "User explicitly deleted the verified quarantined file.");
        return updated;
    }

    public bool IsExactFileAllowed(string path, string sha256)
    {
        var canonicalPath = Path.GetFullPath(path);
        lock (_gate)
        {
            using var storeLock = AcquireStoreLock();
            return LoadRecordsCore().Any(record =>
                record.UserAllowed &&
                record.AllowedSha256?.Equals(sha256, StringComparison.OrdinalIgnoreCase) == true &&
                record.OriginalPath.Equals(canonicalPath, StringComparison.OrdinalIgnoreCase));
        }
    }

    private QuarantineRecord? FindRecord(string id)
    {
        lock (_gate)
        {
            using var storeLock = AcquireStoreLock();
            return LoadRecordsCore().FirstOrDefault(record => record.Id.Equals(id, StringComparison.OrdinalIgnoreCase));
        }
    }

    private QuarantineRecord FindQuarantineRecord(string id)
    {
        var record = FindRecord(id) ?? throw new InvalidOperationException("The quarantine record no longer exists.");
        if (record.Status is not ("Quarantined" or "Containment Failed") ||
            string.IsNullOrWhiteSpace(record.QuarantinedPath))
            throw new InvalidOperationException("The selected record does not refer to a quarantined file.");
        return record;
    }

    private string GetValidatedQuarantinePath(QuarantineRecord record)
    {
        var path = Path.GetFullPath(record.QuarantinedPath);
        if (!Path.GetDirectoryName(path)!.Equals(_quarantineDirectory, StringComparison.OrdinalIgnoreCase) ||
            !Path.GetExtension(path).Equals(".quarantined", StringComparison.OrdinalIgnoreCase) ||
            !File.Exists(path) ||
            (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new InvalidOperationException("The selected quarantine file is missing or outside Winvexa's protected store.");
        return path;
    }

    private List<QuarantineRecord> LoadRecordsCore()
    {
        if (!File.Exists(_recordsPath))
            return [];
        var json = File.ReadAllText(_recordsPath);
        return JsonSerializer.Deserialize<List<QuarantineRecord>>(json)
               ?? throw new InvalidDataException("The quarantine action record is invalid.");
    }

    private void SaveRecord(QuarantineRecord record)
    {
        lock (_gate)
        {
            using var storeLock = AcquireStoreLock();
            var records = LoadRecordsCore();
            var index = records.FindIndex(item => item.Id.Equals(record.Id, StringComparison.OrdinalIgnoreCase));
            if (index < 0)
                records.Add(record);
            else
                records[index] = record;
            WriteRecords(records);
        }
    }

    private void WriteRecords(IReadOnlyList<QuarantineRecord> records)
    {
        Directory.CreateDirectory(_quarantineDirectory);
        EnsureNotReparsePoint(_quarantineDirectory);
        var temporaryPath = _recordsPath + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            File.WriteAllText(temporaryPath, JsonSerializer.Serialize(records, new JsonSerializerOptions { WriteIndented = true }));
            File.Move(temporaryPath, _recordsPath, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporaryPath))
                File.Delete(temporaryPath);
        }
    }

    private void WriteEvent(string eventType, QuarantineRecord record, string details)
    {
        var item = new SecurityEventRecord(
            Guid.NewGuid().ToString("N"),
            DateTimeOffset.UtcNow,
            eventType,
            record.FileName,
            record.OriginalPath,
            record.DetectionName,
            details);
        lock (_gate)
        {
            using var storeLock = AcquireStoreLock();
            Directory.CreateDirectory(_quarantineDirectory);
            EnsureNotReparsePoint(_quarantineDirectory);
            File.AppendAllText(_eventsPath, JsonSerializer.Serialize(item) + Environment.NewLine);
        }
        log($"Security event {eventType}: {record.DetectionName} — {record.FileName}. {details}");
    }

    private static IDisposable AcquireStoreLock()
    {
        var mutex = new Mutex(initiallyOwned: false, StoreMutexName);
        try
        {
            try
            {
                mutex.WaitOne();
            }
            catch (AbandonedMutexException)
            {
            }
            return new StoreLock(mutex);
        }
        catch
        {
            mutex.Dispose();
            throw;
        }
    }

    private sealed class StoreLock(Mutex mutex) : IDisposable
    {
        public void Dispose()
        {
            mutex.ReleaseMutex();
            mutex.Dispose();
        }
    }

    private static ProcessContainmentResult StopProcessesForExactImage(string path)
    {
        var outcomes = new List<string>();
        foreach (var process in Process.GetProcesses())
        {
            using (process)
            {
                try
                {
                    if (!string.Equals(process.MainModule?.FileName, path, StringComparison.OrdinalIgnoreCase))
                        continue;
                    var processId = process.Id;
                    process.Kill(entireProcessTree: false);
                    if (!process.WaitForExit(5000))
                    {
                        outcomes.Add($"PID {processId} termination was requested but exit was not verified");
                        continue;
                    }
                    outcomes.Add($"Verified stopped PID {processId}");
                }
                catch (Exception exception) when (
                    exception is InvalidOperationException or System.ComponentModel.Win32Exception or NotSupportedException)
                {
                    outcomes.Add($"Process containment failed: {exception.Message}");
                }
            }
        }
        if (outcomes.Count == 0)
            return new ProcessContainmentResult(true, "No running process was found with this exact image path.");
        var verified = outcomes.All(outcome => outcome.StartsWith("Verified stopped", StringComparison.Ordinal));
        return new ProcessContainmentResult(verified, string.Join("; ", outcomes));
    }

    private static void ApplyQuarantineProtection(string path)
    {
        var file = new FileInfo(path);
        var security = FileSystemAclExtensions.GetAccessControl(file);
        var user = WindowsIdentity.GetCurrent().User
                   ?? throw new InvalidOperationException("The current Windows user SID is unavailable.");
        security.AddAccessRule(new FileSystemAccessRule(user, FileSystemRights.ExecuteFile, AccessControlType.Deny));
        FileSystemAclExtensions.SetAccessControl(file, security);
        File.SetAttributes(path, FileAttributes.Hidden | FileAttributes.ReadOnly);
    }

    private static void RemoveQuarantineProtection(string path)
    {
        File.SetAttributes(path, FileAttributes.Normal);
        var file = new FileInfo(path);
        var security = FileSystemAclExtensions.GetAccessControl(file);
        var user = WindowsIdentity.GetCurrent().User
                   ?? throw new InvalidOperationException("The current Windows user SID is unavailable.");
        security.RemoveAccessRuleSpecific(new FileSystemAccessRule(user, FileSystemRights.ExecuteFile, AccessControlType.Deny));
        FileSystemAclExtensions.SetAccessControl(file, security);
    }

    private static void ReturnMovedFileOrReport(string quarantinedPath, string originalPath, Exception? cause)
    {
        try
        {
            RemoveQuarantineProtection(quarantinedPath);
            File.Move(quarantinedPath, originalPath);
        }
        catch (Exception restoreException) when (
            restoreException is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            throw new IOException(
                $"The moved file could not be verified or returned. Quarantined copy: '{quarantinedPath}'.",
                cause is null ? restoreException : new AggregateException(cause, restoreException));
        }
    }

    private static async Task<string> ComputeSha256Async(string path, CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            1024 * 128,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        var hash = await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false);
        return Convert.ToHexString(hash);
    }

    private static void EnsureNotReparsePoint(string path)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new InvalidOperationException("The quarantine directory or its parent is a reparse point and cannot be trusted.");
    }

    private sealed record ProcessContainmentResult(bool Verified, string Details);
}
