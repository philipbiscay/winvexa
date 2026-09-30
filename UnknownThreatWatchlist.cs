using System.IO;
using System.Text.Json;

namespace Winvexa;

internal sealed record UnknownThreatWatchRecord(
    string Id,
    string FilePath,
    string Sha256,
    string Publisher,
    DateTimeOffset StartedAtUtc,
    DateTimeOffset LastObservedAtUtc,
    long ObservedDurationTicks,
    string Status)
{
    public string FileName => Path.GetFileName(FilePath);
    public long? FileSizeBytes { get; init; }
    public long? ObservationCount { get; init; }
    public string? RiskState { get; init; }
    public string? UserDecision { get; init; }
    public IReadOnlyList<string> RelatedDetectionIds { get; init; } = [];
    public IReadOnlyList<string> BaselineCapabilities { get; init; } = [];
    public IReadOnlyList<string> BaselineEvidence { get; init; } = [];
    public IReadOnlyList<string> LatestCapabilities { get; init; } = [];
    public IReadOnlyList<string> LatestEvidence { get; init; } = [];
    public string LatestClassification { get; init; } = "Unknown";
    public string LatestConfidence { get; init; } = "Low";
    public string LatestReason { get; init; } = string.Empty;
    public string SecurityOutcome { get; init; } = "Threat Detected";
    public string? PreviousSha256 { get; init; }
    public string? DetectionRecordId { get; init; }
    public DateTimeOffset? CompletedAtUtc { get; init; }
    public TimeSpan ObservedDuration => TimeSpan.FromTicks(ObservedDurationTicks);
    public TimeSpan RemainingDuration => TimeSpan.FromDays(30) - ObservedDuration;
    public string DisplayStatus
    {
        get
        {
            if (Status == "Watching")
            {
                var day = Math.Clamp((int)Math.Ceiling(ObservedDuration.TotalDays), 1, 30);
                var state = LatestClassification switch
                {
                    "Unknown" => "Unknown · Under Observation",
                    "Suspicious" when LatestConfidence.Equals("High", StringComparison.OrdinalIgnoreCase) => "High Risk",
                    "Suspicious" => "Suspicious",
                    "Potentially Unwanted" => "Potentially Unwanted",
                    "Likely legitimate" or "Known legitimate" => "Normal Behavior",
                    _ => "Under Observation"
                };
                return $"{state} · Day {day} / 30";
            }

            return Status switch
            {
                "Completed — No Malicious Behavior Observed" => "Observation Complete · 30 / 30",
                "Security Detection" => SecurityOutcome,
                "Reassessment Required" => "Reassessment Required",
                _ => Status
            };
        }
    }
}

internal sealed class UnknownThreatWatchlistService(
    string storagePath,
    Action<string, string, string> recordEvent)
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };
    private const string StoreMutexName = @"Local\Winvexa.UnknownThreatWatchlist.Store";
    private readonly string _storagePath = Path.GetFullPath(storagePath);
    private readonly object _gate = new();

    public IReadOnlyList<UnknownThreatWatchRecord> LoadAll()
    {
        lock (_gate)
        {
            using var storeLock = AcquireStoreLock();
            return LoadCore();
        }
    }

    public IReadOnlyList<UnknownThreatWatchRecord> LoadActive() =>
        LoadAll().Where(IsActive).OrderBy(record => record.StartedAtUtc).ToArray();

    public UnknownThreatWatchRecord? Enroll(ThreatAnalysisFinding finding)
    {
        ArgumentNullException.ThrowIfNull(finding);
        if (!ShouldObserve(finding))
            return null;

        var path = Path.GetFullPath(finding.FilePath);
        if (!File.Exists(path))
            throw new FileNotFoundException("The unknown program is no longer available for observation.", path);

        lock (_gate)
        {
            using var storeLock = AcquireStoreLock();
            var records = LoadCore();
            var samePath = records
                .Where(record => record.FilePath.Equals(path, StringComparison.OrdinalIgnoreCase))
                .OrderByDescending(record => record.StartedAtUtc)
                .ToArray();
            var current = samePath.FirstOrDefault(IsActive);
            if (current is not null && current.Sha256.Equals(finding.Sha256, StringComparison.OrdinalIgnoreCase))
            {
                var refreshed = UpdateFinding(current, finding);
                Save(records, refreshed);
                return refreshed;
            }

            if (current is not null)
            {
                var replaced = current with { Status = "Reassessment Required" };
                Save(records, replaced);
                recordEvent(
                    "Watchlist reassessment",
                    path,
                    $"The file SHA-256 changed from {current.Sha256} to {finding.Sha256}; the previous observation was stopped and the new file identity must be reviewed.");
            }

            var completed = samePath.FirstOrDefault(record =>
                record.Status == "Completed — No Malicious Behavior Observed" &&
                record.Sha256.Equals(finding.Sha256, StringComparison.OrdinalIgnoreCase));
            if (completed is not null)
            {
                var newCapabilities = finding.ObservedCapabilities.Except(
                    completed.LatestCapabilities,
                    StringComparer.OrdinalIgnoreCase).ToArray();
                if (newCapabilities.Length == 0)
                    return completed;
                var reassessed = CreateRecord(finding) with
                {
                    BaselineCapabilities = finding.ObservedCapabilities,
                    BaselineEvidence = finding.ObservedEvidence,
                    LatestEvidence = finding.ObservedEvidence
                };
                records.Add(reassessed);
                Write(records);
                recordEvent(
                    "Watchlist reassessment",
                    path,
                    $"A later analysis observed new capability indicator(s): {string.Join(", ", newCapabilities)}. A new 30-day observation began; this is not a malware verdict.");
                return reassessed;
            }

            var entry = CreateRecord(finding);
            records.Add(entry);
            Write(records);
            recordEvent(
                "Watchlist enrollment",
                path,
                $"Unknown program added for 30-day observation. Initial classification: {finding.DisplayClassification}; SHA-256 {finding.Sha256}; baseline capabilities: {(finding.ObservedCapabilities.Count == 0 ? "none" : string.Join(", ", finding.ObservedCapabilities))}.");
            return entry;
        }
    }

    public UnknownThreatWatchRecord RecordObservation(
        string id,
        ThreatAnalysisFinding finding,
        DateTimeOffset observedAtUtc,
        TimeSpan observationInterval)
    {
        if (observationInterval <= TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(observationInterval));

        lock (_gate)
        {
            using var storeLock = AcquireStoreLock();
            var records = LoadCore();
            var current = records.FirstOrDefault(record => record.Id.Equals(id, StringComparison.OrdinalIgnoreCase))
                          ?? throw new InvalidOperationException("The watchlist entry no longer exists.");
            if (!IsActive(current))
                return current;
            if (!current.FilePath.Equals(Path.GetFullPath(finding.FilePath), StringComparison.OrdinalIgnoreCase) ||
                !current.Sha256.Equals(finding.Sha256, StringComparison.OrdinalIgnoreCase))
            {
                var changed = current with
                {
                    Status = "Reassessment Required",
                    LastObservedAtUtc = observedAtUtc,
                    LatestReason = "The program path or SHA-256 changed during observation. The previous identity is no longer monitored."
                };
                Save(records, changed);
                recordEvent(
                    "Watchlist reassessment",
                    current.FilePath,
                    $"{changed.LatestReason} Previous hash: {current.Sha256}; current hash: {finding.Sha256}.");
                return changed;
            }

            var elapsed = observedAtUtc - current.LastObservedAtUtc;
            var observedTicks = elapsed > TimeSpan.Zero && elapsed <= observationInterval + observationInterval
                ? elapsed.Ticks
                : 0;
            var durationTicks = checked(current.ObservedDurationTicks + observedTicks);
            var threatDetected = finding.Classification == ThreatClassification.KnownMalicious ||
                                 ThreatAnalysisService.MeetsAutomaticContainmentThreshold(finding);
            var completed = !threatDetected && durationTicks >= TimeSpan.FromDays(30).Ticks;
            var updated = current with
            {
                LastObservedAtUtc = observedAtUtc,
                ObservedDurationTicks = durationTicks,
                ObservationCount = checked((current.ObservationCount ?? 0) + 1),
                LatestCapabilities = finding.ObservedCapabilities,
                LatestEvidence = finding.ObservedEvidence,
                LatestClassification = finding.DisplayClassification,
                LatestConfidence = finding.Confidence.ToString(),
                RiskState = threatDetected ? "High Risk" : finding.DisplayClassification,
                LatestReason = finding.Reason,
                Status = threatDetected
                    ? "Security Detection"
                    : completed
                        ? "Completed — No Malicious Behavior Observed"
                        : "Watching"
            };
            Save(records, updated);

            if (threatDetected)
            {
                recordEvent(
                    "Watchlist threat threshold reached",
                    current.FilePath,
                    $"{finding.DisplayClassification}: {finding.DetectionName}. Observed capabilities: {string.Join(", ", finding.ObservedCapabilities)}. Evidence: {string.Join(" | ", finding.ObservedEvidence)}");
            }
            else if (completed)
            {
                updated = updated with { CompletedAtUtc = observedAtUtc };
                Save(records, updated);
                recordEvent(
                    "Watchlist observation completed",
                    current.FilePath,
                    "Completed — No Malicious Behavior Observed. This does not guarantee that the program is safe; normal antivirus protection remains active.");
            }

            return updated;
        }
    }

    public UnknownThreatWatchRecord LinkDetection(
        string id,
        string detectionRecordId,
        ThreatAnalysisFinding finding,
        string details,
        string securityOutcome = "Threat Detected")
    {
        lock (_gate)
        {
            using var storeLock = AcquireStoreLock();
            var records = LoadCore();
            var current = records.FirstOrDefault(record => record.Id.Equals(id, StringComparison.OrdinalIgnoreCase))
                          ?? throw new InvalidOperationException("The watchlist entry no longer exists.");
            var updated = current with
            {
                Status = "Security Detection",
                PreviousSha256 = current.Sha256.Equals(finding.Sha256, StringComparison.OrdinalIgnoreCase)
                    ? current.PreviousSha256
                    : current.Sha256,
                Sha256 = finding.Sha256,
                DetectionRecordId = detectionRecordId,
                LastObservedAtUtc = finding.ScannedAtUtc,
                LatestCapabilities = finding.ObservedCapabilities,
                LatestEvidence = finding.ObservedEvidence,
                LatestClassification = finding.DisplayClassification,
                LatestConfidence = finding.Confidence.ToString(),
                RiskState = ThreatAnalysisService.MeetsAutomaticContainmentThreshold(finding)
                    ? "High Risk"
                    : finding.DisplayClassification,
                SecurityOutcome = securityOutcome,
                LatestReason = details,
                UserDecision = securityOutcome.Equals("User Allowed", StringComparison.OrdinalIgnoreCase)
                    ? "Allowed exact path and SHA-256"
                    : current.UserDecision,
                RelatedDetectionIds = current.RelatedDetectionIds.Contains(detectionRecordId, StringComparer.OrdinalIgnoreCase)
                    ? current.RelatedDetectionIds
                    : [.. current.RelatedDetectionIds, detectionRecordId]
            };
            Save(records, updated);
            recordEvent("Watchlist removed after detection", current.FilePath, details);
            return updated;
        }
    }

    public UnknownThreatWatchRecord StopWatching(string id)
    {
        lock (_gate)
        {
            using var storeLock = AcquireStoreLock();
            var records = LoadCore();
            var current = records.FirstOrDefault(record => record.Id.Equals(id, StringComparison.OrdinalIgnoreCase))
                          ?? throw new InvalidOperationException("The watchlist entry no longer exists.");
            if (!IsActive(current))
                return current;
            var updated = current with
            {
                Status = "Removed by User",
                UserDecision = "Stopped enhanced observation"
            };
            Save(records, updated);
            recordEvent("Watchlist stopped by user", current.FilePath, "The user explicitly ended enhanced observation. Normal antivirus protection remains active.");
            return updated;
        }
    }

    internal static bool ShouldObserve(ThreatAnalysisFinding finding) =>
        !finding.IsDemo &&
        (finding.Classification is ThreatClassification.NoThreatDetected or
            ThreatClassification.NeedsInvestigation or
            ThreatClassification.Suspicious or
            ThreatClassification.LikelyLegitimate) &&
        finding.Confidence != ThreatConfidence.High &&
        !ThreatAnalysisService.IsProtectedLocation(finding.FilePath) &&
        !ThreatAnalysisService.IsWinvexaPath(finding.FilePath) &&
        ThreatKnowledgeBase.IsSha256(finding.Sha256);

    internal static bool IsActive(UnknownThreatWatchRecord record) =>
        record.Status == "Watching";

    private static UnknownThreatWatchRecord CreateRecord(ThreatAnalysisFinding finding)
    {
        var now = finding.ScannedAtUtc;
        var filePath = Path.GetFullPath(finding.FilePath);
        return new UnknownThreatWatchRecord(
            Guid.NewGuid().ToString("N"),
            filePath,
            finding.Sha256,
            finding.Publisher,
            now,
            now,
            0,
            "Watching")
        {
            FileSizeBytes = new FileInfo(filePath).Length,
            ObservationCount = 0,
            RiskState = finding.DisplayClassification,
            BaselineCapabilities = finding.ObservedCapabilities,
            BaselineEvidence = finding.ObservedEvidence,
            LatestCapabilities = finding.ObservedCapabilities,
            LatestEvidence = finding.ObservedEvidence,
            LatestClassification = finding.DisplayClassification,
            LatestConfidence = finding.Confidence.ToString(),
            LatestReason = finding.Reason
        };
    }

    private static UnknownThreatWatchRecord UpdateFinding(
        UnknownThreatWatchRecord record,
        ThreatAnalysisFinding finding) =>
        record with
        {
            Publisher = finding.Publisher,
            LatestCapabilities = finding.ObservedCapabilities,
            LatestEvidence = finding.ObservedEvidence,
            LatestClassification = finding.DisplayClassification,
            LatestConfidence = finding.Confidence.ToString(),
            RiskState = finding.DisplayClassification,
            LatestReason = finding.Reason
        };

    private List<UnknownThreatWatchRecord> LoadCore()
    {
        if (!File.Exists(_storagePath))
            return [];
        var records = JsonSerializer.Deserialize<List<UnknownThreatWatchRecord>>(
                          File.ReadAllText(_storagePath),
                          JsonOptions)
                      ?? throw new InvalidDataException("The Winvexa unknown threat watchlist is invalid.");
        return records.Select(NormalizeRecord).ToList();
    }

    private static UnknownThreatWatchRecord NormalizeRecord(UnknownThreatWatchRecord? record)
    {
        if (record is null ||
            string.IsNullOrWhiteSpace(record.Id) ||
            string.IsNullOrWhiteSpace(record.FilePath) ||
            string.IsNullOrWhiteSpace(record.Sha256) ||
            string.IsNullOrWhiteSpace(record.Status))
        {
            throw new InvalidDataException("A Winvexa watchlist entry is missing required identity or status data.");
        }

        var relatedDetections = NormalizeValues(record.RelatedDetectionIds);
        if (relatedDetections.Count == 0 && !string.IsNullOrWhiteSpace(record.DetectionRecordId))
            relatedDetections = [record.DetectionRecordId];

        return record with
        {
            Publisher = record.Publisher ?? string.Empty,
            RiskState = record.RiskState ?? record.LatestClassification ?? "Unknown",
            UserDecision = record.UserDecision ??
                           (record.Status == "Removed by User" ? "Stopped enhanced observation" : null),
            RelatedDetectionIds = relatedDetections,
            BaselineCapabilities = NormalizeValues(record.BaselineCapabilities),
            BaselineEvidence = NormalizeValues(record.BaselineEvidence),
            LatestCapabilities = NormalizeValues(record.LatestCapabilities),
            LatestEvidence = NormalizeValues(record.LatestEvidence),
            LatestClassification = string.IsNullOrWhiteSpace(record.LatestClassification)
                ? "Unknown"
                : record.LatestClassification,
            LatestConfidence = string.IsNullOrWhiteSpace(record.LatestConfidence)
                ? "Low"
                : record.LatestConfidence,
            LatestReason = record.LatestReason ?? string.Empty,
            SecurityOutcome = string.IsNullOrWhiteSpace(record.SecurityOutcome)
                ? "Threat Detected"
                : record.SecurityOutcome
        };
    }

    private static IReadOnlyList<string> NormalizeValues(IReadOnlyList<string>? values) =>
        values?.Where(value => !string.IsNullOrWhiteSpace(value)).ToArray() ?? [];

    private void Save(List<UnknownThreatWatchRecord> records, UnknownThreatWatchRecord updated)
    {
        Replace(records, updated);
        Write(records);
    }

    private static void Replace(List<UnknownThreatWatchRecord> records, UnknownThreatWatchRecord updated)
    {
        var index = records.FindIndex(record => record.Id.Equals(updated.Id, StringComparison.OrdinalIgnoreCase));
        if (index < 0)
            throw new InvalidOperationException("The watchlist entry disappeared before it could be updated.");
        records[index] = updated;
    }

    private void Write(IReadOnlyList<UnknownThreatWatchRecord> records)
    {
        var directory = Path.GetDirectoryName(_storagePath)
                       ?? throw new InvalidOperationException("The watchlist storage path has no parent directory.");
        Directory.CreateDirectory(directory);
        var temporaryPath = _storagePath + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            File.WriteAllText(temporaryPath, JsonSerializer.Serialize(records, JsonOptions));
            File.Move(temporaryPath, _storagePath, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporaryPath))
                File.Delete(temporaryPath);
        }
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
}
