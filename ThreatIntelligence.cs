using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.IO;

namespace Winvexa;

internal enum ThreatClassification
{
    KnownMalicious,
    HighConfidenceSuspicious,
    Suspicious,
    NeedsInvestigation,
    PotentiallyUnwanted,
    LikelyLegitimate,
    KnownLegitimate,
    NoThreatDetected
}

internal enum ThreatConfidence
{
    Low,
    Medium,
    High
}

internal sealed record ThreatCategoryDefinition(string Id, string Name, string Description);

internal sealed record ThreatCapabilityDefinition(
    string Id,
    string Name,
    string Meaning,
    string WhyMalwareUsesIt,
    string LegitimateUses,
    IReadOnlyList<string> SafeIndicators,
    ThreatConfidence ConfidenceWhenObserved);

internal sealed record ThreatIndicator(string Type, string Value, string Context);

internal sealed record ThreatHashRecord(string Sha256, string SourceUrl, DateTimeOffset LastUpdatedUtc);

internal sealed record ThreatDetectionRule(
    string Id,
    string Name,
    IReadOnlyList<string> RequiredCapabilities,
    int MinimumMatches,
    ThreatClassification Classification,
    ThreatConfidence Confidence,
    string Rationale);

internal sealed record MalwareFamilyRecord(
    string Id,
    string Name,
    IReadOnlyList<string> Aliases,
    string CategoryId,
    string Description,
    IReadOnlyList<string> KnownCapabilities,
    IReadOnlyList<string> TypicalBehaviors,
    IReadOnlyList<ThreatIndicator> Indicators,
    IReadOnlyList<ThreatHashRecord> Sha256Hashes,
    IReadOnlyList<string> PersistenceMethods,
    IReadOnlyList<string> AttackBehaviors,
    string Severity,
    IReadOnlyList<ThreatDetectionRule> DetectionRules,
    IReadOnlyList<string> References,
    DateTimeOffset LastUpdatedUtc)
{
    public string ThreatType { get; init; } = string.Empty;
    public IReadOnlyList<string> TargetPlatforms { get; init; } = [];
    public string FirstObservedTimeframe { get; init; } = string.Empty;
    public IReadOnlyList<string> DetectionNames { get; init; } = [];
}

internal sealed record ThreatKnowledgeBaseDocument(
    int SchemaVersion,
    string DatabaseVersion,
    DateTimeOffset LastUpdatedUtc,
    IReadOnlyList<ThreatCategoryDefinition> Categories,
    IReadOnlyList<ThreatCapabilityDefinition> Capabilities,
    IReadOnlyList<ThreatDetectionRule> DetectionRules,
    IReadOnlyList<MalwareFamilyRecord> Families,
    IReadOnlyList<string> Sources);

internal sealed record ThreatFamilySimilarity(
    string FamilyName,
    IReadOnlyList<string> SharedCapabilities,
    string Reference);

internal sealed record ThreatAnalysisFinding(
    string FilePath,
    string DetectionName,
    string Category,
    ThreatClassification Classification,
    ThreatConfidence Confidence,
    string Sha256,
    string SignatureStatus,
    string Publisher,
    IReadOnlyList<string> ObservedCapabilities,
    IReadOnlyList<string> ObservedEvidence,
    IReadOnlyList<string> KnownFamilyCapabilities,
    IReadOnlyList<ThreatFamilySimilarity> RelatedFamilies,
    string Reason,
    string RecommendedAction,
    string DetectionSource,
    DateTimeOffset ScannedAtUtc,
    bool IsDemo,
    bool CanQuarantine)
{
    public string Severity { get; init; } = "Unknown";
    public string? CorrelationRuleId { get; init; }

    public string DisplayClassification => Classification switch
    {
        ThreatClassification.KnownMalicious => "Confirmed Threat",
        ThreatClassification.HighConfidenceSuspicious or ThreatClassification.Suspicious or ThreatClassification.NeedsInvestigation => "Suspicious",
        ThreatClassification.PotentiallyUnwanted => "Potentially Unwanted",
        ThreatClassification.NoThreatDetected => "Unknown",
        ThreatClassification.LikelyLegitimate => "Likely legitimate",
        ThreatClassification.KnownLegitimate => "Known legitimate",
        _ => "Unknown"
    };

    public string Details =>
        $"Assessment: {DisplayClassification} ({Confidence} confidence){Environment.NewLine}" +
        $"Severity: {Severity}{Environment.NewLine}" +
        $"File: {FilePath}{Environment.NewLine}" +
        $"SHA-256: {Sha256}{Environment.NewLine}" +
        $"Signature: {SignatureStatus}{Environment.NewLine}" +
        $"Publisher: {Publisher}{Environment.NewLine}" +
        $"Category: {Category}{Environment.NewLine}" +
        $"Observed capabilities: {(ObservedCapabilities.Count == 0 ? "None in this on-demand snapshot" : string.Join(", ", ObservedCapabilities))}{Environment.NewLine}" +
        $"Observed evidence: {(ObservedEvidence.Count == 0 ? "None" : string.Join(Environment.NewLine, ObservedEvidence))}{Environment.NewLine}" +
        $"Known capabilities of exact-hash family record (not observed): {(KnownFamilyCapabilities.Count == 0 ? "Not applicable" : string.Join(", ", KnownFamilyCapabilities))}{Environment.NewLine}" +
        $"Related families (similarity only): {(RelatedFamilies.Count == 0 ? "None established" : string.Join(", ", RelatedFamilies.Select(family => $"{family.FamilyName} ({string.Join(", ", family.SharedCapabilities)})")))}{Environment.NewLine}" +
        $"Reason: {Reason}{Environment.NewLine}" +
        $"Recommended action: {RecommendedAction}{Environment.NewLine}" +
        $"Detection source: {DetectionSource}{Environment.NewLine}" +
        $"Scan time (UTC): {ScannedAtUtc:O}" +
        (IsDemo ? $"{Environment.NewLine}TEST/DEMO ONLY — synthetic data; no real file or malware was analyzed." : string.Empty);
}

internal sealed record QuarantineRecord(
    string Id,
    string OriginalPath,
    string QuarantinedPath,
    string Sha256,
    string DetectionName,
    DateTimeOffset QuarantinedAtUtc,
    bool Restored)
{
    public string FileName { get; init; } = Path.GetFileName(OriginalPath);
    public string MalwareFamily { get; init; } = string.Empty;
    public string Category { get; init; } = string.Empty;
    public string Severity { get; init; } = string.Empty;
    public string DetectionMethod { get; init; } = string.Empty;
    public string Classification { get; init; } = "Unknown";
    public IReadOnlyList<string> KnownCapabilities { get; init; } = [];
    public IReadOnlyList<string> ObservedCapabilities { get; init; } = [];
    public string Status { get; init; } = "Quarantined";
    public string ContainmentResult { get; init; } = string.Empty;
    public DateTimeOffset DetectedAtUtc { get; init; } = QuarantinedAtUtc;
    public bool UserAllowed { get; init; }
    public string? AllowedSha256 { get; init; }
}

internal sealed record SecurityEventRecord(
    string Id,
    DateTimeOffset OccurredAtUtc,
    string EventType,
    string FileName,
    string FilePath,
    string DetectionName,
    string Details);

internal sealed class ThreatKnowledgeBase
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        Converters = { new JsonStringEnumConverter() }
    };

    public ThreatKnowledgeBase(ThreatKnowledgeBaseDocument document, bool supportsKnownHashMatches)
    {
        Validate(document);
        Document = document;
        SupportsKnownHashMatches = supportsKnownHashMatches;
        Categories = document.Categories.ToDictionary(category => category.Id, StringComparer.OrdinalIgnoreCase);
        Capabilities = document.Capabilities.ToDictionary(capability => capability.Id, StringComparer.OrdinalIgnoreCase);
    }

    public ThreatKnowledgeBaseDocument Document { get; }
    public bool SupportsKnownHashMatches { get; }
    public IReadOnlyDictionary<string, ThreatCategoryDefinition> Categories { get; }
    public IReadOnlyDictionary<string, ThreatCapabilityDefinition> Capabilities { get; }

    public static ThreatKnowledgeBase Load(string path, bool supportsKnownHashMatches = false)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        var json = File.ReadAllText(path);
        var document = JsonSerializer.Deserialize<ThreatKnowledgeBaseDocument>(json, JsonOptions)
            ?? throw new InvalidDataException("The threat knowledge base is empty.");
        return new ThreatKnowledgeBase(document, supportsKnownHashMatches);
    }

    public static ThreatKnowledgeBase LoadBundled()
    {
        var path = Path.Combine(AppContext.BaseDirectory, "ThreatKnowledgeBase.json");
        if (!File.Exists(path))
            throw new FileNotFoundException("The bundled Winvexa threat knowledge base is missing.", path);
        return Load(path, supportsKnownHashMatches: true);
    }

    public MalwareFamilyRecord? FindFamilyBySha256(string sha256)
    {
        if (!SupportsKnownHashMatches || !IsSha256(sha256))
            return null;
        return Document.Families.FirstOrDefault(family =>
            family.Sha256Hashes.Any(hash =>
                hash.Sha256.Equals(sha256, StringComparison.OrdinalIgnoreCase)));
    }

    public static IReadOnlyList<MalwareFamilyRecord> MergeFamilies(
        IReadOnlyList<MalwareFamilyRecord> existing,
        IEnumerable<MalwareFamilyRecord> updates)
    {
        var merged = existing.ToList();
        foreach (var update in updates)
        {
            var aliases = new HashSet<string>(
                update.Aliases.Append(update.Name),
                StringComparer.OrdinalIgnoreCase);
            var matchingIndex = merged.FindIndex(family =>
                aliases.Contains(family.Name) ||
                family.Aliases.Any(aliases.Contains) ||
                family.Id.Equals(update.Id, StringComparison.OrdinalIgnoreCase));
            if (matchingIndex < 0)
            {
                merged.Add(update);
                continue;
            }

            var current = merged[matchingIndex];
            merged[matchingIndex] = update with
            {
                Id = current.Id,
                Aliases = current.Aliases.Concat(update.Aliases).Append(current.Name).Append(update.Name)
                    .Where(alias => !alias.Equals(update.Name, StringComparison.OrdinalIgnoreCase))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToArray(),
                KnownCapabilities = current.KnownCapabilities.Concat(update.KnownCapabilities)
                    .Distinct(StringComparer.OrdinalIgnoreCase).ToArray(),
                TypicalBehaviors = current.TypicalBehaviors.Concat(update.TypicalBehaviors)
                    .Distinct(StringComparer.OrdinalIgnoreCase).ToArray(),
                Indicators = current.Indicators.Concat(update.Indicators)
                    .Distinct().ToArray(),
                Sha256Hashes = current.Sha256Hashes.Concat(update.Sha256Hashes)
                    .DistinctBy(hash => hash.Sha256, StringComparer.OrdinalIgnoreCase).ToArray(),
                PersistenceMethods = current.PersistenceMethods.Concat(update.PersistenceMethods)
                    .Distinct(StringComparer.OrdinalIgnoreCase).ToArray(),
                AttackBehaviors = current.AttackBehaviors.Concat(update.AttackBehaviors)
                    .Distinct(StringComparer.OrdinalIgnoreCase).ToArray(),
                References = current.References.Concat(update.References)
                    .Distinct(StringComparer.OrdinalIgnoreCase).ToArray(),
                DetectionNames = current.DetectionNames.Concat(update.DetectionNames)
                    .Distinct(StringComparer.OrdinalIgnoreCase).ToArray(),
                TargetPlatforms = current.TargetPlatforms.Concat(update.TargetPlatforms)
                    .Distinct(StringComparer.OrdinalIgnoreCase).ToArray()
            };
        }
        return merged;
    }

    private static void Validate(ThreatKnowledgeBaseDocument document)
    {
        if (document.SchemaVersion != 1)
            throw new InvalidDataException($"Threat knowledge-base schema {document.SchemaVersion} is unsupported.");
        if (string.IsNullOrWhiteSpace(document.DatabaseVersion) ||
            document.LastUpdatedUtc == default ||
            document.LastUpdatedUtc > DateTimeOffset.UtcNow.AddDays(1))
            throw new InvalidDataException("Threat knowledge-base version or update timestamp is invalid.");
        if (document.Categories.Count == 0 || document.Capabilities.Count == 0 || document.DetectionRules.Count == 0)
            throw new InvalidDataException("Threat categories, capabilities, and correlation rules are required.");
        if (document.Categories.Select(category => category.Id).Distinct(StringComparer.OrdinalIgnoreCase).Count() != document.Categories.Count ||
            document.Capabilities.Select(capability => capability.Id).Distinct(StringComparer.OrdinalIgnoreCase).Count() != document.Capabilities.Count ||
            document.Families.Select(family => family.Id).Distinct(StringComparer.OrdinalIgnoreCase).Count() != document.Families.Count)
            throw new InvalidDataException("Threat knowledge-base category, capability, and family IDs must be unique.");

        var categoryIds = document.Categories.Select(category => category.Id).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var capabilityIds = document.Capabilities.Select(capability => capability.Id).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var seenHashes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var familyNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var capability in document.Capabilities)
        {
            if (string.IsNullOrWhiteSpace(capability.Id) || string.IsNullOrWhiteSpace(capability.Name) ||
                string.IsNullOrWhiteSpace(capability.Meaning) || string.IsNullOrWhiteSpace(capability.WhyMalwareUsesIt) ||
                string.IsNullOrWhiteSpace(capability.LegitimateUses) || capability.SafeIndicators.Count == 0)
                throw new InvalidDataException("Every capability needs a definition, legitimate-use note, and safe indicator guidance.");
        }

        foreach (var rule in document.DetectionRules)
        {
            if (string.IsNullOrWhiteSpace(rule.Id) || rule.RequiredCapabilities.Count == 0 ||
                rule.MinimumMatches < 2 || rule.MinimumMatches > rule.RequiredCapabilities.Count ||
                rule.RequiredCapabilities.Any(capability => !capabilityIds.Contains(capability)))
                throw new InvalidDataException($"Threat detection rule '{rule.Id}' has invalid or insufficiently correlated signals.");
        }

        foreach (var family in document.Families)
        {
            if (string.IsNullOrWhiteSpace(family.Name) || !categoryIds.Contains(family.CategoryId) ||
                family.References.Count == 0 ||
                family.References.Any(reference => !Uri.TryCreate(reference, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps))
                throw new InvalidDataException($"Threat family '{family.Id}' has invalid category or source references.");
            foreach (var familyName in family.Aliases.Append(family.Name))
            {
                if (string.IsNullOrWhiteSpace(familyName) || !familyNames.Add(familyName.Trim()))
                    throw new InvalidDataException($"Threat family '{family.Name}' duplicates a family name or alias. Merge aliases into one record.");
            }
            if (family.KnownCapabilities.Any(capability => !capabilityIds.Contains(capability)) ||
                family.DetectionRules.Any(rule =>
                    rule.MinimumMatches < 1 ||
                    rule.MinimumMatches > rule.RequiredCapabilities.Count ||
                    rule.RequiredCapabilities.Any(capability => !capabilityIds.Contains(capability))))
                throw new InvalidDataException($"Threat family '{family.Name}' references an unknown capability or invalid rule.");
            foreach (var hash in family.Sha256Hashes)
            {
                if (!IsSha256(hash.Sha256) ||
                    !Uri.TryCreate(hash.SourceUrl, UriKind.Absolute, out var source) ||
                    source.Scheme != Uri.UriSchemeHttps ||
                    hash.LastUpdatedUtc == default ||
                    !seenHashes.Add(hash.Sha256))
                    throw new InvalidDataException($"Threat family '{family.Name}' contains an invalid or duplicate SHA-256 IOC.");
            }
        }
    }

    internal static bool IsSha256(string value) =>
        value.Length == 64 && value.All(Uri.IsHexDigit);
}

internal sealed class ThreatKnowledgeBaseProvider(Action<string> log)
{
    private readonly object _gate = new();
    private ThreatKnowledgeBase? _cached;
    private DateTime _loadedWriteTimeUtc;

    public ThreatKnowledgeBase Load()
    {
        var path = Path.Combine(AppContext.BaseDirectory, "ThreatKnowledgeBase.json");
        try
        {
            var writeTime = File.GetLastWriteTimeUtc(path);
            lock (_gate)
            {
                if (_cached is not null && writeTime == _loadedWriteTimeUtc)
                    return _cached;
            }

            var updated = ThreatKnowledgeBase.Load(path, supportsKnownHashMatches: true);
            lock (_gate)
            {
                _cached = updated;
                _loadedWriteTimeUtc = writeTime;
            }
            log($"Loaded Winvexa threat knowledge base {updated.Document.DatabaseVersion} ({updated.Document.Families.Count} family records; {updated.Document.Families.Sum(family => family.Sha256Hashes.Count)} sourced SHA-256 indicators).");
            return updated;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or JsonException or InvalidDataException)
        {
            log($"Threat knowledge base could not be loaded or validated: {exception}");
            throw new InvalidOperationException("The local threat knowledge base is unavailable or invalid. Winvexa did not run capability or hash classification.", exception);
        }
    }
}

internal static class ThreatClassificationPolicy
{
    public static int Rank(ThreatClassification classification) => classification switch
    {
        ThreatClassification.KnownMalicious => 6,
        ThreatClassification.HighConfidenceSuspicious => 5,
        ThreatClassification.Suspicious => 4,
        ThreatClassification.NeedsInvestigation => 3,
        ThreatClassification.LikelyLegitimate => 2,
        ThreatClassification.KnownLegitimate => 1,
        _ => 0
    };
}
