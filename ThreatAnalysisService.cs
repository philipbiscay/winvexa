using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32;

namespace Winvexa;

internal sealed record FileSignatureResult(bool IsValid, string Status, string Publisher);

internal sealed record ThreatObservation(string CapabilityId, string Evidence);

internal sealed record ThreatAnalysisResult(
    ThreatAnalysisFinding Finding,
    IReadOnlyList<string> InspectionNotes);

internal sealed class ThreatAnalysisService(ThreatKnowledgeBase knowledgeBase, Action<string> log)
{
    internal const string HighConfidenceContainmentRuleId = "unsigned-user-persistent-networked";
    private const uint TcpTableOwnerPidAll = 5;
    private const uint TcpEstablished = 5;
    private static readonly Guid AuthenticodePolicyId = new("00AAC56B-CD44-11D0-8CC2-00C04FC295EE");
    private static readonly HashSet<string> ExecutableExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".sys", ".ocx", ".scr", ".com"
    };

    public string DatabaseVersion => knowledgeBase.Document.DatabaseVersion;

    internal static bool MeetsAutomaticContainmentThreshold(ThreatAnalysisFinding finding) =>
        finding.Classification == ThreatClassification.HighConfidenceSuspicious &&
        finding.Confidence == ThreatConfidence.High &&
        finding.CanQuarantine &&
        finding.CorrelationRuleId == HighConfidenceContainmentRuleId &&
        new[]
        {
            "User-writable execution location",
            "Unsigned or invalidly signed executable",
            "Persistence",
            "Established IPv4 TCP connection"
        }
            .All(capability => finding.ObservedCapabilities.Contains(capability, StringComparer.OrdinalIgnoreCase));

    public async Task<ThreatAnalysisResult> AnalyzeFileAsync(
        string path,
        IProgress<string>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("Winvexa local threat analysis requires Windows.");

        var fullPath = Path.GetFullPath(path);
        if (!File.Exists(fullPath))
            throw new FileNotFoundException("The selected file is no longer available.", fullPath);

        progress?.Report("Calculating SHA-256 and verifying the selected file...");
        var hash = await ComputeSha256Async(fullPath, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        var signature = await Task.Run(() => ReadSignature(fullPath), cancellationToken).ConfigureAwait(false);

        progress?.Report("Checking selected file against the local knowledge base...");
        var knownFamily = knowledgeBase.FindFamilyBySha256(hash);
        var observations = new List<ThreatObservation>();
        var notes = new List<string>();

        progress?.Report("Taking a read-only process, persistence, and network snapshot...");
        await Task.Run(
            () => CollectSnapshotObservations(fullPath, signature, observations, notes, cancellationToken),
            cancellationToken).ConfigureAwait(false);
        var verificationHash = await ComputeSha256Async(fullPath, cancellationToken).ConfigureAwait(false);
        if (!verificationHash.Equals(hash, StringComparison.OrdinalIgnoreCase))
            throw new IOException("The selected file changed during analysis. No assessment was issued; select it again to retry.");

        var isWinvexaFile = IsWinvexaPath(fullPath);
        var isProtectedLocation = IsProtectedLocation(fullPath);
        var finding = Assess(
            knowledgeBase,
            fullPath,
            hash,
            signature,
            observations,
            knownFamily,
            isDemo: false,
            isWinvexaFile,
            isProtectedLocation);
        if (notes.Count == 0)
            notes.Add("Read-only point-in-time inspection completed for supported indicators.");

        log($"Local threat assessment for '{fullPath}': {finding.Classification} ({finding.Confidence}); SHA-256 {hash}; observed indicators {finding.ObservedCapabilities.Count}; related family similarities {finding.RelatedFamilies.Count}.");
        foreach (var note in notes)
            log($"Threat analysis limitation for '{fullPath}': {note}");
        return new ThreatAnalysisResult(finding, notes);
    }

    public IReadOnlyList<ThreatAnalysisFinding> CreateDemoFindings()
    {
        var simulatedRecord = new MalwareFamilyRecord(
            "test-only-hash",
            "Winvexa Synthetic Hash Test",
            [],
            "pua",
            "Harmless, in-memory test metadata used only to verify exact hash matching.",
            ["fileEncryption"],
            ["Synthetic test record; no malware sample or executable is present."],
            [],
            [],
            [],
            [],
            "Test only",
            [],
            ["https://attack.mitre.org/"],
            DateTimeOffset.UtcNow);
        var unknownHash = new string('0', 64);
        var knownHash = Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes("WINVEXA-HARMLESS-DEMO-MARKER")));
        var demoRecord = simulatedRecord with
        {
            Sha256Hashes =
            [
                new ThreatHashRecord(
                    knownHash,
                    "https://example.invalid/winvexa-harmless-demo-marker",
                    DateTimeOffset.UtcNow)
            ]
        };
        var demoKnowledgeBase = new ThreatKnowledgeBase(
            knowledgeBase.Document with
            {
                Families = [.. knowledgeBase.Document.Families, demoRecord]
            },
            supportsKnownHashMatches: true);
        return
        [
            Assess(demoKnowledgeBase, "[DEMO] harmless simulated file", knownHash,
                new FileSignatureResult(false, "DEMO: signature state simulated", "DEMO: no publisher"),
                [new ThreatObservation("fileEncryption", "DEMO: synthetic capability signal only")],
                demoKnowledgeBase.FindFamilyBySha256(knownHash), isDemo: true, isWinvexaFile: false, isProtectedLocation: false),
            Assess(knowledgeBase, "[DEMO] correlated suspicious activity", unknownHash,
                new FileSignatureResult(false, "DEMO: unsigned state simulated", "DEMO: unavailable"),
                [
                    new ThreatObservation("userWritableLocation", "DEMO: synthetic user-writable location"),
                    new ThreatObservation("unsignedExecutable", "DEMO: synthetic unsigned-file state"),
                    new ThreatObservation("persistence", "DEMO: synthetic startup persistence reference"),
                    new ThreatObservation("establishedTcpConnection", "DEMO: synthetic established connection")
                ],
                knownFamily: null, isDemo: true, isWinvexaFile: false, isProtectedLocation: false),
            Assess(knowledgeBase, "[DEMO] one low-confidence indicator", unknownHash,
                new FileSignatureResult(false, "DEMO: unsigned state simulated", "DEMO: unavailable"),
                [new ThreatObservation("userWritableLocation", "DEMO: synthetic location only")],
                knownFamily: null, isDemo: true, isWinvexaFile: false, isProtectedLocation: false),
            Assess(knowledgeBase, "[DEMO] trusted Windows example", unknownHash,
                new FileSignatureResult(true, "DEMO: valid Microsoft signature simulated", "Microsoft Corporation"),
                [],
                knownFamily: null, isDemo: true, isWinvexaFile: false, isProtectedLocation: true)
        ];
    }

    internal static ThreatAnalysisFinding Assess(
        ThreatKnowledgeBase knowledgeBase,
        string filePath,
        string sha256,
        FileSignatureResult signature,
        IReadOnlyList<ThreatObservation> observations,
        MalwareFamilyRecord? knownFamily,
        bool isDemo,
        bool isWinvexaFile,
        bool isProtectedLocation)
    {
        var scannedAt = DateTimeOffset.UtcNow;
        var capabilityNames = observations
            .Select(observation => observation.CapabilityId)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Where(knowledgeBase.Capabilities.ContainsKey)
            .Select(id => knowledgeBase.Capabilities[id].Name)
            .ToArray();
        var evidenceDetails = observations
            .Select(observation =>
                $"{(knowledgeBase.Capabilities.TryGetValue(observation.CapabilityId, out var capability) ? capability.Name : observation.CapabilityId)}: {observation.Evidence}")
            .ToArray();
        var knownFamilyCapabilities = knownFamily?.KnownCapabilities
            .Where(knowledgeBase.Capabilities.ContainsKey)
            .Select(id => knowledgeBase.Capabilities[id].Name)
            .ToArray() ?? [];

        var relatedFamilies = knowledgeBase.Document.Families
            .Select(family =>
            {
                var sharedCapabilities = family.KnownCapabilities
                    .Intersect(
                        observations.Select(observation => observation.CapabilityId),
                        StringComparer.OrdinalIgnoreCase)
                    .Where(knowledgeBase.Capabilities.ContainsKey)
                    .Select(id => knowledgeBase.Capabilities[id].Name)
                    .ToArray();
                return new ThreatFamilySimilarity(
                    family.Name,
                    sharedCapabilities,
                    family.References.FirstOrDefault() ?? string.Empty);
            })
            .Where(match => match.SharedCapabilities.Count >= 2)
            .OrderByDescending(match => match.SharedCapabilities.Count)
            .ThenBy(match => match.FamilyName, StringComparer.OrdinalIgnoreCase)
            .Take(5)
            .ToArray();

        ThreatClassification classification;
        ThreatConfidence confidence;
        string detectionName;
        string category;
        string reason;
        string recommendation;
        string source;
        var canQuarantine = false;
        string? correlationRuleId = null;

        if (knownFamily is not null)
        {
            classification = knownFamily.CategoryId.Equals("pua", StringComparison.OrdinalIgnoreCase) ||
                             knownFamily.CategoryId.Equals("adware", StringComparison.OrdinalIgnoreCase)
                ? ThreatClassification.PotentiallyUnwanted
                : ThreatClassification.KnownMalicious;
            confidence = ThreatConfidence.High;
            detectionName = knownFamily.Name;
            category = knowledgeBase.Categories[knownFamily.CategoryId].Name;
            reason = $"The file's SHA-256 exactly matches a sourced indicator in local family record '{knownFamily.Name}'. A hash match identifies the listed sample hash; it does not prove that other files or the whole device are infected.";
            recommendation = classification == ThreatClassification.KnownMalicious
                ? "Confirmed hash match. Contain and quarantine this exact file; do not run it."
                : "This exact hash matches a potentially unwanted application record. Review before taking action.";
            source = string.Join("; ", knownFamily.References);
            canQuarantine = !isDemo && !isWinvexaFile && !isProtectedLocation &&
                            classification == ThreatClassification.KnownMalicious;
        }
        else
        {
            var matchedRule = knowledgeBase.Document.DetectionRules
                .Where(rule => rule.RequiredCapabilities.Count(capability =>
                    observations.Any(observation => observation.CapabilityId.Equals(capability, StringComparison.OrdinalIgnoreCase))) >= rule.MinimumMatches)
                .OrderByDescending(rule => ThreatClassificationPolicy.Rank(rule.Classification))
                .ThenByDescending(rule => rule.Confidence)
                .FirstOrDefault();
            var microsoftWindowsFile = signature.IsValid &&
                                       signature.Publisher.Contains("Microsoft", StringComparison.OrdinalIgnoreCase) &&
                                       IsWindowsPath(filePath);

            if (matchedRule is not null)
            {
                correlationRuleId = matchedRule.Id;
                classification = matchedRule.Classification;
                confidence = matchedRule.Confidence;
                detectionName = matchedRule.Name;
                reason = matchedRule.Rationale;
                recommendation = "Review the correlated evidence and publisher. Quarantine is available only after explicit confirmation and is refused for Windows, installed-program, and Winvexa files.";
                source = $"Local correlation rule '{matchedRule.Id}' plus the local threat knowledge base.";
                canQuarantine = !isDemo && !isWinvexaFile && !isProtectedLocation &&
                                classification == ThreatClassification.HighConfidenceSuspicious;
            }
            else if (observations.Count >= 2)
            {
                classification = ThreatClassification.Suspicious;
                confidence = signature.IsValid ? ThreatConfidence.Medium : ThreatConfidence.Low;
                detectionName = "Multiple indicators require review";
                reason = signature.IsValid
                    ? $"Multiple independent point-in-time indicators were observed despite a valid signature from '{signature.Publisher}'. Signing is a mitigating signal, not proof of benign behavior, and these indicators are not proof of malware."
                    : "More than one independent point-in-time indicator was observed, but no local correlation rule or known malicious hash matched. These indicators are not proof of malware.";
                recommendation = "Review the file, signer, and observed indicators. No automatic action was taken.";
                source = "Local read-only system snapshot, Authenticode verification, and local threat knowledge base.";
            }
            else if (microsoftWindowsFile)
            {
                classification = ThreatClassification.KnownLegitimate;
                confidence = ThreatConfidence.High;
                detectionName = "Microsoft-signed Windows file";
                reason = "Windows Authenticode verification succeeded, the publisher is Microsoft, and the file is under the Windows directory. This is a legitimacy signal, not a guarantee that the file is currently uncompromised.";
                recommendation = "No Winvexa action recommended. Keep Windows Security and Microsoft Defender enabled.";
                source = "Local Windows Authenticode trust verification and file location.";
            }
            else if (signature.IsValid)
            {
                classification = ThreatClassification.LikelyLegitimate;
                confidence = ThreatConfidence.Medium;
                detectionName = "Validly signed file; no known malicious hash";
                reason = $"Windows Authenticode verification succeeded for publisher '{signature.Publisher}'. The publisher is not independently allow-listed by Winvexa, and a valid signature alone does not prove safety.";
                recommendation = "Review the publisher and expected purpose if this file was unexpected. No automatic action was taken.";
                source = "Local Windows Authenticode trust verification; local knowledge-base hash lookup.";
            }
            else if (observations.Count == 1)
            {
                classification = ThreatClassification.NeedsInvestigation;
                confidence = ThreatConfidence.Low;
                detectionName = "Single indicator requires investigation";
                reason = "One low-specificity indicator was observed. Legitimate Windows and third-party applications commonly produce similar behavior.";
                recommendation = "Verify the expected publisher and purpose. Do not treat this single indicator as a malware detection.";
                source = "Local read-only system snapshot.";
            }
            else
            {
                classification = ThreatClassification.NoThreatDetected;
                confidence = ThreatConfidence.Low;
                detectionName = "No known threat indicator detected";
                reason = "The selected file did not match a known SHA-256 indicator and no supported suspicious indicator was observed in this point-in-time snapshot. This is not a clean bill of health.";
                recommendation = "No Winvexa action recommended. Windows Defender remains the active antivirus scanner.";
                source = "Local SHA-256 comparison, Authenticode verification, and supported point-in-time indicators.";
            }
            category = "Unclassified";
        }

        if (isWinvexaFile || isProtectedLocation)
        {
            canQuarantine = false;
            if (isWinvexaFile)
                reason += " Winvexa's own executable is protected from quarantine.";
            else if (isProtectedLocation)
                reason += " Files in Windows and installed-program locations are protected from Winvexa quarantine.";
        }
        if (isDemo)
        {
            canQuarantine = false;
            recommendation = "DEMO only: no action is available or taken.";
            source = "Winvexa harmless synthetic test case; not a real file, sample, or threat-intelligence indicator.";
        }

        return new ThreatAnalysisFinding(
            filePath,
            detectionName,
            category,
            classification,
            confidence,
            sha256,
            signature.Status,
            signature.Publisher,
            capabilityNames,
            evidenceDetails,
            knownFamilyCapabilities,
            relatedFamilies,
            reason,
            recommendation,
            source,
            scannedAt,
            isDemo,
            canQuarantine)
        {
            Severity = knownFamily?.Severity ?? (classification is ThreatClassification.Suspicious or ThreatClassification.NeedsInvestigation
                ? "Undetermined"
                : "Informational"),
            CorrelationRuleId = correlationRuleId
        };
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

    private static FileSignatureResult ReadSignature(string path)
    {
        if (!ExecutableExtensions.Contains(Path.GetExtension(path)))
            return new FileSignatureResult(false, "Not a supported Windows executable; Authenticode not checked.", "Unavailable");

        var filePath = Marshal.StringToCoTaskMemUni(path);
        var fileInfo = new WinTrustFileInfo
        {
            StructSize = (uint)Marshal.SizeOf<WinTrustFileInfo>(),
            FilePath = filePath
        };
        var fileInfoPointer = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustFileInfo>());
        try
        {
            Marshal.StructureToPtr(fileInfo, fileInfoPointer, false);
            var trustData = new WinTrustData
            {
                StructSize = (uint)Marshal.SizeOf<WinTrustData>(),
                UiChoice = 2,
                RevocationChecks = 0,
                UnionChoice = 1,
                FileInfo = fileInfoPointer,
                StateAction = 0,
                ProviderFlags = 0x00001010
            };
            var result = WinVerifyTrust(IntPtr.Zero, AuthenticodePolicyId, ref trustData);
            var valid = result == 0;
            var status = valid
                ? "Valid Windows Authenticode signature (offline trust-cache check)."
                : $"Not verified by Windows Authenticode (status 0x{result:X8}).";
            var publisher = ReadSignerPublisher(path);
            return new FileSignatureResult(valid, status, publisher);
        }
        finally
        {
            Marshal.DestroyStructure<WinTrustFileInfo>(fileInfoPointer);
            Marshal.FreeHGlobal(fileInfoPointer);
            Marshal.FreeCoTaskMem(filePath);
        }
    }

    private static string ReadSignerPublisher(string path)
    {
        try
        {
            using var certificate = X509Certificate2.CreateFromSignedFile(path);
            return certificate.Subject;
        }
        catch (CryptographicException)
        {
            return "No embedded signer certificate";
        }
    }

    private static void CollectSnapshotObservations(
        string fullPath,
        FileSignatureResult signature,
        ICollection<ThreatObservation> observations,
        ICollection<string> notes,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (IsUserWritableLocation(fullPath))
            observations.Add(new ThreatObservation("userWritableLocation", "Selected file is located in a commonly user-writable folder."));
        if (ExecutableExtensions.Contains(Path.GetExtension(fullPath)) && !signature.IsValid)
            observations.Add(new ThreatObservation("unsignedExecutable", signature.Status));

        var processIds = new HashSet<int>();
        var processPathsIncomplete = false;
        try
        {
            foreach (var process in Process.GetProcesses())
            {
                cancellationToken.ThrowIfCancellationRequested();
                using (process)
                {
                    try
                    {
                        if (string.Equals(process.MainModule?.FileName, fullPath, StringComparison.OrdinalIgnoreCase))
                            processIds.Add(process.Id);
                    }
                    catch (Exception exception) when (
                        exception is InvalidOperationException or System.ComponentModel.Win32Exception or NotSupportedException)
                    {
                        processPathsIncomplete = true;
                    }
                }
            }
        }
        catch (Exception exception) when (exception is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            notes.Add($"Process inventory could not be fully read: {exception.Message}");
        }
        if (processPathsIncomplete)
            notes.Add("One or more process image paths could not be inspected due to process exit or access restrictions.");

        CollectStartupReferences(fullPath, observations, notes, cancellationToken);
        CollectServiceReferences(fullPath, observations, notes, cancellationToken);
        CollectScheduledTaskReferences(fullPath, observations, notes, cancellationToken);
        if (processIds.Count > 0)
        {
            try
            {
                var peers = GetEstablishedTcpPeers(processIds);
                if (peers.Count > 0)
                    observations.Add(new ThreatObservation(
                        "establishedTcpConnection",
                        $"Selected process has {peers.Count} established IPv4 TCP connection(s); connection direction, peer reputation, and payload intent were not checked."));
            }
            catch (Exception exception) when (exception is System.ComponentModel.Win32Exception or InvalidOperationException)
            {
                notes.Add($"Established IPv4 TCP connections could not be inspected: {exception.Message}");
            }
        }
        notes.Add("No process-memory, credential-store, file-write, keylogging, screen-capture, injection, or network-payload telemetry is collected.");
    }

    private static void CollectStartupReferences(
        string fullPath,
        ICollection<ThreatObservation> observations,
        ICollection<string> notes,
        CancellationToken cancellationToken)
    {
        foreach (var hive in new[] { RegistryHive.CurrentUser, RegistryHive.LocalMachine })
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                using var root = RegistryKey.OpenBaseKey(hive, RegistryView.Default);
                foreach (var name in new[] {
                             @"Software\Microsoft\Windows\CurrentVersion\Run",
                             @"Software\Microsoft\Windows\CurrentVersion\RunOnce",
                             @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
                         })
                {
                    using var key = root.OpenSubKey(name);
                    if (key is null)
                        continue;
                    foreach (var valueName in key.GetValueNames())
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        var value = key.GetValue(valueName, null, RegistryValueOptions.DoNotExpandEnvironmentNames)?.ToString();
                        if (ReferencesExecutable(value, fullPath))
                        {
                            observations.Add(new ThreatObservation("persistence", $"Registry startup value '{hive}\\{name}\\{valueName}' references this exact executable path."));
                            observations.Add(new ThreatObservation("startupModification", $"Registry startup value '{hive}\\{name}\\{valueName}' references this exact executable path."));
                        }
                    }
                }
            }
            catch (Exception exception) when (exception is UnauthorizedAccessException or System.Security.SecurityException or IOException)
            {
                notes.Add($"Some {hive} startup registry locations could not be inspected: {exception.Message}");
            }
        }
    }

    private static void CollectServiceReferences(
        string fullPath,
        ICollection<ThreatObservation> observations,
        ICollection<string> notes,
        CancellationToken cancellationToken)
    {
        try
        {
            using var root = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Default);
            using var services = root.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
            if (services is null)
                return;
            foreach (var serviceName in services.GetSubKeyNames())
            {
                cancellationToken.ThrowIfCancellationRequested();
                using var service = services.OpenSubKey(serviceName);
                var imagePath = service?.GetValue("ImagePath")?.ToString();
                if (ReferencesExecutable(imagePath, fullPath))
                {
                    observations.Add(new ThreatObservation("persistence", $"Service '{serviceName}' ImagePath references this exact executable path."));
                    observations.Add(new ThreatObservation("servicePersistence", $"Service '{serviceName}' ImagePath references this exact executable path."));
                }
            }
        }
        catch (Exception exception) when (exception is UnauthorizedAccessException or System.Security.SecurityException or IOException)
        {
            notes.Add($"Windows service image paths could not be fully inspected: {exception.Message}");
        }
    }

    private static void CollectScheduledTaskReferences(
        string fullPath,
        ICollection<ThreatObservation> observations,
        ICollection<string> notes,
        CancellationToken cancellationToken)
    {
        var taskRoot = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            "System32",
            "Tasks");
        if (!Directory.Exists(taskRoot))
        {
            notes.Add("The Windows scheduled-task store was unavailable.");
            return;
        }

        try
        {
            foreach (var taskPath in Directory.EnumerateFiles(taskRoot, "*", SearchOption.AllDirectories))
            {
                cancellationToken.ThrowIfCancellationRequested();
                try
                {
                    var info = new FileInfo(taskPath);
                    if (info.Length > 2 * 1024 * 1024)
                        continue;
                    var content = File.ReadAllText(taskPath);
                    if (ReferencesExecutable(content, fullPath))
                    {
                        observations.Add(new ThreatObservation("persistence", $"Scheduled-task definition '{Path.GetFileName(taskPath)}' references this exact executable path."));
                        observations.Add(new ThreatObservation("scheduledTaskPersistence", $"Scheduled-task definition '{Path.GetFileName(taskPath)}' references this exact executable path."));
                    }
                }
                catch (Exception exception) when (exception is UnauthorizedAccessException or IOException or System.Security.SecurityException)
                {
                    notes.Add($"A scheduled task could not be inspected: {exception.Message}");
                }
            }
        }
        catch (Exception exception) when (exception is UnauthorizedAccessException or IOException or System.Security.SecurityException)
        {
            notes.Add($"The scheduled-task store could not be fully enumerated: {exception.Message}");
        }
    }

    private static IReadOnlyList<string> GetEstablishedTcpPeers(IReadOnlySet<int> processIds)
    {
        var tableSize = 0;
        var result = GetExtendedTcpTable(IntPtr.Zero, ref tableSize, true, 2, TcpTableOwnerPidAll, 0);
        if (result != 122 && result != 0)
            throw new System.ComponentModel.Win32Exception(result, "Windows could not size the IPv4 TCP owner table.");
        if (tableSize <= sizeof(uint))
            return [];

        var table = Marshal.AllocHGlobal(tableSize);
        try
        {
            result = GetExtendedTcpTable(table, ref tableSize, true, 2, TcpTableOwnerPidAll, 0);
            if (result != 0)
                throw new System.ComponentModel.Win32Exception(result, "Windows could not read the IPv4 TCP owner table.");

            var count = Marshal.ReadInt32(table);
            var rowSize = Marshal.SizeOf<TcpRowOwnerPid>();
            var peers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            for (var index = 0; index < count; index++)
            {
                var rowPointer = IntPtr.Add(table, sizeof(uint) + index * rowSize);
                var row = Marshal.PtrToStructure<TcpRowOwnerPid>(rowPointer);
                if (row.State != TcpEstablished || !processIds.Contains(checked((int)row.OwningProcessId)))
                    continue;
                var address = new IPAddress(BitConverter.GetBytes(row.RemoteAddress));
                if (IPAddress.IsLoopback(address) || address.Equals(IPAddress.Any))
                    continue;
                peers.Add($"{address}:{NetworkToHostPort(row.RemotePort)}");
            }
            return peers.ToArray();
        }
        finally
        {
            Marshal.FreeHGlobal(table);
        }
    }

    private static int NetworkToHostPort(uint value)
    {
        var port = (ushort)value;
        return ((port & 0x00FF) << 8) | ((port & 0xFF00) >> 8);
    }

    private static bool ReferencesExecutable(string? value, string fullPath)
    {
        if (string.IsNullOrWhiteSpace(value))
            return false;
        var expanded = Environment.ExpandEnvironmentVariables(value);
        return expanded.Contains(fullPath, StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsUserWritableLocation(string path)
    {
        var roots = new[]
        {
            Path.GetTempPath(),
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) is { Length: > 0 } profile
                ? Path.Combine(profile, "Downloads")
                : string.Empty,
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData)
        };
        return roots.Where(root => !string.IsNullOrWhiteSpace(root))
            .Any(root => IsWithin(path, root));
    }

    internal static bool IsProtectedLocation(string path)
    {
        var roots = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86)
        };
        return roots.Where(root => !string.IsNullOrWhiteSpace(root))
            .Any(root => IsWithin(path, root));
    }

    private static bool IsWindowsPath(string path)
    {
        var root = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        return !string.IsNullOrWhiteSpace(root) && IsWithin(path, root);
    }

    private static bool IsWithin(string path, string root)
    {
        var canonicalRoot = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        var canonicalPath = Path.GetFullPath(path);
        return canonicalPath.StartsWith(canonicalRoot, StringComparison.OrdinalIgnoreCase) ||
               canonicalPath.Equals(canonicalRoot.TrimEnd(Path.DirectorySeparatorChar), StringComparison.OrdinalIgnoreCase);
    }

    internal static bool IsWinvexaPath(string path)
    {
        var currentPath = Environment.ProcessPath;
        if (string.IsNullOrWhiteSpace(currentPath))
            return false;
        var applicationDirectory = Path.GetDirectoryName(Path.GetFullPath(currentPath));
        return !string.IsNullOrWhiteSpace(applicationDirectory) && IsWithin(path, applicationDirectory);
    }

    private static int WinVerifyTrust(IntPtr window, [MarshalAs(UnmanagedType.LPStruct)] Guid actionId, ref WinTrustData trustData) =>
        OperatingSystem.IsWindows()
            ? WinVerifyTrustNative(window, actionId, ref trustData)
            : throw new PlatformNotSupportedException();

    [DllImport("wintrust.dll", EntryPoint = "WinVerifyTrust", ExactSpelling = true, PreserveSig = true)]
    private static extern int WinVerifyTrustNative(
        IntPtr window,
        [MarshalAs(UnmanagedType.LPStruct)] Guid actionId,
        ref WinTrustData trustData);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern int GetExtendedTcpTable(
        IntPtr tcpTable,
        ref int size,
        [MarshalAs(UnmanagedType.Bool)] bool order,
        int addressFamily,
        uint tableClass,
        uint reserved);

    [StructLayout(LayoutKind.Sequential)]
    private struct WinTrustFileInfo
    {
        public uint StructSize;
        public IntPtr FilePath;
        public IntPtr FileHandle;
        public IntPtr KnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WinTrustData
    {
        public uint StructSize;
        public IntPtr PolicyCallbackData;
        public IntPtr SipClientData;
        public uint UiChoice;
        public uint RevocationChecks;
        public uint UnionChoice;
        public IntPtr FileInfo;
        public uint StateAction;
        public IntPtr StateData;
        public IntPtr UrlReference;
        public uint ProviderFlags;
        public uint UiContext;
        public IntPtr SignatureSettings;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    private struct TcpRowOwnerPid
    {
        public uint State;
        public uint LocalAddress;
        public uint LocalPort;
        public uint RemoteAddress;
        public uint RemotePort;
        public uint OwningProcessId;
    }
}
