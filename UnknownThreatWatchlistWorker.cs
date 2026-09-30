using System.IO;
using System.Threading;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace Winvexa;

internal static class UnknownThreatWatchlistWorker
{
    internal static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(30);
    private const string MutexName = @"Local\Winvexa.UnknownThreatWatchlist";

    public static bool IsRunning
    {
        get
        {
            try
            {
                using var mutex = Mutex.OpenExisting(MutexName);
                return true;
            }
            catch (WaitHandleCannotBeOpenedException)
            {
                return false;
            }
            catch (UnauthorizedAccessException)
            {
                return false;
            }
        }
    }

    public static async Task<int> RunAsync(
        Action<string, string, string> notify,
        CancellationToken cancellationToken = default)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("The unknown threat watchlist requires Windows.");

        using var mutex = new Mutex(initiallyOwned: true, MutexName, out var createdNew);
        if (!createdNew)
            return 0;

        var appData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (string.IsNullOrWhiteSpace(appData))
            throw new InvalidOperationException("The signed-in user's Local AppData path is unavailable.");

        var root = Path.Combine(appData, "Winvexa");
        var logPath = Path.Combine(root, "Logs", "watchlist-worker.log");
        void Log(string message)
        {
            var line = $"[{DateTimeOffset.UtcNow:O}] {message}{Environment.NewLine}";
            Directory.CreateDirectory(Path.GetDirectoryName(logPath)!);
            File.AppendAllText(logPath, line);
        }

        var quarantineService = new ThreatQuarantineService(
            Path.Combine(root, "Quarantine"),
            message => Log($"[Security] {message}"));
        var watchlist = new UnknownThreatWatchlistService(
            Path.Combine(root, "Security", "UnknownThreatWatchlist.json"),
            quarantineService.RecordWatchlistEvent);
        var knowledgeBase = ThreatKnowledgeBase.LoadBundled();
        var analyzer = new ThreatAnalysisService(knowledgeBase, Log);
        Log($"Background watcher started. Database {knowledgeBase.Document.DatabaseVersion}; active watchlist entries {watchlist.LoadActive().Count}.");

        while (!cancellationToken.IsCancellationRequested)
        {
            await RunObservationCycleAsync(
                watchlist,
                quarantineService,
                analyzer,
                Log,
                notify,
                DateTimeOffset.UtcNow,
                cancellationToken);
            await Task.Delay(PollInterval, cancellationToken);
        }

        return 0;
    }

    internal static async Task RunObservationCycleAsync(
        UnknownThreatWatchlistService watchlist,
        ThreatQuarantineService quarantine,
        ThreatAnalysisService analyzer,
        Action<string> log,
        Action<string, string, string> notify,
        DateTimeOffset observedAtUtc,
        CancellationToken cancellationToken = default)
    {
        foreach (var entry in watchlist.LoadActive())
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                if (!File.Exists(entry.FilePath))
                {
                    log($"Watchlist entry '{entry.FilePath}' is unavailable. It remains pending and its observation period is not advanced.");
                    continue;
                }

                ThreatAnalysisResult result;
                try
                {
                    result = await analyzer.AnalyzeFileAsync(entry.FilePath, cancellationToken: cancellationToken);
                }
                catch (Exception exception) when (
                    exception is IOException or UnauthorizedAccessException or System.Security.SecurityException or InvalidOperationException)
                {
                    log($"Could not observe '{entry.FilePath}'; the entry remains pending and is not counted toward its observation period. {exception.Message}");
                    quarantine.RecordWatchlistEvent(
                        "Watchlist observation failed",
                        entry.FilePath,
                        $"The program could not be inspected on this cycle. Observation time was not counted. {exception.Message}");
                    continue;
                }

                var finding = result.Finding;
                if (finding.Classification == ThreatClassification.KnownMalicious ||
                    ThreatAnalysisService.MeetsAutomaticContainmentThreshold(finding))
                {
                    var claimedEntry = watchlist.RecordObservation(
                        entry.Id,
                        finding,
                        observedAtUtc,
                        PollInterval);
                    if (claimedEntry.Status is not ("Security Detection" or "Reassessment Required"))
                        continue;

                    var detection = quarantine.RecordDetection(finding);
                    if (quarantine.IsExactFileAllowed(finding.FilePath, finding.Sha256))
                    {
                        var allowed = quarantine.MarkDetectionAllowed(detection.Id);
                        const string allowedDetails = "This exact path and SHA-256 was explicitly allowed by the user. No quarantine or process termination was attempted; changed file hashes are evaluated independently.";
                        notify(
                            finding.DetectionName,
                            finding.FilePath,
                            $"High-confidence activity was observed in a file the user explicitly allowed. Winvexa did not quarantine or stop this exact path and SHA-256. {allowedDetails}");
                        watchlist.LinkDetection(entry.Id, allowed.Id, finding, allowedDetails, "User Allowed");
                        RecordScanCompletion(
                            quarantine,
                            allowed.Id,
                            $"The watchlist threshold was reached, but the exact file-specific user allowance was honored. {allowedDetails}",
                            log);
                        continue;
                    }

                    QuarantineRecord record;
                    try
                    {
                        record = await quarantine.QuarantineAsync(
                            finding,
                            detection.Id,
                            attemptProcessTermination: true,
                            cancellationToken: cancellationToken,
                            allowCorrelatedBehaviorContainment: finding.Classification != ThreatClassification.KnownMalicious);
                    }
                    catch (Exception exception) when (
                        exception is IOException or UnauthorizedAccessException or InvalidOperationException or System.Security.SecurityException)
                    {
                        quarantine.RecordContainmentFailure(detection.Id, exception.Message);
                            notify(
                                finding.DetectionName,
                                finding.FilePath,
                                $"{(finding.Classification == ThreatClassification.KnownMalicious ? "A confirmed threat was detected" : "High-confidence suspicious behavior was detected")}, but containment failed: {exception.Message}. Open Winvexa > Antivirus & Security > Quarantine for details.");
                            watchlist.LinkDetection(
                            entry.Id,
                            detection.Id,
                            finding,
                            $"Threat threshold reached, but containment failed: {exception.Message}",
                            "Containment Failed");
                        RecordScanCompletion(
                            quarantine,
                            detection.Id,
                            $"Background watchlist detected {finding.DisplayClassification}, but containment failed: {exception.Message}",
                            log);
                        log($"Containment failed for watchlist entry '{finding.FilePath}': {exception}");
                        continue;
                    }

                    var detail = record.Status == "Quarantined"
                        ? $"Threat detected and quarantined. {record.ContainmentResult}"
                        : $"Threat file was quarantined, but process containment could not be verified. {record.ContainmentResult}";
                    var alert = finding.Classification == ThreatClassification.KnownMalicious
                        ? $"Confirmed threat detected. {detail}"
                        : $"High-confidence suspicious behavior detected; this is not a confirmed malware-family attribution. {detail}";
                    notify(finding.DetectionName, finding.FilePath, alert);
                    watchlist.LinkDetection(
                        entry.Id,
                        record.Id,
                        finding,
                        detail,
                        record.Status == "Quarantined" ? "Quarantined" : "Containment Failed");
                    RecordScanCompletion(
                        quarantine,
                        record.Id,
                        $"Background watchlist detected {finding.DisplayClassification}; file quarantine completed. {detail}",
                        log);
                    continue;
                }

                var updated = watchlist.RecordObservation(entry.Id, finding, observedAtUtc, PollInterval);
                if (updated.Status == "Reassessment Required" &&
                    UnknownThreatWatchlistService.ShouldObserve(finding))
                {
                    var reassessed = watchlist.Enroll(finding);
                    if (reassessed is not null)
                        log($"Changed file identity for '{finding.FilePath}' was enrolled as a new watchlist item ({reassessed.Id}).");
                }
            }
            catch (Exception exception) when (
                exception is IOException or UnauthorizedAccessException or InvalidOperationException or System.Security.SecurityException or System.Text.Json.JsonException)
            {
                log($"Watchlist processing failed for '{entry.FilePath}'; this entry was skipped and remaining entries will continue. {exception}");
                try
                {
                    quarantine.RecordWatchlistEvent(
                        "Watchlist observation failed",
                        entry.FilePath,
                        $"The observation cycle failed; no observation time was credited. {exception.Message}");
                }
                catch (Exception eventException) when (
                    eventException is IOException or UnauthorizedAccessException or System.Security.SecurityException)
                {
                    log($"Could not record the watchlist failure in the security-event store: {eventException}");
                }
            }
        }
    }

    private static void RecordScanCompletion(
        ThreatQuarantineService quarantine,
        string recordId,
        string details,
        Action<string> log)
    {
        try
        {
            quarantine.RecordScanCompletion(recordId, details);
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or System.Security.SecurityException)
        {
            log($"A watchlist scan-completion event could not be recorded for detection '{recordId}': {exception}");
        }
    }

    public static void ShowNotification(string threatName, string filePath, string details)
    {
        var window = new Window
        {
            Title = "Winvexa security notification",
            Width = 430,
            SizeToContent = SizeToContent.Height,
            MinHeight = 180,
            MaxHeight = 420,
            ResizeMode = ResizeMode.NoResize,
            WindowStartupLocation = WindowStartupLocation.Manual,
            Topmost = true,
            ShowInTaskbar = false,
            Background = new SolidColorBrush(Color.FromRgb(24, 37, 54)),
            Foreground = Brushes.White
        };
        var workArea = SystemParameters.WorkArea;
        window.Left = workArea.Right - window.Width - 18;
        window.Top = workArea.Bottom - 220;

        var content = new StackPanel { Margin = new Thickness(18) };
        content.Children.Add(new TextBlock
        {
            Text = "Winvexa security alert",
            FontSize = 19,
            FontWeight = FontWeights.Bold
        });
        content.Children.Add(new TextBlock
        {
            Text = threatName,
            FontSize = 14,
            FontWeight = FontWeights.SemiBold,
            Margin = new Thickness(0, 8, 0, 0)
        });
        content.Children.Add(new TextBlock
        {
            Text = $"{threatName}{Environment.NewLine}{Path.GetFileName(filePath)}",
            Foreground = new SolidColorBrush(Color.FromRgb(205, 216, 228)),
            TextTrimming = TextTrimming.CharacterEllipsis,
            Margin = new Thickness(0, 4, 0, 0)
        });
        content.Children.Add(new TextBlock
        {
            Text = details,
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 8, 0, 0)
        });
        content.Children.Add(new TextBlock
        {
            Text = "Open Winvexa > Antivirus & Security > Quarantine for details.",
            Foreground = new SolidColorBrush(Color.FromRgb(205, 216, 228)),
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 8, 0, 0)
        });
        var closeButton = new Button
        {
            Content = "Dismiss",
            Width = 82,
            HorizontalAlignment = HorizontalAlignment.Right,
            Margin = new Thickness(0, 12, 0, 0),
            Padding = new Thickness(10, 6, 10, 6)
        };
        closeButton.Click += (_, _) => window.Close();
        content.Children.Add(closeButton);
        window.Content = content;

        window.Show();
    }
}
