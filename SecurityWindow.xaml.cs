using System.Diagnostics;
using System.Collections.ObjectModel;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;
using Microsoft.Win32;

namespace Winvexa;

public partial class SecurityWindow : Window
{
    private readonly MaintenanceService _service;
    private readonly Action<string> _writeLog;
    private readonly bool _isAdministrator;
    private readonly Func<string, string, bool> _requestElevation;
    private readonly string? _startupAction;
    private readonly string? _startupTarget;
    private readonly ThreatKnowledgeBaseProvider _threatKnowledgeBaseProvider;
    private readonly ThreatQuarantineService _threatQuarantineService;
    private readonly UnknownThreatWatchlistService _watchlistService;
    private readonly ObservableCollection<ThreatAnalysisFinding> _localFindings = [];
    private readonly ObservableCollection<QuarantineRecord> _quarantineRecords = [];
    private readonly ObservableCollection<UnknownThreatWatchRecord> _watchlistRecords = [];
    private readonly ObservableCollection<UnknownThreatWatchRecord> _watchlistHistoryRecords = [];
    private readonly Dictionary<ThreatAnalysisFinding, IReadOnlyList<string>> _inspectionNotes = [];
    private readonly DispatcherTimer _scanHeartbeat;
    private readonly DispatcherTimer _watchlistRefreshTimer;
    private ThreatAnalysisService? _threatAnalysisService;
    private CancellationTokenSource? _operationCancellation;
    private bool _busy;
    private bool _stopping;
    private string _currentOperation = string.Empty;

    internal SecurityWindow(
        MaintenanceService service,
        Action<string> writeLog,
        bool isAdministrator,
        Func<string, string, bool> requestElevation,
        string? startupAction = null,
        string? startupTarget = null)
    {
        InitializeComponent();
        GlassThemeService.ApplyToWindow(this);
        _service = service;
        _writeLog = writeLog;
        _isAdministrator = isAdministrator;
        _requestElevation = requestElevation;
        _startupAction = startupAction;
        _startupTarget = startupTarget;
        _threatKnowledgeBaseProvider = new ThreatKnowledgeBaseProvider(
            message => _writeLog($"[Local Threat Analysis] {message}"));
        _threatQuarantineService = new ThreatQuarantineService(
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Winvexa", "Quarantine"),
            message => _writeLog($"[Local Threat Analysis] {message}"));
        _watchlistService = new UnknownThreatWatchlistService(
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Winvexa", "Security", "UnknownThreatWatchlist.json"),
            _threatQuarantineService.RecordWatchlistEvent);
        LocalFindingsList.ItemsSource = _localFindings;
        QuarantineItemsList.ItemsSource = _quarantineRecords;
        WatchlistItemsList.ItemsSource = _watchlistRecords;
        WatchlistHistoryList.ItemsSource = _watchlistHistoryRecords;
        _scanHeartbeat = new DispatcherTimer { Interval = TimeSpan.FromSeconds(15) };
        _scanHeartbeat.Tick += (_, _) =>
        {
            if (_busy && !_stopping &&
                _currentOperation.Contains("Scan", StringComparison.OrdinalIgnoreCase))
            {
                OperationStatusText.Text =
                    $"Scanning · {_currentOperation} is still running. Exact scan progress is unavailable to Winvexa.";
                Log("Microsoft Defender scan remains in progress; the scan process has not exited. Exact progress is unavailable.");
            }
        };
        _watchlistRefreshTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(30) };
        _watchlistRefreshTimer.Tick += (_, _) => RefreshWatchlistView();
        Loaded += async (_, _) =>
        {
            Log($"Security page opened. Startup action: {_startupAction ?? "none"}.");
            RefreshQuarantineView();
            RefreshWatchlistView();
            _watchlistRefreshTimer.Start();
            await RefreshStatusAsync();
            switch (_startupAction)
            {
                case "quick":
                    await StartScanAsync(fullScan: false, null);
                    break;
                case "full":
                    await StartScanAsync(fullScan: true, null);
                    break;
                case "custom" when !string.IsNullOrWhiteSpace(_startupTarget):
                    await StartScanAsync(fullScan: false, _startupTarget);
                    break;
                case "update":
                    await UpdateSignaturesAsync();
                    break;
            }
        };
    }

    public void AppendLog(string line)
    {
        if (!Dispatcher.CheckAccess())
        {
            Dispatcher.BeginInvoke(new Action(() => AppendLog(line)));
            return;
        }

        ActivityLogText.AppendText(line + Environment.NewLine);
        ActivityLogText.ScrollToEnd();
    }

    private async Task RefreshStatusAsync()
    {
        await RunSecurityOperationAsync("Checking Windows Security protection status", false, async () =>
        {
            var status = await _service.GetDefenderSecurityStatusAsync();
            DisplayStatus(status);
            Log($"Security status verified: {status.OverallStatus}.");
        });
    }

    private void DisplayStatus(DefenderSecurityStatus status)
    {
        var protectedState = status.OverallStatus.Equals("Protected", StringComparison.OrdinalIgnoreCase);
        var threatDetected = status.OverallStatus.Equals("Threat detected", StringComparison.OrdinalIgnoreCase);
        OverallStatusText.Text = status.OverallStatus;
        OverallStatusIndicator.Fill = new SolidColorBrush(threatDetected
            ? Color.FromRgb(226, 76, 86)
            : protectedState
                ? Color.FromRgb(52, 201, 129)
                : Color.FromRgb(237, 173, 67));
        OverallStatusDetailText.Text =
            $"Microsoft Defender Antivirus · {status.RunningMode} mode · Engine {status.EngineVersion}";
        RealTimeStatusText.Text = FormatEnabled(status.RealTimeProtectionEnabled);
        AntivirusStatusText.Text = status.AntivirusEnabled && status.ServiceEnabled
            ? "Active"
            : "Inactive or unavailable";
        IntelligenceStatusText.Text = status.SignatureAgeDays is int age
            ? $"{status.SignatureVersion} · updated {FormatDate(status.SignatureLastUpdated)} · {age} day(s) old"
            : "Unable to verify";
        WindowsSecurityStatusText.Text = status.ServiceEnabled
            ? "Defender service available"
            : "Defender service unavailable";
        LastQuickScanText.Text = FormatDate(status.LastQuickScan);
        LastFullScanText.Text = FormatDate(status.LastFullScan);

        if (status.ActiveThreats.Count > 0)
        {
            ThreatStatusText.Text = $"{status.ActiveThreats.Count} active detection(s). Review Protection history and Windows Security.";
            Log($"Threat status verified: {status.ActiveThreats.Count} active Defender detection(s) reported by Windows.");
        }
        else if (status.RecentDetections.Count > 0)
        {
            ThreatStatusText.Text =
                $"No active threats reported. Windows returned {status.RecentDetections.Count} recent protection-history detection(s); review the history below.";
        }
        else
        {
            ThreatStatusText.Text = "No active threats or recent detections were reported by Microsoft Defender.";
        }

        var history = new List<string>();
        if (status.ActiveThreats.Count > 0)
        {
            history.Add("ACTIVE DETECTIONS");
            history.AddRange(status.ActiveThreats.Select(FormatThreat));
        }
        if (status.RecentDetections.Count > 0)
        {
            if (history.Count > 0)
                history.Add(string.Empty);
            history.Add("RECENT PROTECTION HISTORY");
            history.AddRange(status.RecentDetections.Select(FormatThreat));
        }
        if (history.Count == 0)
            history.Add("Microsoft Defender reported no active threats or recent detections.");
        ProtectionHistoryText.Text = string.Join(Environment.NewLine + Environment.NewLine, history);
    }

    private static string FormatThreat(DefenderThreatInfo threat)
    {
        var detected = threat.DetectedAt is DateTimeOffset time
            ? time.LocalDateTime.ToString("g")
            : "time unavailable";
        var action = threat.ActionSucceeded is bool succeeded
            ? succeeded ? "Defender action succeeded" : "Defender action not confirmed"
            : "action status unavailable";
        var resource = string.IsNullOrWhiteSpace(threat.Resource) || threat.Resource == "Unavailable"
            ? "resource unavailable"
            : threat.Resource;
        return $"{threat.ThreatName} (ID {threat.ThreatId}, severity {threat.Severity}) · {detected} · {action}{Environment.NewLine}  {resource}";
    }

    private static string FormatEnabled(bool enabled) => enabled ? "On" : "Off";

    private static string FormatDate(DateTimeOffset? date) =>
        date is DateTimeOffset value ? value.LocalDateTime.ToString("g") : "No scan time reported";

    private async Task RunSecurityOperationAsync(
        string name,
        bool cancellableScan,
        Func<Task> operation,
        bool allowCancellationOutcome = false)
    {
        if (_busy)
            return;

        using var cancellation = new CancellationTokenSource();
        _operationCancellation = cancellation;
        _busy = true;
        _stopping = false;
        _currentOperation = name;
        SetActionButtonsEnabled(false);
        StopButton.Content = "Stop";
        StopButton.IsEnabled = cancellableScan;
        StopButton.Visibility = cancellableScan ? Visibility.Visible : Visibility.Collapsed;
        OperationProgress.IsIndeterminate = true;
        OperationStatusText.Text = $"Preparing · {name}...";
        if (cancellableScan)
            _scanHeartbeat.Start();
        Log($"{name} started.");
        try
        {
            using (OperationCancellationContext.Enter(cancellation.Token))
            {
                await operation();
                if (!allowCancellationOutcome)
                    OperationCancellationContext.ThrowIfCancellationRequested();
            }
            if (cancellation.IsCancellationRequested)
            {
                OperationStatusText.Text = $"{name} cancelled. Results may be incomplete; review the activity log.";
                Log($"{name} ended after cancellation; the result is incomplete.");
            }
            else
            {
                if (string.IsNullOrWhiteSpace(OperationStatusText.Text) ||
                    OperationStatusText.Text.StartsWith("Preparing", StringComparison.Ordinal))
                    OperationStatusText.Text = $"{name} completed.";
                Log($"{name} operation completed.");
            }
        }
        catch (OperationCanceledException) when (_stopping)
        {
            OperationStatusText.Text = "Cancelled · Scan stopped. Results may be incomplete; review Protection history in Windows Security.";
            Log($"{name} stopped after the Microsoft Defender scan process exited following cancellation. Results may be incomplete.");
        }
        catch (Exception exception) when (!_stopping || exception is not OperationCanceledException)
        {
            OperationStatusText.Text = $"Error · {_currentOperation} failed: {exception.Message} Review the activity log for recovery details.";
            if (name.StartsWith("Checking Windows Security", StringComparison.Ordinal))
                SetUnableToVerify(exception.Message);
            Log($"{name} failed. Verification failed: {exception}");
        }
        finally
        {
            SetScanButtonProcessing(false);
            _scanHeartbeat.Stop();
            _busy = false;
            _operationCancellation = null;
            _stopping = false;
            StopButton.Visibility = Visibility.Collapsed;
            StopButton.IsEnabled = false;
            OperationProgress.IsIndeterminate = false;
            OperationProgress.Value = 0;
            SetActionButtonsEnabled(true);
        }
    }

    private void SetUnableToVerify(string detail)
    {
        OverallStatusText.Text = "Unable to verify";
        OverallStatusIndicator.Fill = new SolidColorBrush(Color.FromRgb(115, 131, 151));
        OverallStatusDetailText.Text = detail;
        RealTimeStatusText.Text = "Unable to verify";
        AntivirusStatusText.Text = "Unable to verify";
        IntelligenceStatusText.Text = "Unable to verify";
        WindowsSecurityStatusText.Text = "Unable to verify";
        ThreatStatusText.Text = "Unable to verify";
        LastQuickScanText.Text = "Unable to verify";
        LastFullScanText.Text = "Unable to verify";
        ProtectionHistoryText.Text = $"Unable to verify Microsoft Defender protection history.{Environment.NewLine}{detail}";
    }

    private void SetActionButtonsEnabled(bool enabled)
    {
        RefreshStatusButton.IsEnabled = enabled;
        QuickScanButton.IsEnabled = enabled;
        FullScanButton.IsEnabled = enabled;
        CustomScanButton.IsEnabled = enabled;
        ScanPathButton.IsEnabled = enabled;
        UpdateSignaturesButton.IsEnabled = enabled;
        AnalyzeFileButton.IsEnabled = enabled;
        RunDemoTestsButton.IsEnabled = enabled;
        ShowThreatKnowledgeBaseButton.IsEnabled = enabled;
        QuarantineButton.IsEnabled = enabled && LocalFindingsList.SelectedItem is ThreatAnalysisFinding finding &&
                                     finding.CanQuarantine && !finding.IsDemo;
        RefreshQuarantineButton.IsEnabled = enabled;
        SetQuarantineActionButtons(enabled);
        OpenWindowsSecurityButton.IsEnabled = true;
    }

    private async void AnalyzeFile_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Title = "Choose a file for Winvexa's read-only local analysis",
            CheckFileExists = true,
            Multiselect = false
        };
        if (dialog.ShowDialog(this) != true)
            return;

        await RunSecurityOperationAsync("Local read-only threat analysis", false, async () =>
        {
            LocalAnalysisStatus("Loading the local threat knowledge base...");
            var analyzer = GetThreatAnalysisService();
            var progress = new Progress<string>(message =>
            {
                LocalAnalysisStatus(message);
                OperationStatusText.Text = message;
            });
            var result = await analyzer.AnalyzeFileAsync(dialog.FileName, progress);
            var automaticContainment = result.Finding.Classification == ThreatClassification.KnownMalicious ||
                                       ThreatAnalysisService.MeetsAutomaticContainmentThreshold(result.Finding);
            if (automaticContainment)
                OperationStatusText.Text = $"Threat Detected · {result.Finding.DetectionName}. Preparing immediate containment.";
            var record = _threatQuarantineService.RecordDetection(result.Finding);
            AddLocalFinding(result.Finding, result.InspectionNotes);
            var disposition = "No automatic changes were made.";
            if (automaticContainment)
            {
                if (_threatQuarantineService.IsExactFileAllowed(result.Finding.FilePath, result.Finding.Sha256))
                {
                    record = _threatQuarantineService.MarkDetectionAllowed(record.Id);
                    disposition = "This exact path and SHA-256 match a user-approved file-specific allowance; no action was taken.";
                    OperationStatusText.Text = "User Allowed · This exact path and SHA-256 were previously approved; no containment was attempted.";
                }
                else
                {
                    try
                    {
                        OperationStatusText.Text = "Quarantining · Winvexa is verifying the selected file and attempting safe containment.";
                        record = await _threatQuarantineService.QuarantineAsync(
                            result.Finding,
                            record.Id,
                            attemptProcessTermination: true,
                            allowCorrelatedBehaviorContainment: result.Finding.Classification != ThreatClassification.KnownMalicious);
                        OperationStatusText.Text = record.Status == "Quarantined"
                            ? "Quarantined · Winvexa verified the file in protected quarantine."
                            : $"Containment Failed · The file action was not fully verified. {record.ContainmentResult}";
                        disposition = result.Finding.Classification == ThreatClassification.KnownMalicious
                            ? record.Status == "Quarantined"
                                ? $"Threat detected and quarantined. {record.ContainmentResult}"
                                : $"Threat file quarantined; running-process containment could not be verified. {record.ContainmentResult}"
                            : record.Status == "Quarantined"
                                ? $"High-confidence suspicious activity was contained and quarantined. This is not a confirmed malware-family attribution. {record.ContainmentResult}"
                                : $"High-confidence suspicious activity was quarantined, but process containment could not be verified. {record.ContainmentResult}";
                    }
                    catch (Exception exception) when (
                        exception is IOException or UnauthorizedAccessException or InvalidOperationException or System.Security.SecurityException)
                    {
                        record = _threatQuarantineService.RecordContainmentFailure(record.Id, exception.Message);
                        OperationStatusText.Text = $"Containment Failed · {exception.Message}";
                        disposition = $"Threat detected, but containment failed: {exception.Message}";
                        Log($"Containment failed for '{result.Finding.FilePath}': {exception}");
                    }
                }
                ShowThreatNotification(record, disposition);
            }
            else if (UnknownThreatWatchlistService.ShouldObserve(result.Finding))
            {
                var watchEntry = _watchlistService.Enroll(result.Finding);
                if (watchEntry is not null)
                {
                    disposition = $"Unknown program added to the 30-day watchlist. Observation is active only while the signed-in Windows session's background watcher is running. {watchEntry.DisplayStatus}.";
                    OperationStatusText.Text = $"Under Observation · {watchEntry.DisplayStatus}. Normal antivirus protection remains active.";
                    RefreshWatchlistView(watchEntry.Id);
                }
            }
            else if (result.Finding.Classification is ThreatClassification.Suspicious or
                     ThreatClassification.HighConfidenceSuspicious or
                     ThreatClassification.NeedsInvestigation)
            {
                disposition = "Suspicious activity recorded for review; it was not automatically quarantined.";
                OperationStatusText.Text = "Suspicious · Recorded for review; automatic quarantine was not triggered.";
            }

            _threatQuarantineService.RecordScanCompletion(
                record.Id,
                $"On-demand file scan completed as {result.Finding.DisplayClassification}. {disposition}");
            RefreshQuarantineView(record.Id);
            LocalAnalysisStatus($"{result.Finding.DisplayClassification} · {result.Finding.Confidence} confidence · {disposition}");
            Log($"Local analysis completed: {result.Finding.DisplayClassification} ({result.Finding.Confidence}); '{result.Finding.FilePath}'; SHA-256 {result.Finding.Sha256}; {disposition}");
            if (!automaticContainment &&
                !UnknownThreatWatchlistService.ShouldObserve(result.Finding) &&
                result.Finding.Classification is not (ThreatClassification.Suspicious or
                    ThreatClassification.HighConfidenceSuspicious or ThreatClassification.NeedsInvestigation))
                OperationStatusText.Text = $"Completed · {result.Finding.DisplayClassification} ({result.Finding.Confidence} confidence). {disposition}";
        });
    }

    private async void RunDemoTests_Click(object sender, RoutedEventArgs e)
    {
        await RunSecurityOperationAsync("Safe TEST/DEMO threat scenarios", false, () =>
        {
            var analyzer = GetThreatAnalysisService();
            foreach (var finding in analyzer.CreateDemoFindings())
                AddLocalFinding(finding, ["Synthetic scenario only; it did not inspect a file, start a process, or change system state."]);
            LocalAnalysisStatus("DEMO complete. Every displayed scenario is synthetic and cannot be quarantined.");
            Log("Ran four harmless in-memory TEST/DEMO scenarios; no sample files, processes, persistence entries, or network activity were created.");
            return Task.CompletedTask;
        });
    }

    private async void ShowThreatKnowledgeBase_Click(object sender, RoutedEventArgs e)
    {
        await RunSecurityOperationAsync("Loading local threat knowledge base", false, () =>
        {
            var knowledgeBase = _threatKnowledgeBaseProvider.Load();
            _ = GetThreatAnalysisService();
            ThreatKnowledgeBaseStatusText.Text =
                $"Version {knowledgeBase.Document.DatabaseVersion} · updated {knowledgeBase.Document.LastUpdatedUtc:yyyy-MM-dd} · {knowledgeBase.Document.Families.Count} family records · {knowledgeBase.Document.Families.Sum(family => family.Sha256Hashes.Count)} sourced SHA-256 hashes.";
            ThreatKnowledgeBaseDetailsText.Text = FormatKnowledgeBaseDetails(knowledgeBase);
            if (_threatQuarantineService.RecordDatabaseVersion(
                    knowledgeBase.Document.DatabaseVersion,
                    knowledgeBase.Document.Families.Count))
                RefreshQuarantineView();
            LocalAnalysisStatus("Local threat knowledge base validated and loaded. Family capabilities are context, not attribution.");
            Log($"Loaded knowledge base version {knowledgeBase.Document.DatabaseVersion}.");
            return Task.CompletedTask;
        });
    }

    private async void QuarantineSelected_Click(object sender, RoutedEventArgs e)
    {
        if (LocalFindingsList.SelectedItem is not ThreatAnalysisFinding finding ||
            !finding.CanQuarantine ||
            finding.IsDemo)
            return;
        var response = MessageBox.Show(
            this,
            $"Quarantine this file by moving it out of its original folder? This does not delete it.{Environment.NewLine}{Environment.NewLine}" +
            $"Detection: {finding.DetectionName}{Environment.NewLine}Classification: {finding.Classification} ({finding.Confidence})" +
            $"{Environment.NewLine}SHA-256: {finding.Sha256}{Environment.NewLine}Path: {finding.FilePath}" +
            $"{Environment.NewLine}{Environment.NewLine}Winvexa will re-check the SHA-256 and will refuse Windows, installed-program, or Winvexa files.",
            "Confirm quarantine",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);
        if (response != MessageBoxResult.Yes)
            return;

        await RunSecurityOperationAsync("Quarantining reviewed file", false, async () =>
        {
            var detectedRecord = _quarantineRecords.FirstOrDefault(item =>
                item.OriginalPath.Equals(finding.FilePath, StringComparison.OrdinalIgnoreCase) &&
                item.Sha256.Equals(finding.Sha256, StringComparison.OrdinalIgnoreCase));
            QuarantineRecord record;
            try
            {
                OperationStatusText.Text = "Quarantining · Winvexa is verifying and moving the reviewed file into protected storage.";
                record = await _threatQuarantineService.QuarantineAsync(finding, detectedRecord?.Id);
            }
            catch (Exception exception) when (
                exception is IOException or UnauthorizedAccessException or InvalidOperationException or System.Security.SecurityException)
            {
                if (detectedRecord is not null &&
                    _threatQuarantineService.LoadDetectionRecords()
                        .FirstOrDefault(item => item.Id == detectedRecord.Id)?.Status != "Containment Failed")
                    _threatQuarantineService.RecordContainmentFailure(detectedRecord.Id, exception.Message);
                Log($"User-requested quarantine failed for '{finding.FilePath}': {exception}");
                throw;
            }
            OperationStatusText.Text = record.Status == "Quarantined"
                ? "Quarantined · Winvexa verified the file in protected quarantine."
                : $"Containment Failed · The file action was not fully verified. {record.ContainmentResult}";
            var index = _localFindings.IndexOf(finding);
            if (index >= 0)
            {
                var updated = finding with
                {
                    CanQuarantine = false,
                    RecommendedAction = $"Quarantined at {record.QuarantinedAtUtc:O}. The action record is stored in Winvexa's local quarantine folder."
                };
                _localFindings[index] = updated;
                LocalFindingsList.SelectedItem = updated;
            }
            RefreshQuarantineView(record.Id);
            LocalAnalysisStatus($"Quarantine complete. File moved to {record.QuarantinedPath}; action recorded.");
            Log($"Quarantine completed and recorded: '{record.OriginalPath}' -> '{record.QuarantinedPath}'.");
        });
    }

    private void RefreshQuarantine_Click(object sender, RoutedEventArgs e) =>
        RefreshQuarantineView();

    private void RefreshQuarantineView(string? selectId = null)
    {
        try
        {
            var records = _threatQuarantineService.LoadDetectionRecords()
                .OrderByDescending(record => record.DetectedAtUtc)
                .ToArray();
            _quarantineRecords.Clear();
            foreach (var record in records)
                _quarantineRecords.Add(record);
            SecurityEventsText.Text = string.Join(
                Environment.NewLine,
                _threatQuarantineService.LoadEvents()
                    .OrderByDescending(item => item.OccurredAtUtc)
                    .Take(250)
                    .Select(item => $"{item.OccurredAtUtc.ToLocalTime():g} · {item.EventType} · {item.DetectionName} · {item.FileName}{Environment.NewLine}  {item.Details}"));
            QuarantineItemsList.SelectedItem = selectId is null
                ? null
                : _quarantineRecords.FirstOrDefault(item => item.Id.Equals(selectId, StringComparison.OrdinalIgnoreCase));
            if (QuarantineItemsList.SelectedItem is null)
                QuarantineDetailsText.Text = $"{records.Length} detection record(s). Select an item to view details.";
            SetQuarantineActionButtons(!_busy);
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or System.Security.SecurityException or System.Text.Json.JsonException or InvalidDataException)
        {
            QuarantineDetailsText.Text = $"Quarantine records could not be loaded: {exception.Message}";
            SecurityEventsText.Text = "Security event history could not be loaded.";
            Log($"Quarantine/event records could not be loaded: {exception}");
        }
    }

    private void RefreshWatchlist_Click(object sender, RoutedEventArgs e) =>
        RefreshWatchlistView();

    private void RefreshWatchlistView(string? selectId = null)
    {
        try
        {
            var records = _watchlistService.LoadAll()
                .OrderByDescending(record => record.StartedAtUtc)
                .ToArray();
            _watchlistRecords.Clear();
            foreach (var record in records.Where(UnknownThreatWatchlistService.IsActive))
                _watchlistRecords.Add(record);
            _watchlistHistoryRecords.Clear();
            foreach (var record in records.Where(record => !UnknownThreatWatchlistService.IsActive(record)))
                _watchlistHistoryRecords.Add(record);

            var activeCount = records.Count(UnknownThreatWatchlistService.IsActive);
            WatchlistWorkerStatusText.Text = UnknownThreatWatchlistWorker.IsRunning
                ? $"Background watcher is active for this signed-in Windows session · using 30-second polling cycles · {activeCount} active program(s). Observation time is counted only across successful, consecutive checks. Monitoring pauses at sign-out or while Windows is off."
                : $"Background watcher is not currently running · {activeCount} program(s) are waiting for observation. The installer registers a per-user task to start at sign-in; portable use does not install that task. Observation time is not counted while it is stopped.";
            WatchlistItemsList.SelectedItem = selectId is null
                ? null
                : _watchlistRecords.FirstOrDefault(record => record.Id.Equals(selectId, StringComparison.OrdinalIgnoreCase));
            WatchlistHistoryList.SelectedItem = WatchlistItemsList.SelectedItem is null && selectId is not null
                ? _watchlistHistoryRecords.FirstOrDefault(record => record.Id.Equals(selectId, StringComparison.OrdinalIgnoreCase))
                : null;
            if (WatchlistItemsList.SelectedItem is null && WatchlistHistoryList.SelectedItem is null)
                WatchlistDetailsText.Text = $"{activeCount} active watchlist item(s), {records.Length - activeCount} historical item(s). Select an item to review its observation period and evidence.";
            SetWatchlistActionButtons(!_busy);
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or System.Security.SecurityException or System.Text.Json.JsonException or InvalidDataException)
        {
            WatchlistWorkerStatusText.Text = $"The unknown threat watchlist could not be loaded: {exception.Message}";
            WatchlistDetailsText.Text = "Watchlist data is unavailable. No clean or malicious verdict was inferred.";
            Log($"Unknown Threat Watchlist could not be loaded: {exception}");
        }
    }

    private async void StopWatching_Click(object sender, RoutedEventArgs e)
    {
        if (WatchlistItemsList.SelectedItem is not UnknownThreatWatchRecord record ||
            !UnknownThreatWatchlistService.IsActive(record))
            return;

        var response = MessageBox.Show(
            this,
            $"Stop enhanced observation for '{Path.GetFileName(record.FilePath)}'? Normal antivirus protection remains active, but this program will no longer be on the Unknown Threat Watchlist.",
            "Stop unknown-program observation",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);
        if (response != MessageBoxResult.Yes)
            return;

        await RunSecurityOperationAsync("Stopping unknown-program observation", false, () =>
        {
            _watchlistService.StopWatching(record.Id);
            RefreshWatchlistView(record.Id);
            Log($"User stopped enhanced watchlist observation for '{record.FilePath}'.");
            return Task.CompletedTask;
        });
    }

    private void WatchlistItemsList_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        if (WatchlistItemsList.SelectedItem is not UnknownThreatWatchRecord record)
        {
            SetWatchlistActionButtons(!_busy);
            return;
        }

        WatchlistHistoryList.SelectedItem = null;
        WatchlistDetailsText.Text = FormatWatchlistDetails(record);
        SetWatchlistActionButtons(!_busy);
    }

    private void WatchlistHistoryList_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        if (WatchlistHistoryList.SelectedItem is not UnknownThreatWatchRecord record)
        {
            SetWatchlistActionButtons(!_busy);
            return;
        }

        WatchlistItemsList.SelectedItem = null;
        WatchlistDetailsText.Text = FormatWatchlistDetails(record);
        SetWatchlistActionButtons(!_busy);
    }

    private void SetWatchlistActionButtons(bool enabled) =>
        StopWatchingButton.IsEnabled = enabled &&
                                       WatchlistItemsList?.SelectedItem is UnknownThreatWatchRecord record &&
                                       UnknownThreatWatchlistService.IsActive(record);

    private static string FormatWatchlistDetails(UnknownThreatWatchRecord record) =>
        $"Program: {Path.GetFileName(record.FilePath)}{Environment.NewLine}" +
        $"Path: {record.FilePath}{Environment.NewLine}" +
        $"SHA-256: {record.Sha256}{Environment.NewLine}" +
        $"File size: {(record.FileSizeBytes is long size ? $"{size:N0} bytes" : "Unavailable for this legacy entry")}{Environment.NewLine}" +
        $"Publisher: {record.Publisher}{Environment.NewLine}" +
        $"Status: {record.Status}{Environment.NewLine}" +
        $"Risk state: {record.RiskState ?? record.LatestClassification}{Environment.NewLine}" +
        $"First seen / observation started (UTC): {record.StartedAtUtc:O}{Environment.NewLine}" +
        $"Successful observation checks: {(record.ObservationCount is long observations ? observations.ToString("N0") : "Unavailable for this legacy entry")}{Environment.NewLine}" +
        $"Observed monitoring time: {record.ObservedDuration:d\\.hh\\:mm\\:ss}{Environment.NewLine}" +
        $"Time remaining: {record.RemainingDuration:d\\.hh\\:mm\\:ss}{Environment.NewLine}" +
        $"Last successful observation (UTC): {record.LastObservedAtUtc:O}{Environment.NewLine}" +
        $"User decision: {record.UserDecision ?? (record.Status == "Removed by User" ? "Stopped enhanced observation" : "None")}{Environment.NewLine}" +
        $"Latest assessment: {record.LatestClassification}{Environment.NewLine}" +
        $"Baseline capabilities: {(record.BaselineCapabilities.Count == 0 ? "None" : string.Join(", ", record.BaselineCapabilities))}{Environment.NewLine}" +
        $"Baseline evidence: {(record.BaselineEvidence.Count == 0 ? "None" : string.Join(Environment.NewLine, record.BaselineEvidence))}{Environment.NewLine}" +
        $"Latest capabilities: {(record.LatestCapabilities.Count == 0 ? "None" : string.Join(", ", record.LatestCapabilities))}{Environment.NewLine}" +
        $"Latest evidence: {(record.LatestEvidence.Count == 0 ? "None" : string.Join(Environment.NewLine, record.LatestEvidence))}{Environment.NewLine}" +
        $"Reason: {record.LatestReason}{Environment.NewLine}" +
        $"Detection record: {record.DetectionRecordId ?? "None"}{Environment.NewLine}" +
        $"Related detections: {FormatRelatedDetections(record)}{Environment.NewLine}" +
        "A completed observation means no malicious behavior was observed by supported checks; it is not a guarantee of safety.";

    private static string FormatRelatedDetections(UnknownThreatWatchRecord record)
    {
        var detectionIds = record.RelatedDetectionIds
            .Append(record.DetectionRecordId)
            .Where(id => !string.IsNullOrWhiteSpace(id))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        return detectionIds.Length == 0 ? "None" : string.Join(", ", detectionIds);
    }

    private void QuarantineItemsList_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        if (QuarantineItemsList.SelectedItem is not QuarantineRecord record)
        {
            SetQuarantineActionButtons(!_busy);
            return;
        }

        QuarantineDetailsText.Text = FormatQuarantineDetails(record);
        SetQuarantineActionButtons(!_busy);
    }

    private void SetQuarantineActionButtons(bool enabled)
    {
        var selected = QuarantineItemsList?.SelectedItem as QuarantineRecord;
        var isStored = selected is not null &&
                       selected.Status is "Quarantined" or "Containment Failed" &&
                       !string.IsNullOrWhiteSpace(selected.QuarantinedPath);
        KeepQuarantinedButton.IsEnabled = enabled && isStored;
        RestoreQuarantinedButton.IsEnabled = enabled && isStored;
        RestoreAllowButton.IsEnabled = enabled && isStored;
        DeleteQuarantinedButton.IsEnabled = enabled && isStored;
        ViewQuarantineDetailsButton.IsEnabled = enabled && selected is not null;
        RemoveAllowanceButton.IsEnabled = enabled && selected?.UserAllowed == true;
    }

    private void KeepQuarantined_Click(object sender, RoutedEventArgs e)
    {
        if (QuarantineItemsList.SelectedItem is not QuarantineRecord record)
            return;
        try
        {
            _threatQuarantineService.KeepQuarantined(record.Id);
            RefreshQuarantineView(record.Id);
            Log($"User kept '{record.FileName}' quarantined.");
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            Log($"Could not confirm quarantine for '{record.FileName}': {exception}");
            MessageBox.Show(this, exception.Message, "Quarantine status", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private async void RestoreQuarantined_Click(object sender, RoutedEventArgs e)
    {
        if (QuarantineItemsList.SelectedItem is not QuarantineRecord record)
            return;
        if (MessageBox.Show(
                this,
                $"Restore '{record.FileName}' to its original location? Winvexa will verify its SHA-256 first. The file will not be opened or executed.",
                "Confirm restore",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning) != MessageBoxResult.Yes)
            return;
        await RestoreRecordAsync(record, allow: false);
    }

    private async void RestoreAllow_Click(object sender, RoutedEventArgs e)
    {
        if (QuarantineItemsList.SelectedItem is not QuarantineRecord record)
            return;
        if (MessageBox.Show(
                this,
                $"HIGH RISK: Restore and allow only this exact file? It was identified as '{record.DetectionName}' ({record.Severity}). " +
                $"The matching file hash is {record.Sha256}. It will be restored without being opened, and Winvexa will record an allowance for this exact path and SHA-256 only. " +
                "A changed file hash is a new file and is not allowed. Microsoft Defender protections will not be disabled.",
                "Confirm restore and allow",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning) != MessageBoxResult.Yes)
            return;
        await RestoreRecordAsync(record, allow: true);
    }

    private async Task RestoreRecordAsync(QuarantineRecord record, bool allow)
    {
        await RunSecurityOperationAsync(allow ? "Restoring and allowing exact file" : "Restoring quarantined file", false, async () =>
        {
            var updated = await _threatQuarantineService.RestoreAsync(record.Id, allow);
            RefreshQuarantineView(updated.Id);
            Log($"{(allow ? "Restored and allowed" : "Restored")} '{updated.FileName}' to '{updated.OriginalPath}'. The file was not executed.");
        });
    }

    private async void DeleteQuarantined_Click(object sender, RoutedEventArgs e)
    {
        if (QuarantineItemsList.SelectedItem is not QuarantineRecord record)
            return;
        if (MessageBox.Show(
                this,
                $"Permanently delete '{record.FileName}' from quarantine? This cannot be undone. Winvexa will verify the saved SHA-256 before deletion.",
                "Confirm permanent deletion",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning) != MessageBoxResult.Yes)
            return;

        await RunSecurityOperationAsync("Permanently deleting quarantined file", false, async () =>
        {
            var updated = await _threatQuarantineService.DeletePermanentlyAsync(record.Id);
            RefreshQuarantineView(updated.Id);
            Log($"Permanently deleted quarantined file '{updated.FileName}'.");
        });
    }

    private void ViewQuarantineDetails_Click(object sender, RoutedEventArgs e)
    {
        if (QuarantineItemsList.SelectedItem is not QuarantineRecord record)
            return;
        MessageBox.Show(
            this,
            FormatQuarantineDetails(record),
            $"Winvexa security record — {record.FileName}",
            MessageBoxButton.OK,
            MessageBoxImage.Information);
    }

    private void RemoveAllowance_Click(object sender, RoutedEventArgs e)
    {
        if (QuarantineItemsList.SelectedItem is not QuarantineRecord record)
            return;
        if (MessageBox.Show(
                this,
                $"Remove the file-specific allowance for '{record.FileName}'? Its recorded SHA-256 will no longer be allowed.",
                "Remove file allowance",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning) != MessageBoxResult.Yes)
            return;
        try
        {
            var updated = _threatQuarantineService.RemoveAllowance(record.Id);
            RefreshQuarantineView(updated.Id);
            Log($"Removed file-specific allowance for '{updated.FileName}' ({updated.Sha256}).");
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            Log($"Could not remove allowance for '{record.FileName}': {exception}");
            MessageBox.Show(this, exception.Message, "Allowance removal failed", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private static string FormatQuarantineDetails(QuarantineRecord record) =>
        $"Threat: {record.DetectionName}{Environment.NewLine}" +
        $"Family: {record.MalwareFamily}{Environment.NewLine}" +
        $"File name: {record.FileName}{Environment.NewLine}" +
        $"Original location: {record.OriginalPath}{Environment.NewLine}" +
        $"Quarantine location: {(string.IsNullOrWhiteSpace(record.QuarantinedPath) ? "Not quarantined" : record.QuarantinedPath)}{Environment.NewLine}" +
        $"Category: {record.Category}{Environment.NewLine}" +
        $"Severity: {record.Severity}{Environment.NewLine}" +
        $"Classification: {record.Classification}{Environment.NewLine}" +
        $"Known family capabilities (not necessarily observed): {(record.KnownCapabilities.Count == 0 ? "None recorded" : string.Join(", ", record.KnownCapabilities))}{Environment.NewLine}" +
        $"Observed capabilities: {(record.ObservedCapabilities.Count == 0 ? "None observed" : string.Join(", ", record.ObservedCapabilities))}{Environment.NewLine}" +
        $"SHA-256: {record.Sha256}{Environment.NewLine}" +
        $"Detection method: {record.DetectionMethod}{Environment.NewLine}" +
        $"Detected (UTC): {record.DetectedAtUtc:O}{Environment.NewLine}" +
        $"Status: {record.Status}{Environment.NewLine}" +
        $"Containment result: {record.ContainmentResult}{Environment.NewLine}" +
        $"User allowed exact file: {record.UserAllowed}";

    private void ShowThreatNotification(QuarantineRecord record, string disposition)
    {
        var title = record.Classification == "Confirmed Threat"
            ? record.Status == "Quarantined"
                ? "Threat detected and quarantined."
                : disposition
            : record.Status == "Quarantined"
                ? "High-confidence suspicious activity contained."
                : disposition;
        var notification = new ThreatNotificationWindow(
            this,
            title,
            record.DetectionName,
            record.FileName,
            record.Severity,
            disposition + (record.Severity.Equals("Critical", StringComparison.OrdinalIgnoreCase)
                ? " This high-severity threat may have attempted harmful activity before detection; Winvexa's on-demand scan cannot determine whether prior activity occurred."
                : string.Empty));
        if (notification.ShowDialog() == true)
        {
            RefreshQuarantineView(record.Id);
            foreach (var tab in FindVisualChildren<TabItem>(this))
            {
                if (Equals(tab.Header, "Quarantine"))
                {
                    tab.IsSelected = true;
                    break;
                }
            }
        }
    }

    private static IEnumerable<T> FindVisualChildren<T>(DependencyObject parent) where T : DependencyObject
    {
        for (var index = 0; index < System.Windows.Media.VisualTreeHelper.GetChildrenCount(parent); index++)
        {
            var child = System.Windows.Media.VisualTreeHelper.GetChild(parent, index);
            if (child is T match)
                yield return match;
            foreach (var descendant in FindVisualChildren<T>(child))
                yield return descendant;
        }
    }

    private void LocalFindingsList_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        if (LocalFindingsList.SelectedItem is not ThreatAnalysisFinding finding)
        {
            LocalFindingDetailsText.Text = "Select an analysis result to see the evidence and limits.";
            QuarantineButton.IsEnabled = false;
            return;
        }

        var notes = _inspectionNotes.TryGetValue(finding, out var inspectionNotes)
            ? inspectionNotes
            : [];
        LocalFindingDetailsText.Text = finding.Details +
            (notes.Count == 0 ? string.Empty : Environment.NewLine + Environment.NewLine +
                "Inspection limits and notes:" + Environment.NewLine + string.Join(Environment.NewLine, notes));
        QuarantineButton.IsEnabled = !_busy && finding.CanQuarantine && !finding.IsDemo;
    }

    private ThreatAnalysisService GetThreatAnalysisService()
    {
        var knowledgeBase = _threatKnowledgeBaseProvider.Load();
        if (_threatQuarantineService.RecordDatabaseVersion(
                knowledgeBase.Document.DatabaseVersion,
                knowledgeBase.Document.Families.Count))
            RefreshQuarantineView();
        ThreatKnowledgeBaseStatusText.Text =
            $"Version {knowledgeBase.Document.DatabaseVersion} · updated {knowledgeBase.Document.LastUpdatedUtc:yyyy-MM-dd} · {knowledgeBase.Document.Families.Count} family records · {knowledgeBase.Document.Families.Sum(family => family.Sha256Hashes.Count)} sourced SHA-256 hashes.";
        if (_threatAnalysisService is null ||
            !_threatAnalysisService.DatabaseVersion.Equals(knowledgeBase.Document.DatabaseVersion, StringComparison.Ordinal))
        {
            _threatAnalysisService = new ThreatAnalysisService(
                knowledgeBase,
                message => _writeLog($"[Local Threat Analysis] {message}"));
        }
        return _threatAnalysisService;
    }

    private void AddLocalFinding(ThreatAnalysisFinding finding, IReadOnlyList<string> inspectionNotes)
    {
        _localFindings.Insert(0, finding);
        _inspectionNotes[finding] = inspectionNotes;
        ThreatFindingCountText.Text = $"{_localFindings.Count} result(s)";
        LocalFindingsList.SelectedItem = finding;
    }

    private void LocalAnalysisStatus(string message) =>
        LocalAnalysisStatusText.Text = message;

    private static string FormatKnowledgeBaseDetails(ThreatKnowledgeBase knowledgeBase)
    {
        var lines = new List<string>
        {
            $"Database version: {knowledgeBase.Document.DatabaseVersion}",
            $"Last updated (UTC): {knowledgeBase.Document.LastUpdatedUtc:O}",
            "Threat family metadata supplies capability context only; no family attribution is made from capability overlap.",
            "No online threat-intelligence download or update mechanism is enabled. Hash matches are available only for explicit sourced SHA-256 records in the validated local database.",
            string.Empty,
            "CATEGORIES"
        };
        lines.AddRange(knowledgeBase.Document.Categories.Select(category => $"{category.Name}: {category.Description}"));
        lines.Add(string.Empty);
        lines.Add("CAPABILITIES");
        lines.AddRange(knowledgeBase.Document.Capabilities.Select(capability =>
            $"{capability.Name} ({capability.ConfidenceWhenObserved} when observable){Environment.NewLine}" +
            $"  Meaning: {capability.Meaning}{Environment.NewLine}" +
            $"  Why malware uses it: {capability.WhyMalwareUsesIt}{Environment.NewLine}" +
            $"  Legitimate uses: {capability.LegitimateUses}{Environment.NewLine}" +
            $"  Safe indicators: {string.Join("; ", capability.SafeIndicators)}"));
        lines.Add(string.Empty);
        lines.Add("KNOWN FAMILY RECORDS (CAPABILITIES ARE DOCUMENTED FAMILY KNOWLEDGE, NOT OBSERVED FILE BEHAVIOR)");
        lines.AddRange(knowledgeBase.Document.Families.Select(family =>
            $"{family.Name}{(family.Aliases.Count == 0 ? string.Empty : $" (aliases: {string.Join(", ", family.Aliases)})")}{Environment.NewLine}" +
            $"  Category/type: {knowledgeBase.Categories[family.CategoryId].Name} / {family.ThreatType}{Environment.NewLine}" +
            $"  Platform(s): {(family.TargetPlatforms.Count == 0 ? "Not established by the cited sources" : string.Join(", ", family.TargetPlatforms))}{Environment.NewLine}" +
            $"  First observed: {(string.IsNullOrWhiteSpace(family.FirstObservedTimeframe) ? "Not established by the cited sources" : family.FirstObservedTimeframe)}{Environment.NewLine}" +
            $"  Known capabilities: {string.Join(", ", family.KnownCapabilities.Where(knowledgeBase.Capabilities.ContainsKey).Select(id => knowledgeBase.Capabilities[id].Name))}{Environment.NewLine}" +
            $"  Detection names: {(family.DetectionNames.Count == 0 ? "No stable family-wide name asserted" : string.Join(", ", family.DetectionNames))}{Environment.NewLine}" +
            $"  Database updated: {family.LastUpdatedUtc:yyyy-MM-dd}{Environment.NewLine}" +
            $"  Source(s): {string.Join("; ", family.References)}"));
        lines.Add(string.Empty);
        lines.Add("SOURCES");
        lines.AddRange(knowledgeBase.Document.Sources);
        return string.Join(Environment.NewLine, lines);
    }

    private void Log(string message) => _writeLog($"[Antivirus & Security] {message}");

    private async void RefreshStatus_Click(object sender, RoutedEventArgs e) =>
        await RefreshStatusAsync();

    private async void QuickScan_Click(object sender, RoutedEventArgs e)
    {
        if (PrepareAction("quick", null))
            await StartScanAsync(fullScan: false, null);
    }

    private async void FullScan_Click(object sender, RoutedEventArgs e)
    {
        if (MessageBox.Show(
                this,
                "A Full Scan can take a long time. Microsoft Defender will perform the scan; Winvexa will not delete or quarantine files.",
                "Confirm Microsoft Defender Full Scan",
                MessageBoxButton.OKCancel,
                MessageBoxImage.Warning) == MessageBoxResult.OK)
        {
            if (PrepareAction("full", null))
                await StartScanAsync(fullScan: true, null);
        }
    }

    private async void CustomScan_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFolderDialog
        {
            Title = "Choose a folder for Microsoft Defender Custom Scan",
            Multiselect = false
        };
        if (dialog.ShowDialog(this) == true && PrepareAction("custom", dialog.FolderName))
            await StartScanAsync(fullScan: false, dialog.FolderName);
    }

    private async void ScanPath_Click(object sender, RoutedEventArgs e)
    {
        var choice = MessageBox.Show(
            this,
            "Choose Yes to select a file, No to select a folder, or Cancel to return.",
            "Scan a file or folder",
            MessageBoxButton.YesNoCancel,
            MessageBoxImage.Question);
        if (choice == MessageBoxResult.Cancel)
            return;

        string? path;
        if (choice == MessageBoxResult.Yes)
        {
            var dialog = new OpenFileDialog
            {
                Title = "Choose a file for Microsoft Defender Custom Scan",
                CheckFileExists = true,
                Multiselect = false
            };
            path = dialog.ShowDialog(this) == true ? dialog.FileName : null;
        }
        else
        {
            var dialog = new OpenFolderDialog
            {
                Title = "Choose a folder for Microsoft Defender Custom Scan",
                Multiselect = false
            };
            path = dialog.ShowDialog(this) == true ? dialog.FolderName : null;
        }

        if (!string.IsNullOrWhiteSpace(path) && PrepareAction("custom", path))
            await StartScanAsync(fullScan: false, path);
    }

    private async Task StartScanAsync(bool fullScan, string? targetPath)
    {
        var scanName = string.IsNullOrWhiteSpace(targetPath)
            ? fullScan ? "Microsoft Defender Full Scan" : "Microsoft Defender Quick Scan"
            : $"Microsoft Defender Custom Scan ({targetPath})";
        await RunSecurityOperationAsync(scanName, cancellableScan: true, async () =>
        {
            _currentOperation = "Updating Microsoft Defender security intelligence";
            OperationStatusText.Text = "Preparing · Updating Microsoft Defender security intelligence...";
            StopButton.IsEnabled = false;
            StopButton.Visibility = Visibility.Collapsed;
            Log("Updating Microsoft Defender security intelligence before the requested scan.");
            await _service.UpdateDefenderSignaturesAsync();
            OperationCancellationContext.ThrowIfCancellationRequested();

            _currentOperation = scanName;
            StopButton.Visibility = Visibility.Visible;
            StopButton.IsEnabled = true;
            OperationStatusText.Text = $"Scanning · {scanName} is running in Microsoft Defender. Exact file counts and scan progress are unavailable to Winvexa.";
            SetScanButtonProcessing(true, fullScan, targetPath);
            var result = await _service.RunDefenderScanAsync(fullScan, targetPath);
            OperationStatusText.Text = result;
            Log($"Scan result: {result}");
            StopButton.Visibility = Visibility.Collapsed;
            StopButton.IsEnabled = false;
            if (!OperationCancellationContext.IsCancellationRequested &&
                !result.Contains("stopped", StringComparison.OrdinalIgnoreCase) &&
                !result.Contains("completed before the Stop request", StringComparison.OrdinalIgnoreCase))
            {
                try
                {
                    await RefreshStatusCoreAsync();
                }
                catch (Exception exception) when (
                    exception is InvalidOperationException or IOException or UnauthorizedAccessException or
                        System.ComponentModel.Win32Exception or System.Text.Json.JsonException or FormatException)
                {
                    OperationStatusText.Text =
                        $"Completed · {result} Defender's post-scan status could not be verified: {exception.Message}";
                    Log($"The Defender scan completed, but its post-scan status refresh failed: {exception}");
                }
            }
        }, allowCancellationOutcome: true);
    }

    private async void UpdateSignatures_Click(object sender, RoutedEventArgs e)
    {
        if (PrepareAction("update", null))
            await UpdateSignaturesAsync();
    }

    private async Task UpdateSignaturesAsync()
    {
        await RunSecurityOperationAsync("Updating Microsoft Defender security intelligence", false, async () =>
        {
            var before = await _service.GetDefenderSecurityStatusAsync();
            DisplayStatus(before);
            await _service.UpdateDefenderSignaturesAsync();
            var verified = await _service.GetDefenderSecurityStatusAsync();
            DisplayStatus(verified);
            var changed = !before.SignatureVersion.Equals(verified.SignatureVersion, StringComparison.OrdinalIgnoreCase) ||
                          before.SignatureLastUpdated != verified.SignatureLastUpdated;
            Log(changed
                ? $"Security intelligence changed and was verified: version {verified.SignatureVersion}, last updated {FormatDate(verified.SignatureLastUpdated)}."
                : $"Update request succeeded and resulting status was verified. The reported version and timestamp are unchanged ({verified.SignatureVersion}, {FormatDate(verified.SignatureLastUpdated)}); Windows may already have current intelligence or have no newer applicable update.");
        });
    }

    private bool PrepareAction(string action, string? targetPath)
    {
        if (_isAdministrator)
            return true;

        var argument = action switch
        {
            "quick" => "--security-action-quick",
            "full" => "--security-action-full",
            "update" => "--security-action-update",
            "custom" when !string.IsNullOrWhiteSpace(targetPath) =>
                $"--security-action-custom:{Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(targetPath))}",
            _ => throw new ArgumentOutOfRangeException(nameof(action), action, "Unsupported elevated security action.")
        };
        _requestElevation(
            argument,
            $"Microsoft Defender {action} requires administrator permission on this system. Windows will show its standard UAC prompt; Winvexa will not bypass it or change antivirus protections.");
        return false;
    }

    private async Task RefreshStatusCoreAsync()
    {
        var status = await _service.GetDefenderSecurityStatusAsync();
        DisplayStatus(status);
    }

    private void Stop_Click(object sender, RoutedEventArgs e)
    {
        if (!_busy || _stopping || _operationCancellation is null)
            return;
        _stopping = true;
        _operationCancellation.Cancel();
        StopButton.Content = "Stopping...";
        StopButton.IsEnabled = false;
        OperationStatusText.Text = "Stopping · Waiting for Microsoft Defender to confirm the scan has ended.";
        Log($"Stop requested during '{_currentOperation}'. Sent through MpCmdRun.exe -Scan -Cancel; Winvexa will wait for the scan process to exit.");
    }

    private void SetScanButtonProcessing(bool processing, bool fullScan = false, string? targetPath = null)
    {
        QuickScanButton.Content = processing && string.IsNullOrWhiteSpace(targetPath) && !fullScan
            ? "Scanning..."
            : "Quick Scan";
        FullScanButton.Content = processing && string.IsNullOrWhiteSpace(targetPath) && fullScan
            ? "Scanning..."
            : "Full Scan";
        CustomScanButton.Content = processing && !string.IsNullOrWhiteSpace(targetPath)
            ? "Scanning..."
            : "Custom Scan";
    }

    private void OpenWindowsSecurity_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            Process.Start(new ProcessStartInfo("ms-settings:windowsdefender") { UseShellExecute = true });
            Log("Opened Windows Security settings at the user's request.");
        }
        catch (Exception exception) when (exception is InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            Log($"Could not open Windows Security settings: {exception}");
            MessageBox.Show(
                this,
                $"Windows Security could not be opened automatically. Open it from the Start menu instead.{Environment.NewLine}{Environment.NewLine}{exception.Message}",
                "Windows Security unavailable",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
    }

    private void SecurityWindow_Closing(object? sender, System.ComponentModel.CancelEventArgs e)
    {
        if (!_busy)
        {
            _watchlistRefreshTimer.Stop();
            return;
        }
        e.Cancel = true;
        OperationStatusText.Text = "An operation is still running. Stop it and wait for Windows Defender to finish before closing this page.";
    }
}
