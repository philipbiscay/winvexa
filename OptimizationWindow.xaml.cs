using System.Security.Principal;
using System.Diagnostics;
using System.ComponentModel;
using System.Windows;
using System.Windows.Threading;

namespace Winvexa;

internal sealed class OptimizationItemViewModel(OptimizationRecommendation recommendation)
{
    public OptimizationRecommendation Recommendation { get; } = recommendation;
    public string Heading => $"[{Recommendation.Category}] {Recommendation.Name}" +
                             (string.IsNullOrWhiteSpace(Recommendation.Publisher) ? string.Empty : $" — {Recommendation.Publisher}");
    public string CurrentAndProposed => $"Current: {Recommendation.CurrentSetting}    Proposed: {Recommendation.ProposedSetting}";
    public string Description => Recommendation.Description +
                                 (Recommendation.ActionKind == OptimizationActionKind.DriveOptimization
                                     ? " This operation cannot be undone."
                                     : Recommendation.ActionKind == OptimizationActionKind.OpenSettings
                                         ? " This opens a Windows Settings page; Winvexa does not change that setting."
                                         : " The previous setting is saved by Winvexa for undo.");
    public bool Selectable => Recommendation.Selectable;
    public bool IsSelected { get; set; }
}

public partial class OptimizationWindow : Window
{
    private readonly OptimizationService _optimization;
    private readonly MaintenanceService _maintenance;
    private readonly Action<string> _log;
    private readonly Stopwatch _operationStopwatch = new();
    private readonly DispatcherTimer _operationHeartbeat;
    private CancellationTokenSource? _operationCancellation;
    private string _operationStatus = string.Empty;
    private IReadOnlyList<OptimizationItemViewModel> _items = [];
    private bool _busy;
    private bool _stopRequested;
    private bool _hasUndoableChanges;

    internal OptimizationWindow(MaintenanceService maintenance, Action<string> log)
    {
        InitializeComponent();
        GlassThemeService.ApplyToWindow(this);
        _maintenance = maintenance;
        _log = log;
        _optimization = new OptimizationService(log);
        _operationHeartbeat = new DispatcherTimer { Interval = TimeSpan.FromSeconds(15) };
        _operationHeartbeat.Tick += (_, _) =>
        {
            if (_busy && !string.IsNullOrWhiteSpace(_operationStatus))
            {
                var stopMessage = _stopRequested
                    ? " Stop requested; canceling cancellable work. Restore-point creation or drive optimization may need to finish before Winvexa returns to idle."
                    : string.Empty;
                StatusText.Text =
                    $"{_operationStatus}{stopMessage} Still working — {_operationStopwatch.Elapsed.ToString(@"mm\:ss")} elapsed.";
            }
        };
        RefreshUndoSummary();
        Loaded += async (_, _) => await ScanAsync();
    }

    private async void Scan_Click(object sender, RoutedEventArgs e) => await ScanAsync();

    private async Task ScanAsync()
    {
        if (_busy)
            return;
        SetBusy(true);
        SetOperationStatus("Scanning Windows settings and installed system information...");
        ReportText.Text = "WINDOWS 11 OPTIMIZATION REPORT" + Environment.NewLine + "Scanning...";
        try
        {
            using var cancellationScope = OperationCancellationContext.Enter(_operationCancellation!.Token);
            var scan = await Task.Run(() => _optimization.ScanAsync(
                message => Dispatcher.Invoke(() => SetOperationStatus(message))));
            _items = scan.Recommendations.Select(item => new OptimizationItemViewModel(item)).ToArray();
            RecommendationsList.ItemsSource = _items;
            ReportText.Text = BuildReport(scan);
            SetOperationStatus($"{scan.ActionableCount} individual change(s) available for review. Nothing has been changed.");
        }
        catch (OperationCanceledException) when (_stopRequested)
        {
            _log("Operation Stopped: Windows 11 Optimization scan canceled; active cancellable child processes were stopped.");
            ReportText.Text += $"{Environment.NewLine}{Environment.NewLine}Operation Stopped. The scan was canceled and no changes were applied.";
            StatusText.Text = "Operation Stopped";
        }
        catch (Exception exception) when (!_stopRequested || exception is not OperationCanceledException)
        {
            _log($"Windows 11 Optimization scan failed: {exception}");
            ReportText.Text = $"WINDOWS 11 OPTIMIZATION SCAN FAILED{Environment.NewLine}{Environment.NewLine}{exception.Message}";
            SetOperationStatus("The scan could not complete. See the repair log for details.");
            MessageBox.Show(this, exception.Message, "Optimization scan failed", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            SetBusy(false);
        }
    }

    private async void Apply_Click(object sender, RoutedEventArgs e)
    {
        if (_busy)
            return;
        var selected = _items.Where(item => item.IsSelected).Select(item => item.Recommendation).ToArray();
        var changes = selected.Where(item => item.ActionKind != OptimizationActionKind.OpenSettings).ToArray();
        if (selected.Length == 0)
        {
            MessageBox.Show(this, "Select at least one proposed change to review.", "No changes selected",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        if (changes.Any(item => item.ActionKind == OptimizationActionKind.DriveOptimization) && !IsAdministrator())
        {
            MessageBox.Show(this,
                "Windows drive optimization requires administrator access. Close Winvexa, restart it, and approve the normal UAC prompt before selecting this operation. No drive operation was started.",
                "Administrator access required",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
            return;
        }

        var summary = string.Join(Environment.NewLine, selected.Select(item =>
            $"✓ {item.ProposedSetting}: {item.Name} ({item.Category})" +
            (item.ActionKind == OptimizationActionKind.DriveOptimization ? " — cannot be undone" :
             item.ActionKind == OptimizationActionKind.OpenSettings ? " — opens Settings only" : " — saved for undo")));
        if (MessageBox.Show(
                this,
                $"Review the selected items before continuing:{Environment.NewLine}{Environment.NewLine}{summary}{Environment.NewLine}{Environment.NewLine}Winvexa will not apply any unselected item. Continue?",
                "Review selected optimizations",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning) != MessageBoxResult.Yes)
            return;

        SetBusy(true);
        using var cancellationScope = OperationCancellationContext.Enter(_operationCancellation!.Token);
        var reversible = changes.Any(item => item.RequiresRestorePoint);
        if (reversible)
        {
            try
            {
                OperationCancellationContext.ThrowIfCancellationRequested();
                SetOperationStatus("Creating a restore point before applying settings...");
                await _maintenance.CreateRestorePointAsync();
            }
            catch (OperationCanceledException) when (_stopRequested)
            {
                _log("Operation Stopped: optimization canceled after the restore-point operation finished normally.");
                ReportText.Text += $"{Environment.NewLine}{Environment.NewLine}Operation Stopped. No selected optimization change was applied.";
                StatusText.Text = "Operation Stopped";
                SetBusy(false);
                return;
            }
            catch (Exception exception) when (!_stopRequested || exception is not OperationCanceledException)
            {
                _log($"Optimization restore point could not be created: {exception}");
                if (MessageBox.Show(
                        this,
                        $"Windows could not create a restore point:{Environment.NewLine}{exception.Message}{Environment.NewLine}{Environment.NewLine}Winvexa still saves the exact previous values for its own Undo feature. Continue without a restore point?",
                        "Restore point unavailable",
                        MessageBoxButton.YesNo,
                        MessageBoxImage.Warning) != MessageBoxResult.Yes)
                {
                    SetBusy(false);
                    return;
                }
            }
        }

        try
        {
            if (changes.Length > 0)
            {
                SetOperationStatus("Applying only the selected optimization changes...");
                await _optimization.ApplyAsync(changes, _maintenance);
            }

            foreach (var item in selected.Where(item => item.ActionKind == OptimizationActionKind.OpenSettings)
                         .GroupBy(item => item.SettingsUri, StringComparer.OrdinalIgnoreCase)
                         .Select(group => group.First()))
            {
                OperationCancellationContext.ThrowIfCancellationRequested();
                await OptimizationService.OpenSettingsAsync(item);
                _log($"Opened Windows Settings for review only: {item.Name}.");
            }

            SetOperationStatus("Selected changes processed. Review-only settings pages do not change options automatically.");
            if (changes.Length > 0)
                ReportText.Text += $"{Environment.NewLine}{Environment.NewLine}Applied {changes.Length} selected change(s). Previous reversible values are saved in the Winvexa optimization history.";
            if (selected.Any(item => item.ActionKind == OptimizationActionKind.OpenSettings))
                ReportText.Text += $"{Environment.NewLine}Opened selected Windows Settings pages; those settings were not changed by Winvexa.";
        }
        catch (OperationCanceledException) when (_stopRequested)
        {
            _log("Operation Stopped: selected Windows 11 Optimization changes canceled; completed changes remain recorded.");
            StatusText.Text = "Operation Stopped";
            ReportText.Text += $"{Environment.NewLine}{Environment.NewLine}Operation Stopped. Any completed change remains recorded and can be undone where supported.";
        }
        catch (Exception exception) when (!_stopRequested || exception is not OperationCanceledException)
        {
            _log($"Selected Windows 11 Optimization changes did not all complete: {exception}");
            SetOperationStatus("One or more changes could not be applied. Check the log and Undo option.");
            ReportText.Text += $"{Environment.NewLine}{Environment.NewLine}A selected change failed: {exception.Message}{Environment.NewLine}Any earlier changes remain recorded and can be undone.";
            MessageBox.Show(this, exception.Message, "Optimization change failed", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            RefreshUndoSummary();
            SetBusy(false);
        }
    }

    private async void OpenSettings_Click(object sender, RoutedEventArgs e)
    {
        var selected = _items.Where(item => item.IsSelected)
            .Select(item => item.Recommendation)
            .Where(item => item.ActionKind == OptimizationActionKind.OpenSettings)
            .ToArray();
        if (selected.Length == 0)
        {
            MessageBox.Show(this, "Select a review-only recommendation, such as Power Mode, Gaming/Graphics, or Installed Applications.",
                "No Settings recommendation selected", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        if (MessageBox.Show(this,
                $"Open the selected Windows Settings page(s)? Winvexa will not change those options.{Environment.NewLine}{Environment.NewLine}{string.Join(Environment.NewLine, selected.Select(item => item.Name))}",
                "Open Windows Settings",
                MessageBoxButton.YesNo,
                MessageBoxImage.Question) != MessageBoxResult.Yes)
            return;
        try
        {
            foreach (var item in selected.GroupBy(item => item.SettingsUri, StringComparer.OrdinalIgnoreCase).Select(group => group.First()))
                await OptimizationService.OpenSettingsAsync(item);
            SetOperationStatus("Opened selected Windows Settings pages. Review-only options were not changed by Winvexa.");
        }
        catch (Exception exception) when (!_stopRequested || exception is not OperationCanceledException)
        {
            _log($"Could not open a Windows Settings page: {exception}");
            MessageBox.Show(this, exception.Message, "Could not open Settings", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private async void Undo_Click(object sender, RoutedEventArgs e)
    {
        if (!_hasUndoableChanges || _busy)
            return;
        if (MessageBox.Show(this,
                $"{_optimization.GetUndoSummary()}{Environment.NewLine}{Environment.NewLine}Restore the exact settings and startup items saved by Winvexa?",
                "Undo Previous Optimization",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning) != MessageBoxResult.Yes)
            return;
        SetBusy(true);
        using var cancellationScope = OperationCancellationContext.Enter(_operationCancellation!.Token);
        try
        {
            await _optimization.UndoPreviousAsync();
            SetOperationStatus("Previous reversible Winvexa optimization settings were restored.");
            ReportText.Text += $"{Environment.NewLine}{Environment.NewLine}Previous reversible Winvexa optimization settings were restored.";
        }
        catch (OperationCanceledException) when (_stopRequested)
        {
            _log("Operation Stopped: Undo Previous Optimization canceled; completed restorations remain applied.");
            StatusText.Text = "Operation Stopped";
            ReportText.Text += $"{Environment.NewLine}{Environment.NewLine}Operation Stopped. Completed restorations remain applied; retry Undo to continue.";
        }
        catch (Exception exception) when (!_stopRequested || exception is not OperationCanceledException)
        {
            _log($"Undo Previous Optimization failed: {exception}");
            SetOperationStatus("Undo did not fully complete. Saved history remains available; see the log.");
            MessageBox.Show(this, exception.Message, "Undo failed", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            RefreshUndoSummary();
            SetBusy(false);
        }
    }

    private static string BuildReport(OptimizationScan scan)
    {
        var groups = scan.Recommendations.GroupBy(item => item.Category).ToDictionary(group => group.Key, group => group.ToArray());
        var categories = new[]
        {
            "Startup Apps", "Background Apps", "Visual Effects", "Notifications", "Windows Suggestions",
            "Privacy/Personalization Settings", "Unused Applications", "Power Mode", "Drive Optimization",
            "Gaming/Graphics Settings"
        };
        var lines = new List<string>
        {
            "WINDOWS 11 OPTIMIZATION REPORT",
            string.Empty
        };
        foreach (var category in categories)
        {
            lines.Add($"{category}:");
            if (!groups.TryGetValue(category, out var recommendations))
            {
                lines.Add("  No report available.");
                continue;
            }
            var count = recommendations.Count(item => item.Selectable && item.ActionKind != OptimizationActionKind.OpenSettings);
            if (category == "Unused Applications")
                lines.Add($"  0 classified as potentially unused; {recommendations.Count(item => item.ActionKind == OptimizationActionKind.OpenSettings)} app(s) inventoried, reliable last-use data unavailable");
            else
                lines.Add($"  {count} selectable setting/maintenance change(s)");
            var settingsReviews = recommendations.Count(item => item.Selectable && item.ActionKind == OptimizationActionKind.OpenSettings);
            if (settingsReviews > 0 && category != "Unused Applications")
                lines.Add($"  {settingsReviews} optional Windows Settings page(s) available");
            var displayedRecommendations = category == "Unused Applications" ? recommendations.Take(25) : recommendations;
            foreach (var item in displayedRecommendations)
                lines.Add($"  - {item.Name}: {item.CurrentSetting} -> {item.ProposedSetting}");
            if (category == "Unused Applications" && recommendations.Length > 25)
                lines.Add($"  - {recommendations.Length - 25} more app(s) are available in the review list below.");
        }
        lines.Add(string.Empty);
        lines.Add($"Potential optimizations found: {scan.ActionableCount}");
        lines.Add("No changes have been applied. Review and select each item below.");
        lines.Add("Windows does not expose reliable last-use information for every desktop app; no application was marked unused.");
        return string.Join(Environment.NewLine, lines);
    }

    private void RefreshUndoSummary()
    {
        try
        {
            _hasUndoableChanges = _optimization.HasUndoableChanges;
            UndoButton.IsEnabled = _hasUndoableChanges;
            UndoSummaryText.Text = _optimization.GetUndoSummary();
        }
        catch (Exception exception) when (!_stopRequested || exception is not OperationCanceledException)
        {
            _hasUndoableChanges = false;
            UndoButton.IsEnabled = false;
            UndoSummaryText.Text = "Saved undo history could not be read.";
            _log($"Could not read the optimization undo history: {exception}");
        }
    }

    private void SetBusy(bool busy)
    {
        _busy = busy;
        if (busy)
        {
            _operationCancellation = new CancellationTokenSource();
            _stopRequested = false;
            _operationStopwatch.Restart();
            OperationProgress.Visibility = Visibility.Visible;
            OperationProgress.IsIndeterminate = true;
            _operationHeartbeat.Start();
        }
        else
        {
            _operationCancellation?.Dispose();
            _operationCancellation = null;
            _stopRequested = false;
            _operationHeartbeat.Stop();
            _operationStopwatch.Stop();
            OperationProgress.IsIndeterminate = false;
            OperationProgress.Visibility = Visibility.Collapsed;
        }
        ScanButton.IsEnabled = !busy;
        ApplyButton.IsEnabled = !busy;
        SettingsButton.IsEnabled = !busy;
        UndoButton.IsEnabled = !busy && _hasUndoableChanges;
        CloseButton.IsEnabled = !busy;
        RecommendationsList.IsEnabled = !busy;
        StopButton.Visibility = busy ? Visibility.Visible : Visibility.Collapsed;
        StopButton.IsEnabled = busy && !_stopRequested;
        System.Windows.Input.Mouse.OverrideCursor = busy ? System.Windows.Input.Cursors.Wait : null;
    }

    private void Stop_Click(object sender, RoutedEventArgs e)
    {
        if (!_busy || _stopRequested || _operationCancellation is null)
            return;

        _stopRequested = true;
        _operationCancellation.Cancel();
        StopButton.Content = "Stopping...";
        StopButton.IsEnabled = false;
        StatusText.Text = $"{_operationStatus} — stop requested. Cancellable tasks and safe-to-stop child processes are stopping. Restore-point creation or drive optimization may need to finish before Winvexa returns to idle.";
        _log($"Cancellation requested by the user during optimization: {_operationStatus}. Cancellable tasks and safe-to-stop Winvexa child processes will be canceled; restore-point creation and drive optimization will finish normally.");
    }

    private void SetOperationStatus(string message)
    {
        if (_busy && _stopRequested)
        {
            StatusText.Text =
                $"Stop requested. Cancellable work is stopping; restore-point creation or drive optimization may need to finish. {_operationStatus}";
            return;
        }
        _operationStatus = message;
        StatusText.Text = message;
    }

    private void Close_Click(object sender, RoutedEventArgs e)
    {
        if (!_busy)
            Close();
    }

    private void OptimizationWindow_Closing(object? sender, CancelEventArgs e)
    {
        if (!_busy)
            return;

        e.Cancel = true;
        StatusText.Text = "An optimization operation is still running. Wait for it to finish before closing this window.";
        _log("Optimization window close was deferred because an operation is still running.");
    }

    private static bool IsAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }
}
