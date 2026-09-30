using System.IO;
using System.Windows;
using System.Windows.Controls;

namespace Winvexa;

public partial class RepairHistoryWindow : Window
{
    private sealed record HistoryEntry(string Path, string DisplayName, string Summary);

    private readonly string _logDirectory;

    public RepairHistoryWindow(string logDirectory)
    {
        InitializeComponent();
        GlassThemeService.ApplyToWindow(this);
        _logDirectory = logDirectory;
        Loaded += async (_, _) => await LoadHistoryAsync();
    }

    private async Task LoadHistoryAsync()
    {
        try
        {
            var entries = await Task.Run(() => Directory.Exists(_logDirectory)
                    ? Directory.EnumerateFiles(_logDirectory, "*.log")
                        .Select(path => new FileInfo(path))
                        .OrderByDescending(file => file.LastWriteTime)
                        .Select(file => new HistoryEntry(
                            file.FullName,
                            file.LastWriteTime.ToString("yyyy-MM-dd HH:mm"),
                            $"{file.Name}  •  {file.Length / 1024d:0.#} KB"))
                        .ToArray()
                    : Array.Empty<HistoryEntry>());
            HistoryList.ItemsSource = entries;
            HistoryStatusText.Text = entries.Length == 0
                ? $"No repair logs were found in {_logDirectory}."
                : $"{entries.Length} log file(s)  •  {_logDirectory}";
            if (entries.Length > 0)
                HistoryList.SelectedIndex = 0;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            HistoryStatusText.Text = "Repair history could not be loaded. Technical details are shown in the viewer.";
            LogContentText.Text = exception.ToString();
        }
    }

    private async void HistoryList_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (HistoryList.SelectedItem is not HistoryEntry entry)
            return;
        LogContentText.Text = "Loading log...";
        try
        {
            var content = await File.ReadAllTextAsync(entry.Path);
            if (Equals(HistoryList.SelectedItem, entry))
                LogContentText.Text = content;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            if (Equals(HistoryList.SelectedItem, entry))
                LogContentText.Text = $"This log could not be opened.{Environment.NewLine}{Environment.NewLine}{exception}";
        }
    }

    private void Close_Click(object sender, RoutedEventArgs e) => Close();
}
