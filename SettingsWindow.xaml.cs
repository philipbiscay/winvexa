using System.IO;
using System.Text.Json;
using System.Windows;

namespace Winvexa;

public partial class SettingsWindow : Window
{
    private bool _initializing;

    public SettingsWindow(string logPath, bool isAdministrator, string windowsVersion)
    {
        InitializeComponent();
        GlassThemeService.ApplyToWindow(this);
        _initializing = true;
        LiquidGlassToggle.IsChecked = GlassThemeService.IsEnabled;
        UpdateLiquidGlassStatus();
        _initializing = false;
        Loaded += (_, _) => UpdateLiquidGlassStatus();
        WindowsVersionText.Text = $"Windows version: {windowsVersion}";
        AdministratorText.Text = isAdministrator
            ? "Administrator permission: granted for this session"
            : "Administrator permission: not granted; some operations may request UAC";
        LogPathText.Text = logPath;
    }

    private void LiquidGlassToggle_Changed(object sender, RoutedEventArgs e)
    {
        if (_initializing || LiquidGlassToggle.IsChecked is not bool enabled)
            return;

        try
        {
            GlassThemeService.SetEnabled(enabled);
            UpdateLiquidGlassStatus();
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or System.Security.SecurityException or JsonException)
        {
            _initializing = true;
            LiquidGlassToggle.IsChecked = GlassThemeService.IsEnabled;
            _initializing = false;
            UpdateLiquidGlassStatus();
            MessageBox.Show(
                this,
                $"Winvexa could not save the Liquid Glass preference. The current appearance was not changed.{Environment.NewLine}{Environment.NewLine}{exception.Message}",
                "Settings could not be saved",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
    }

    private void UpdateLiquidGlassStatus()
    {
        LiquidGlassValueText.Text = $"Liquid Glass: {(GlassThemeService.IsEnabled ? "ON" : "OFF")}";
        LiquidGlassStatusText.Text = GlassThemeService.EffectDescription;
    }

    private void Close_Click(object sender, RoutedEventArgs e) => Close();
}
