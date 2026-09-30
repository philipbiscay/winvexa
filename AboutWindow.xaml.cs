using System.Reflection;
using System.IO;
using System.Windows;

namespace Winvexa;

public partial class AboutWindow : Window
{
    public AboutWindow()
    {
        InitializeComponent();
        GlassThemeService.ApplyToWindow(this);
        var assembly = Assembly.GetExecutingAssembly();
        VersionText.Text = $"Version {assembly.GetName().Version?.ToString(3) ?? "Unknown"}";
        var informationalVersion = assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
        if (!string.IsNullOrWhiteSpace(informationalVersion) &&
            !informationalVersion.StartsWith(VersionText.Text["Version ".Length..], StringComparison.Ordinal))
        {
            VersionText.Text += $" ({informationalVersion})";
        }
        var executable = Environment.ProcessPath;
        var build = string.IsNullOrWhiteSpace(executable)
            ? "Unavailable"
            : new FileInfo(executable).LastWriteTime.ToString("yyyy-MM-dd");
        BuildText.Text = $"Build {build}";
        ChangelogText.Text =
            $"Current release: Winvexa {assembly.GetName().Version?.ToString(3) ?? "Unknown"}.{Environment.NewLine}{Environment.NewLine}" +
            "Version 1.9.0 rebuilds the release pipeline around the project version, keeps source and portable installer inputs in sync, and requires the supported .NET 8 SDK before launch builds. The Windows Defender integration remains the security provider: Defender reports detections, scans, and protection history, and Windows Security owns threat remediation and quarantine. " +
            "Version 1.8.0 adds an Antivirus & Security page backed by Windows-reported Microsoft Defender status, scan history, active threat information, supported Quick/Full/Custom scans, scan cancellation through Defender, and verified security-intelligence updates. Repair My PC now checks Defender health first, asks before an outdated-intelligence update, and reports unresolved protection issues without changing Defender settings. " +
            "Version 1.7.0 adds a pre-repair Windows source check: Winvexa records the installed Windows edition/build/architecture, explicitly checks the Microsoft Windows Update service, verifies Microsoft signatures for DISM/SFC, checks servicing-source policy, and runs a read-only DISM component-store check before repairs. Approved repairs use Windows servicing and only applicable Microsoft update payloads; the program does not download installation media or trigger a feature upgrade. If the source cannot be verified, repair is blocked. Version 1.6.0 added Windows Acrylic Liquid Glass blur, with native/fallback surfaces and remembered ON/OFF preference.";
    }

    private void Close_Click(object sender, RoutedEventArgs e) => Close();
}
