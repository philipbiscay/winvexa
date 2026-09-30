using System.Reflection;
using System.IO;
using System.Text;
using System.Windows;

namespace Winvexa;

public partial class AboutWindow : Window
{
    public AboutWindow()
    {
        InitializeComponent();
        GlassThemeService.ApplyToWindow(this);
        var assembly = Assembly.GetExecutingAssembly();
        var informationalVersion = assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
            ?? throw new InvalidOperationException("The Winvexa application version metadata is missing.");
        VersionText.Text = $"Version {informationalVersion}";
        var executable = Environment.ProcessPath;
        var build = string.IsNullOrWhiteSpace(executable)
            ? "Unavailable"
            : new FileInfo(executable).LastWriteTime.ToString("yyyy-MM-dd");
        BuildText.Text = $"Build {build}";
        var changelogResourceName = assembly.GetManifestResourceNames()
            .Where(name => name.EndsWith("CHANGELOG.md", StringComparison.Ordinal))
            .FirstOrDefault();
        using var changelog = changelogResourceName is null
            ? null
            : assembly.GetManifestResourceStream(changelogResourceName);
        if (changelog is null)
            throw new InvalidOperationException("The embedded Winvexa release history could not be loaded.");
        ChangelogText.Text = ReadChangelog(changelog);
    }

    private static string ReadChangelog(Stream stream)
    {
        using var reader = new StreamReader(stream);
        var formatted = new StringBuilder();
        foreach (var line in reader.ReadToEnd().Split(["\r\n", "\n"], StringSplitOptions.None))
        {
            if (line.StartsWith("# ", StringComparison.Ordinal))
                formatted.AppendLine(line[2..]);
            else if (line.StartsWith("## ", StringComparison.Ordinal))
                formatted.AppendLine().AppendLine(line[3..]);
            else if (line.StartsWith("- ", StringComparison.Ordinal))
                formatted.Append("• ").AppendLine(line[2..]);
            else
                formatted.AppendLine(line);
        }
        return formatted.ToString().Trim();
    }

    private void Close_Click(object sender, RoutedEventArgs e) => Close();
}
