using System.Diagnostics;
using System.IO;

namespace Winvexa;

internal static class InstallerCommand
{
    internal const string InstallerPathEnvironmentVariable = "WINVEXA_INSTALLER_PATH";

    internal static string ResolveInstallerPath(string? configuredPath, string applicationDirectory)
    {
        var path = string.IsNullOrWhiteSpace(configuredPath)
            ? Environment.GetEnvironmentVariable(InstallerPathEnvironmentVariable)
            : configuredPath;

        if (!string.IsNullOrWhiteSpace(path))
        {
            var resolvedPath = Path.GetFullPath(Environment.ExpandEnvironmentVariables(path.Trim()));
            if (File.Exists(resolvedPath))
                return resolvedPath;

            throw new FileNotFoundException(
                $"The configured Winvexa installer was not found: {resolvedPath}",
                resolvedPath);
        }

        var candidates = new[]
        {
            Path.Combine(applicationDirectory, "WinvexaSetup.exe"),
            Path.Combine(applicationDirectory, "Winvexa-Setup.exe")
        };
        var installerPath = candidates.FirstOrDefault(File.Exists);
        if (installerPath is not null)
            return installerPath;

        throw new FileNotFoundException(
            $"The Winvexa installer is missing. Place WinvexaSetup.exe or Winvexa-Setup.exe next to Winvexa.exe, or set {InstallerPathEnvironmentVariable} or pass an installer path with /install.");
    }

    internal static ProcessStartInfo CreateStartInfo(string installerPath) =>
        new(installerPath)
        {
            UseShellExecute = true,
            Verb = "runas",
            WorkingDirectory = Path.GetDirectoryName(installerPath)
                ?? throw new InvalidOperationException("The Winvexa installer directory could not be resolved."),
            Arguments = "/SILENT /NORESTART"
        };
}
