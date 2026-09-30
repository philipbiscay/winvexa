using System.IO;
using System.Security;

namespace Winvexa;

internal sealed class LiquidGlassSettingsStore(string settingsPath)
{
    private readonly string _settingsPath = Path.GetFullPath(settingsPath);

    public string? Load(out bool enabled)
    {
        string? savedSettings;
        try
        {
            savedSettings = ReadSettingsIfPresent();
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or SecurityException)
        {
            enabled = false;
            return $"The saved appearance settings could not be read. Winvexa started with Liquid Glass off; the settings file was left unchanged. Details: {exception.Message}";
        }

        var normalizedSettings = LiquidGlassPreference.Normalize(savedSettings, out enabled, out var recovered);
        try
        {
            if (savedSettings is null || !string.Equals(savedSettings, normalizedSettings, StringComparison.Ordinal))
            {
                string? backupPath = null;
                if (recovered)
                    backupPath = PreserveInvalidSettings();
                WriteSettings(normalizedSettings);

                if (recovered)
                    return $"Winvexa recovered invalid appearance settings and restored safe defaults. The original file was preserved{(backupPath is null ? "" : $" at '{backupPath}'")}.";
            }
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or SecurityException)
        {
            return $"Winvexa started with Liquid Glass {(enabled ? "on" : "off")}, but could not save the corrected appearance settings. The preference may not persist after restart. Details: {exception.Message}";
        }

        return null;
    }

    public void Save(bool enabled)
    {
        var existingSettings = ReadSettingsIfPresent();
        var normalizedSettings = LiquidGlassPreference.Normalize(existingSettings, out _, out var recovered);
        var updatedSettings = LiquidGlassPreference.Write(normalizedSettings, enabled);
        if (recovered)
            PreserveInvalidSettings();
        WriteSettings(updatedSettings);
    }

    private string? ReadSettingsIfPresent()
    {
        try
        {
            return File.ReadAllText(_settingsPath);
        }
        catch (FileNotFoundException)
        {
            return null;
        }
        catch (DirectoryNotFoundException)
        {
            return null;
        }
    }

    private string PreserveInvalidSettings()
    {
        var backupPath = _settingsPath + ".corrupt-" + Guid.NewGuid().ToString("N");
        File.Move(_settingsPath, backupPath);
        return backupPath;
    }

    private void WriteSettings(string settings)
    {
        var directory = Path.GetDirectoryName(_settingsPath)
            ?? throw new InvalidOperationException("The Winvexa settings directory could not be resolved.");
        Directory.CreateDirectory(directory);
        var temporaryPath = _settingsPath + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            File.WriteAllText(temporaryPath, settings);
            File.Move(temporaryPath, _settingsPath, overwrite: true);
        }
        catch (Exception exception)
        {
            try
            {
                File.Delete(temporaryPath);
            }
            catch (FileNotFoundException)
            {
            }
            catch (Exception cleanupException) when (
                cleanupException is IOException or UnauthorizedAccessException or SecurityException)
            {
                throw new IOException(
                    $"Winvexa could not save its settings, and the temporary file '{temporaryPath}' could not be removed.",
                    new AggregateException(exception, cleanupException));
            }

            System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(exception).Throw();
            throw;
        }
    }
}
