using System.Text.Json;
using System.Text.Json.Nodes;

namespace Winvexa;

internal static class LiquidGlassPreference
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    public static bool Read(string json)
    {
        using var document = JsonDocument.Parse(json);
        return Read(document.RootElement);
    }

    public static string Normalize(string? json, out bool enabled, out bool recovered)
    {
        try
        {
            if (json is null)
            {
                enabled = false;
                recovered = false;
                return Write(null, enabled);
            }

            using var document = JsonDocument.Parse(json);
            enabled = Read(document.RootElement);
            recovered = false;
            return Write(json, enabled);
        }
        catch (JsonException)
        {
            enabled = false;
            recovered = json is not null;
            return Write(null, enabled);
        }
    }

    private static bool Read(JsonElement settings)
    {
        if (settings.ValueKind != JsonValueKind.Object)
            throw new JsonException("The saved appearance settings must be a JSON object.");

        if (TryReadBoolean(settings, "LiquidGlass", out var enabled))
            return enabled;
        if (TryReadBoolean(settings, "LiquidGlassEnabled", out enabled))
            return enabled;

        return false;
    }

    public static string Write(string? json, bool enabled)
    {
        var settings = json is null
            ? new JsonObject()
            : JsonNode.Parse(json) as JsonObject
              ?? throw new JsonException("The saved appearance settings must be a JSON object.");
        settings["LiquidGlass"] = enabled;
        return settings.ToJsonString(JsonOptions);
    }

    private static bool TryReadBoolean(JsonElement settings, string propertyName, out bool value)
    {
        if (!settings.TryGetProperty(propertyName, out var property) ||
            property.ValueKind == JsonValueKind.Null)
        {
            value = false;
            return false;
        }

        if (property.ValueKind is JsonValueKind.True or JsonValueKind.False)
        {
            value = property.GetBoolean();
            return true;
        }

        value = false;
        return false;
    }
}
