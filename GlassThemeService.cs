using System.IO;
using System.Runtime.InteropServices;
using System.Windows.Media.Animation;
using System.Windows.Interop;
using System.Windows;
using System.Windows.Media;

namespace Winvexa;

internal static class GlassThemeService
{
    private const int SystemBackdropAttribute = 38;
    private const int BackdropNone = 1;
    private const int BackdropAcrylic = 3;
    private const int AccentPolicyAttribute = 19;
    private const int AccentDisabled = 0;
    private const int AccentEnableAcrylicBlurBehind = 4;
    private const int AccentEnableFlags = 2;
    private const uint AcrylicTint = 0xA8F5F9FC;
    private static readonly Duration ThemeTransitionDuration = new(TimeSpan.FromMilliseconds(220));
    private static readonly Duration WindowFadeDuration = new(TimeSpan.FromMilliseconds(180));
    private static readonly string SettingsPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Winvexa",
        "settings.json");
    private static readonly LiquidGlassSettingsStore SettingsStore = new(SettingsPath);
    private static readonly Dictionary<string, Color> StandardColors = new(StringComparer.Ordinal)
    {
        ["WindowBackground"] = Color.FromRgb(0xF2, 0xF5, 0xF9),
        ["CardBackground"] = Color.FromRgb(0xFF, 0xFF, 0xFF),
        ["AccentSoftBrush"] = Color.FromRgb(0xE7, 0xF2, 0xF8),
        ["DangerBackgroundBrush"] = Color.FromRgb(0xFB, 0xE9, 0xE8),
        ["DangerForegroundBrush"] = Color.FromRgb(0xA3, 0x3D, 0x3B),
        ["ProgressTrackBrush"] = Color.FromRgb(0xDF, 0xE8, 0xEF),
        ["BorderBrush"] = Color.FromRgb(0xDC, 0xE4, 0xEC),
        ["SubtleBrush"] = Color.FromRgb(0xF5, 0xF8, 0xFB)
    };
    private static readonly Color[] StandardHeroColors =
    [
        Color.FromRgb(0xF5, 0xFA, 0xFD),
        Color.FromRgb(0xE9, 0xF3, 0xF8)
    ];
    private static readonly Color[] GlassHeroColors =
    [
        Color.FromArgb(0xCA, 0xF5, 0xFA, 0xFD),
        Color.FromArgb(0xA6, 0xDF, 0xED, 0xF5)
    ];
    private static readonly Color[] StandardHighlightColors =
    [
        Colors.Transparent,
        Colors.Transparent
    ];
    private static readonly Color[] GlassHighlightColors =
    [
        Color.FromArgb(0x48, 0xFF, 0xFF, 0xFF),
        Color.FromArgb(0x00, 0xFF, 0xFF, 0xFF)
    ];
    private static readonly HashSet<Window> RegisteredWindows = [];
    private static readonly Dictionary<Window, WindowBackdrop> WindowBackdrops = [];
    private static Application? _application;
    private static int _acrylicWindowCount;
    private static int _systemBackdropWindowCount;

    public static bool IsEnabled { get; private set; }
    private static bool ReducedMotion => !SystemParameters.ClientAreaAnimation;

    public static string EffectDescription => !IsEnabled
        ? "Liquid Glass is off. The standard Winvexa appearance is active."
        : _acrylicWindowCount > 0
            ? "Windows Acrylic blur is active behind Winvexa's translucent, highlighted glass surfaces."
            : _systemBackdropWindowCount > 0
                ? "Windows Acrylic is unavailable; the native Windows system backdrop is active behind translucent glass surfaces."
                : "Windows glass blur is unavailable; translucent Winvexa surfaces are active without a native backdrop.";

    public static string? Initialize(Application application)
    {
        _application = application;
        var warning = SettingsStore.Load(out var enabled);
        Apply(enabled, transition: false);
        return warning;
    }

    public static void SetEnabled(bool enabled)
    {
        SettingsStore.Save(enabled);
        Apply(enabled, transition: true);
    }

    public static void ApplyToWindow(Window window, bool animateAppearance = true)
    {
        if (RegisteredWindows.Add(window))
        {
            window.Opacity = !animateAppearance || ReducedMotion ? 1 : 0;
            if (animateAppearance)
                window.Loaded += Window_Loaded;
            window.SourceInitialized += Window_SourceInitialized;
            window.Closed += (_, _) =>
            {
                RegisteredWindows.Remove(window);
                WindowBackdrops.Remove(window);
                UpdateBackdropStatus();
            };
        }

        if (!OperatingSystem.IsWindows())
            return;

        var handle = new WindowInteropHelper(window).Handle;
        if (handle == IntPtr.Zero)
            return;

        ApplyBackdrop(handle);
        UpdateBackdropStatus();
    }

    private static void Window_Loaded(object sender, RoutedEventArgs e)
    {
        if (sender is not Window window)
            return;
        window.Loaded -= Window_Loaded;
        if (ReducedMotion)
        {
            window.Opacity = 1;
            return;
        }

        window.BeginAnimation(
            UIElement.OpacityProperty,
            new DoubleAnimation(0, 1, WindowFadeDuration)
            {
                EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
            },
            HandoffBehavior.SnapshotAndReplace);
    }

    private static void Window_SourceInitialized(object? sender, EventArgs e)
    {
        if (sender is Window window)
            ApplyToWindow(window);
    }

    private static void Apply(bool enabled, bool transition)
    {
        IsEnabled = enabled;
        if (_application is null)
            return;

        foreach (var pair in StandardColors)
        {
            var color = enabled
                ? pair.Key switch
                {
                    "WindowBackground" => Color.FromArgb(0x48, 0xF2, 0xF6, 0xFA),
                    "CardBackground" => Color.FromArgb(0xA8, 0xFF, 0xFF, 0xFF),
                    "AccentSoftBrush" => Color.FromArgb(0xB2, 0xD9, 0xED, 0xF5),
                    "DangerBackgroundBrush" => Color.FromArgb(0xB8, 0xF5, 0xE5, 0xE4),
                    "DangerForegroundBrush" => pair.Value,
                    "ProgressTrackBrush" => Color.FromArgb(0x98, 0xD8, 0xE4, 0xEC),
                    "BorderBrush" => Color.FromArgb(0x90, 0xB9, 0xCE, 0xDD),
                    "SubtleBrush" => Color.FromArgb(0xA0, 0xE8, 0xF0, 0xF5),
                    _ => pair.Value
                }
                : pair.Value;
            SetBrushColor(pair.Key, color, transition);
        }

        SetHeroGradient(enabled ? GlassHeroColors : StandardHeroColors, transition);
        SetHighlightGradient(enabled ? GlassHighlightColors : StandardHighlightColors, transition);

        WindowBackdrops.Clear();
        foreach (Window window in _application.Windows)
            ApplyToWindow(window);
        UpdateBackdropStatus();
    }

    private static void SetBrushColor(string key, Color color, bool transition)
    {
        if (_application is null || !_application.Resources.Contains(key))
            return;

        var currentBrush = _application.Resources[key] as SolidColorBrush;
        var brush = currentBrush?.CloneCurrentValue() ?? new SolidColorBrush(color);
        if (transition && !ReducedMotion)
        {
            brush.BeginAnimation(
                SolidColorBrush.ColorProperty,
                new ColorAnimation
                {
                    From = brush.Color,
                    To = color,
                    Duration = ThemeTransitionDuration,
                    EasingFunction = new CubicEase { EasingMode = EasingMode.EaseInOut }
                },
                HandoffBehavior.SnapshotAndReplace);
        }
        else
            brush.Color = color;

        _application.Resources[key] = brush;
    }

    private static void SetHeroGradient(IReadOnlyList<Color> colors, bool transition)
    {
        if (_application is null)
            return;
        var gradient = new LinearGradientBrush
        {
            StartPoint = new Point(0, 0),
            EndPoint = new Point(1, 1)
        };
        for (var index = 0; index < colors.Count; index++)
        {
            var offset = index / (double)Math.Max(1, colors.Count - 1);
            var initialColor = _application.Resources["HeroGradient"] is LinearGradientBrush previous &&
                               previous.GradientStops.Count > index
                ? previous.GradientStops[index].Color
                : colors[index];
            gradient.GradientStops.Add(new GradientStop(initialColor, offset));
        }

        if (transition && !ReducedMotion)
            AnimateGradientStops(gradient, colors);
        else
            SetGradientStopColors(gradient, colors);
        _application.Resources["HeroGradient"] = gradient;
    }

    private static void SetHighlightGradient(IReadOnlyList<Color> colors, bool transition)
    {
        if (_application is null)
            return;

        var gradient = new LinearGradientBrush
        {
            StartPoint = new Point(0, 0),
            EndPoint = new Point(1, 1)
        };
        for (var index = 0; index < colors.Count; index++)
        {
            var offset = index / (double)Math.Max(1, colors.Count - 1);
            var initialColor = _application.Resources["GlassHighlightBrush"] is LinearGradientBrush previous &&
                               previous.GradientStops.Count > index
                ? previous.GradientStops[index].Color
                : colors[index];
            gradient.GradientStops.Add(new GradientStop(initialColor, offset));
        }

        if (transition && !ReducedMotion)
            AnimateGradientStops(gradient, colors);
        else
            SetGradientStopColors(gradient, colors);
        _application.Resources["GlassHighlightBrush"] = gradient;
    }

    private static void SetGradientStopColors(LinearGradientBrush gradient, IReadOnlyList<Color> colors)
    {
        for (var index = 0; index < colors.Count; index++)
            gradient.GradientStops[index].Color = colors[index];
    }

    private static void AnimateGradientStops(LinearGradientBrush gradient, IReadOnlyList<Color> colors)
    {
        for (var index = 0; index < colors.Count; index++)
        {
            gradient.GradientStops[index].BeginAnimation(
                GradientStop.ColorProperty,
                new ColorAnimation
                {
                    From = gradient.GradientStops[index].Color,
                    To = colors[index],
                    Duration = ThemeTransitionDuration,
                    EasingFunction = new CubicEase { EasingMode = EasingMode.EaseInOut }
                },
                HandoffBehavior.SnapshotAndReplace);
        }
    }

    private static void ApplyBackdrop(IntPtr handle)
    {
        if (!IsEnabled)
        {
            _ = SetAccentBackdrop(handle, enabled: false);
            _ = SetSystemBackdrop(handle, BackdropNone);
            return;
        }

        if (SetAccentBackdrop(handle, enabled: true))
        {
            _ = SetSystemBackdrop(handle, BackdropNone);
            RecordBackdrop(handle, WindowBackdrop.Acrylic);
            return;
        }

        _ = SetAccentBackdrop(handle, enabled: false);
        var systemBackdrop = OperatingSystem.IsWindowsVersionAtLeast(10, 0, 22621) &&
                             SetSystemBackdrop(handle, BackdropAcrylic);
        RecordBackdrop(handle, systemBackdrop ? WindowBackdrop.System : WindowBackdrop.None);
    }

    private static void RecordBackdrop(IntPtr handle, WindowBackdrop backdrop)
    {
        if (_application is null)
            return;

        foreach (Window window in _application.Windows)
        {
            if (new WindowInteropHelper(window).Handle == handle)
            {
                WindowBackdrops[window] = backdrop;
                return;
            }
        }
    }

    private static void UpdateBackdropStatus()
    {
        _acrylicWindowCount = WindowBackdrops.Values.Count(value => value == WindowBackdrop.Acrylic);
        _systemBackdropWindowCount = WindowBackdrops.Values.Count(value => value == WindowBackdrop.System);
    }

    private static bool SetAccentBackdrop(IntPtr handle, bool enabled)
    {
        var policy = new AccentPolicy
        {
            State = enabled ? AccentEnableAcrylicBlurBehind : AccentDisabled,
            Flags = enabled ? AccentEnableFlags : 0,
            GradientColor = enabled ? AcrylicTint : 0
        };
        var policyPointer = Marshal.AllocHGlobal(Marshal.SizeOf<AccentPolicy>());
        try
        {
            Marshal.StructureToPtr(policy, policyPointer, fDeleteOld: false);
            var data = new WindowCompositionAttributeData
            {
                Attribute = AccentPolicyAttribute,
                Data = policyPointer,
                SizeOfData = Marshal.SizeOf<AccentPolicy>()
            };
            return SetWindowCompositionAttribute(handle, ref data);
        }
        catch (DllNotFoundException)
        {
            return false;
        }
        catch (EntryPointNotFoundException)
        {
            return false;
        }
        finally
        {
            Marshal.FreeHGlobal(policyPointer);
        }
    }

    private static bool SetSystemBackdrop(IntPtr handle, int backdrop)
    {
        try
        {
            return DwmSetWindowAttribute(
                handle,
                SystemBackdropAttribute,
                ref backdrop,
                sizeof(int)) == 0;
        }
        catch (DllNotFoundException)
        {
            return false;
        }
        catch (EntryPointNotFoundException)
        {
            return false;
        }
    }

    [DllImport("user32.dll", PreserveSig = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetWindowCompositionAttribute(
        IntPtr hwnd,
        ref WindowCompositionAttributeData data);

    [DllImport("dwmapi.dll", PreserveSig = true)]
    private static extern int DwmSetWindowAttribute(
        IntPtr hwnd,
        int attribute,
        ref int value,
        int valueSize);

    [StructLayout(LayoutKind.Sequential)]
    private struct AccentPolicy
    {
        public int State;
        public int Flags;
        public uint GradientColor;
        public int AnimationId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WindowCompositionAttributeData
    {
        public int Attribute;
        public IntPtr Data;
        public int SizeOfData;
    }

    private enum WindowBackdrop
    {
        None,
        Acrylic,
        System
    }
}
