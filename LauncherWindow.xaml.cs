using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;

namespace Winvexa;

public partial class LauncherWindow : Window
{
    private const int DwmWindowCornerPreference = 33;
    private const int DwmWindowCornerRound = 2;

    public LauncherWindow()
    {
        InitializeComponent();
        GlassThemeService.ApplyToWindow(this);
        SourceInitialized += (_, _) =>
        {
            var handle = new WindowInteropHelper(this).Handle;
            var preference = DwmWindowCornerRound;
            _ = DwmSetWindowAttribute(
                handle,
                DwmWindowCornerPreference,
                ref preference,
                sizeof(int));
        };
    }

    private void LauncherWindow_Loaded(object sender, RoutedEventArgs e)
    {
        OpenWinvexaButton.Focus();
        ReadyStatusText.Text = "Winvexa is ready";
    }

    private void OpenWinvexa_Click(object sender, RoutedEventArgs e)
    {
        OpenWinvexaButton.IsEnabled = false;
        ReadyStatusText.Text = "Opening your dashboard…";
        if (Application.Current is App app)
            app.OpenMainWindow();
    }

    private void Settings_Click(object sender, RoutedEventArgs e)
    {
        if (Application.Current is App app)
            app.OpenMainWindow(openSettings: true);
    }

    private void Exit_Click(object sender, RoutedEventArgs e) =>
        Application.Current.Shutdown();

    [DllImport("dwmapi.dll", PreserveSig = true)]
    private static extern int DwmSetWindowAttribute(
        IntPtr hwnd,
        int attribute,
        ref int attributeValue,
        int attributeSize);
}
