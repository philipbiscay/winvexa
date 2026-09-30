using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace Winvexa;

internal sealed class ThreatNotificationWindow : Window
{
    public ThreatNotificationWindow(
        Window owner,
        string heading,
        string threatName,
        string fileName,
        string severity,
        string disposition)
    {
        Title = "Winvexa security notification";
        Owner = owner;
        Width = 490;
        SizeToContent = SizeToContent.Height;
        MinHeight = 240;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        ResizeMode = ResizeMode.NoResize;
        Background = (Brush)owner.FindResource("WindowBackground");
        Foreground = owner.Foreground;
        GlassThemeService.ApplyToWindow(this, animateAppearance: false);

        var layout = new Grid { Margin = new Thickness(22) };
        layout.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        layout.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        layout.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        layout.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        layout.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

        var title = new TextBlock
        {
            Text = heading,
            FontSize = 20,
            FontWeight = FontWeights.Bold,
            TextWrapping = TextWrapping.Wrap
        };
        Grid.SetRow(title, 0);
        layout.Children.Add(title);

        var name = new TextBlock
        {
            Text = threatName,
            FontSize = 15,
            FontWeight = FontWeights.SemiBold,
            Margin = new Thickness(0, 12, 0, 0),
            TextWrapping = TextWrapping.Wrap
        };
        Grid.SetRow(name, 1);
        layout.Children.Add(name);

        var metadata = new TextBlock
        {
            Text = $"File: {fileName}{Environment.NewLine}Severity: {severity}",
            Margin = new Thickness(0, 7, 0, 0),
            TextWrapping = TextWrapping.Wrap
        };
        Grid.SetRow(metadata, 2);
        layout.Children.Add(metadata);

        var action = new TextBlock
        {
            Text = disposition,
            Margin = new Thickness(0, 9, 0, 0),
            Foreground = (Brush)owner.FindResource("MutedBrush"),
            TextWrapping = TextWrapping.Wrap
        };
        Grid.SetRow(action, 3);
        layout.Children.Add(action);

        var buttons = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            HorizontalAlignment = HorizontalAlignment.Right,
            Margin = new Thickness(0, 18, 0, 0)
        };
        var detailsButton = new Button
        {
            Content = "View Details",
            MinWidth = 108,
            Background = (Brush)owner.FindResource("AccentGradient"),
            Foreground = Brushes.White,
            IsDefault = true
        };
        detailsButton.Click += (_, _) =>
        {
            DialogResult = true;
            Close();
        };
        var closeButton = new Button
        {
            Content = "Close",
            MinWidth = 88,
            Margin = new Thickness(8, 0, 0, 0),
            Background = (Brush)owner.FindResource("AccentSoftBrush"),
            Foreground = (Brush)owner.FindResource("AccentBrush"),
            IsCancel = true
        };
        buttons.Children.Add(detailsButton);
        buttons.Children.Add(closeButton);
        Grid.SetRow(buttons, 4);
        layout.Children.Add(buttons);

        Content = layout;
    }
}
