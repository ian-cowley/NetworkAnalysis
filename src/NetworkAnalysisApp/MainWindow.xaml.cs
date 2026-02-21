using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

namespace NetworkAnalysisApp;

/// <summary>
/// Interaction logic for MainWindow.xaml
/// </summary>
public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
        var vm = new ViewModels.MainViewModel();
        DataContext = vm;

        // Auto-Scroll implementation
        vm.Packets.CollectionChanged += (s, e) =>
        {
            if (e.Action == System.Collections.Specialized.NotifyCollectionChangedAction.Add && AutoScrollToggle.IsChecked == true)
            {
                if (e.NewItems != null && e.NewItems.Count > 0)
                {
                    // Scroll to the last item added
                    var lastItem = e.NewItems[e.NewItems.Count - 1];
                    // Dispatch to ensure UI is ready
                    Dispatcher.BeginInvoke(() =>
                    {
                        PacketDataGrid.ScrollIntoView(lastItem);
                    }, System.Windows.Threading.DispatcherPriority.Background);
                }
            }
        };
    }

    private void EditProtocols_Click(object sender, RoutedEventArgs e)
    {
        if (DataContext is ViewModels.MainViewModel vm)
        {
            var maintenanceWindow = new ProtocolMaintenanceWindow(vm.Protocols);
            maintenanceWindow.Owner = this;
            maintenanceWindow.ShowDialog();
        }
    }

    private void Dashboard_Click(object sender, RoutedEventArgs e)
    {
        if (DataContext is ViewModels.MainViewModel vm)
        {
            var statsWindow = new StatisticsWindow
            {
                Owner = this,
                DataContext = new ViewModels.StatisticsViewModel(vm.Packets)
            };
            statsWindow.Show();
        }
    }

    private void Help_Click(object sender, RoutedEventArgs e)
    {
        var helpWindow = new HelpWindow();
        helpWindow.Owner = this;
        helpWindow.Show();
    }
}