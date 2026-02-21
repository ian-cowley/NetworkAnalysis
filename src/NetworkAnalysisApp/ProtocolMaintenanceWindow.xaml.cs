using System.Collections.ObjectModel;
using System.Windows;
using NetworkAnalysisApp.Models;

namespace NetworkAnalysisApp
{
    public partial class ProtocolMaintenanceWindow : Window
    {
        public ProtocolMaintenanceWindow(ObservableCollection<ProtocolModel> protocols)
        {
            InitializeComponent();
            DataContext = this;
            Protocols = protocols;
        }

        public ObservableCollection<ProtocolModel> Protocols { get; }

        private void AddButton_Click(object sender, RoutedEventArgs e)
        {
            string newProtocol = NewProtocolTextBox.Text.Trim().ToLower();
            if (!string.IsNullOrWhiteSpace(newProtocol))
            {
                // Check if it already exists
                bool exists = false;
                foreach (var p in Protocols)
                {
                    if (p.Name == newProtocol)
                    {
                        exists = true;
                        break;
                    }
                }

                if (!exists)
                {
                    Protocols.Add(new ProtocolModel { Name = newProtocol, IsSelected = true });
                    NewProtocolTextBox.Clear();
                }
                else
                {
                    MessageBox.Show("Protocol already exists.", "Validation", MessageBoxButton.OK, MessageBoxImage.Warning);
                }
            }
        }
    }
}
