using System;
using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Input;
using System.Windows.Threading;
using SharpPcap;
using NetworkAnalysisApp.Models;
using NetworkAnalysisApp.Services;

namespace NetworkAnalysisApp.ViewModels
{
    public class MainViewModel : ViewModelBase
    {
        private readonly CaptureService _captureService;
        private readonly DnsResolverService _dnsResolver;
        private readonly SettingsService _settingsService;
        private readonly LiveTlsDecryptionService _tlsService;
        private readonly Dispatcher _uiDispatcher;

        public AppConfig Config { get; private set; }

        public ObservableCollection<ILiveDevice> Devices { get; } = new ObservableCollection<ILiveDevice>();
        public ObservableCollection<PacketModel> Packets { get; } = new ObservableCollection<PacketModel>();
        public System.ComponentModel.ICollectionView PacketsView { get; }
        public ObservableCollection<ProtocolModel> Protocols { get; } = new ObservableCollection<ProtocolModel>();

        private ILiveDevice? _selectedDevice;
        public ILiveDevice? SelectedDevice
        {
            get => _selectedDevice;
            set
            {
                if (SetProperty(ref _selectedDevice, value))
                {
                    CommandManager.InvalidateRequerySuggested();
                }
            }
        }

        private PacketModel? _selectedPacket;
        public PacketModel? SelectedPacket
        {
            get => _selectedPacket;
            set
            {
                if (SetProperty(ref _selectedPacket, value))
                {
                    HighlightConversation(value);
                    OnPropertyChanged(nameof(SelectedPacketHex));
                    OnPropertyChanged(nameof(SelectedPacketText));
                }
            }
        }

        public string SelectedPacketHex
        {
            get
            {
                if (SelectedPacket?.Payload == null || SelectedPacket.Payload.Length == 0) return "No Application Payload.";
                return BitConverter.ToString(SelectedPacket.Payload).Replace("-", " ");
            }
        }

        public string SelectedPacketText
        {
            get
            {
                if (SelectedPacket?.Payload == null || SelectedPacket.Payload.Length == 0) return "No Application Payload.";
                
                var sb = new System.Text.StringBuilder();
                foreach (var b in SelectedPacket.Payload)
                {
                    if (b >= 32 && b <= 126)
                        sb.Append((char)b);
                    else
                        sb.Append('.');
                }
                return sb.ToString();
            }
        }

        private void HighlightConversation(PacketModel? selected)
        {
            foreach (var packet in Packets)
            {
                if (selected == null)
                {
                    packet.IsHighlighted = false;
                    continue;
                }

                // If both are IP packets and ports/IPs match in either direction, it is the same conversation
                bool isSameConversation = false;

                if (!string.IsNullOrEmpty(selected.SourceIp) && selected.SourcePort > 0)
                {
                    bool matchForward = (packet.SourceIp == selected.SourceIp && packet.DestinationIp == selected.DestinationIp && 
                                         packet.SourcePort == selected.SourcePort && packet.DestinationPort == selected.DestinationPort);

                    bool matchReverse = (packet.SourceIp == selected.DestinationIp && packet.DestinationIp == selected.SourceIp && 
                                         packet.SourcePort == selected.DestinationPort && packet.DestinationPort == selected.SourcePort);

                    isSameConversation = matchForward || matchReverse;
                }

                packet.IsHighlighted = isSameConversation;
            }
        }

        private string _filterSourceIp = string.Empty;
        public string FilterSourceIp
        {
            get => _filterSourceIp;
            set => SetProperty(ref _filterSourceIp, value);
        }

        private string _filterDestinationIp = string.Empty;
        public string FilterDestinationIp
        {
            get => _filterDestinationIp;
            set => SetProperty(ref _filterDestinationIp, value);
        }

        private string _filterExpression = "";
        public string FilterExpression
        {
            get => _filterExpression;
            set => SetProperty(ref _filterExpression, value);
        }

        private bool _isCapturing;
        public bool IsCapturing
        {
            get => _isCapturing;
            set => SetProperty(ref _isCapturing, value);
        }

        private string _searchText = string.Empty;
        public string SearchText
        {
            get => _searchText;
            set
            {
                if (SetProperty(ref _searchText, value))
                {
                    PacketsView.Refresh();
                    
                    if (!string.IsNullOrWhiteSpace(_searchText))
                    {
                        UpdateHistoryList(Config.SearchHistory, _searchText);
                        Config.SearchHistory = new System.Collections.Generic.List<string>(Config.SearchHistory);
                        OnPropertyChanged(nameof(Config)); // Force UI refresh
                        _settingsService.SaveConfig(Config);
                    }
                }
            }
        }

        private int _totalPacketsCaptured;
        public int TotalPacketsCaptured
        {
            get => _totalPacketsCaptured;
            set => SetProperty(ref _totalPacketsCaptured, value);
        }

        public ICommand StartCaptureCommand { get; }
        public ICommand StopCaptureCommand { get; }
        public ICommand ClearPacketsCommand { get; }
        public ICommand OpenFileCommand { get; }
        public ICommand SaveFileCommand { get; }
        public ICommand LaunchBrowserCommand { get; }

        public MainViewModel()
        {
            _uiDispatcher = Application.Current.Dispatcher;
            _captureService = new CaptureService();
            _dnsResolver = new DnsResolverService();
            _settingsService = new SettingsService();

            Config = _settingsService.LoadConfig();
            
            _tlsService = new LiveTlsDecryptionService(Config.SslKeyLogPath);

            _captureService.OnPacketCaptured += CaptureService_OnPacketCaptured;
            _captureService.OnCaptureError += CaptureService_OnCaptureError;
            _captureService.OnFileCaptureComplete += CaptureService_OnFileCaptureComplete;

            StartCaptureCommand = new RelayCommand(_ => StartCapture(), _ => SelectedDevice != null && !IsCapturing);
            StopCaptureCommand = new RelayCommand(_ => StopCapture(), _ => IsCapturing);
            ClearPacketsCommand = new RelayCommand(_ => ClearPackets());
            OpenFileCommand = new RelayCommand(_ => OpenFile(), _ => !IsCapturing);
            SaveFileCommand = new RelayCommand(_ => SaveFile(), _ => Packets.Count > 0 && !IsCapturing);
            LaunchBrowserCommand = new RelayCommand(_ => LaunchBrowser());

            PacketsView = System.Windows.Data.CollectionViewSource.GetDefaultView(Packets);
            PacketsView.Filter = SearchFilter;

            Protocols.Add(new ProtocolModel { Name = "tcp", IsSelected = false });
            Protocols.Add(new ProtocolModel { Name = "udp", IsSelected = false });
            Protocols.Add(new ProtocolModel { Name = "icmp", IsSelected = false });
            Protocols.Add(new ProtocolModel { Name = "arp", IsSelected = false });

            // Hook into property changed on protocol to rebuild filter logic, though usually done at Start time
            foreach(var p in Protocols)
            {
                p.PropertyChanged += (s, e) => {
                    if (e.PropertyName == nameof(ProtocolModel.IsSelected))
                    {
                        // Could rebuild filter string here if live updating was supported
                    }
                };
            }

            LoadDevices();
        }

        private void LoadDevices()
        {
            try
            {
                var devices = _captureService.GetDevices();
                foreach (var device in devices)
                {
                    Devices.Add(device);
                }
                
                if (Devices.Count > 0)
                {
                    SelectedDevice = Devices[0];
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error loading network interfaces (Are you running as Administrator?):\n\n{ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private string CompileBpfFilter()
        {
            var filters = new System.Collections.Generic.List<string>();

            if (!string.IsNullOrWhiteSpace(FilterSourceIp))
            {
                // Capture both directions so the decryption engine gets the server reply
                filters.Add($"(src host {FilterSourceIp.Trim()} or dst host {FilterSourceIp.Trim()})");
            }
            if (!string.IsNullOrWhiteSpace(FilterDestinationIp))
            {
                // Capture both directions so the decryption engine gets the server reply
                filters.Add($"(dst host {FilterDestinationIp.Trim()} or src host {FilterDestinationIp.Trim()})");
            }

            var selectedProtocols = new System.Collections.Generic.List<string>();
            foreach (var proto in Protocols)
            {
                if (proto.IsSelected)
                {
                    selectedProtocols.Add(proto.Name);
                }
            }

            string combinedProtocolFilter = "";
            if (selectedProtocols.Count > 0)
            {
                combinedProtocolFilter = "(" + string.Join(" or ", selectedProtocols) + ")";
                filters.Add(combinedProtocolFilter);
            }

            if (!string.IsNullOrWhiteSpace(FilterExpression))
            {
                filters.Add($"({FilterExpression.Trim()})");
            }

            return string.Join(" and ", filters);
        }

        private void UpdateHistoryList(System.Collections.Generic.List<string> historyList, string newItem)
        {
            if (string.IsNullOrWhiteSpace(newItem)) return;
            
            historyList.Remove(newItem);
            historyList.Insert(0, newItem);
            
            while (historyList.Count > 10)
            {
                historyList.RemoveAt(historyList.Count - 1);
            }
        }

        private void StartCapture()
        {
            if (SelectedDevice == null) return;
            
            // Re-evaluating BPF filter
            IsCapturing = true;
            Packets.Clear();
            _tlsService.Clear();
            TotalPacketsCaptured = 0;
            SelectedPacket = null;
            
            var filter = CompileBpfFilter();

            // Append to Config Histories and save
            UpdateHistoryList(Config.SrcIpHistory, FilterSourceIp);
            UpdateHistoryList(Config.DstIpHistory, FilterDestinationIp);
            UpdateHistoryList(Config.FilterHistory, FilterExpression);
            
            // Assigning new list references forces WPF to rebind the ComboBox ItemsSource correctly
            Config.SrcIpHistory = new System.Collections.Generic.List<string>(Config.SrcIpHistory);
            Config.DstIpHistory = new System.Collections.Generic.List<string>(Config.DstIpHistory);
            Config.FilterHistory = new System.Collections.Generic.List<string>(Config.FilterHistory);
            OnPropertyChanged(nameof(Config));
            
            _settingsService.SaveConfig(Config);

            _captureService.StartCapture(SelectedDevice, filter);
        }

        private bool SearchFilter(object item)
        {
            if (string.IsNullOrWhiteSpace(SearchText))
                return true;

            if (item is PacketModel packet)
            {
                // Check if the payload contains the ASCII search text (case-insensitive)
                if (packet.Payload == null || packet.Payload.Length == 0)
                    return false;

                try
                {
                    var asciiString = System.Text.Encoding.ASCII.GetString(packet.Payload);
                    return asciiString.Contains(SearchText, StringComparison.OrdinalIgnoreCase);
                }
                catch
                {
                    return false;
                }
            }
            return false;
        }

        private void StopCapture()
        {
            IsCapturing = false;
            _captureService.StopCapture();
        }

        private void ClearPackets()
        {
            Packets.Clear();
            _tlsService.Clear();
            TotalPacketsCaptured = 0;
            SelectedPacket = null;
            _dnsResolver.ClearCache();
        }

        private void CaptureService_OnFileCaptureComplete()
        {
            _uiDispatcher.Invoke(() =>
            {
                IsCapturing = false;
                CommandManager.InvalidateRequerySuggested();
            });
        }

        private void OpenFile()
        {
            var dialog = new Microsoft.Win32.OpenFileDialog
            {
                Filter = "PCAP Files (*.pcap;*.pcapng)|*.pcap;*.pcapng|All Files (*.*)|*.*",
                Title = "Open Packet Capture File"
            };

            if (dialog.ShowDialog() == true)
            {
                Packets.Clear();
                _tlsService.Clear();
                TotalPacketsCaptured = 0;
                SelectedPacket = null;
                IsCapturing = true; // Prevents other actions while loading
                _captureService.LoadFromPcap(dialog.FileName);
            }
        }

        private void SaveFile()
        {
            var dialog = new Microsoft.Win32.SaveFileDialog
            {
                Filter = "PCAP Files (*.pcap)|*.pcap|All Files (*.*)|*.*",
                Title = "Save Packet Capture File",
                DefaultExt = ".pcap"
            };

            if (dialog.ShowDialog() == true)
            {
                _captureService.SaveToPcap(dialog.FileName);
            }
        }

        private void LaunchBrowser()
        {
            try
            {
                // Ensure directory for log exists
                var logDir = System.IO.Path.GetDirectoryName(Config.SslKeyLogPath);
                if (!string.IsNullOrEmpty(logDir) && !System.IO.Directory.Exists(logDir))
                {
                    System.IO.Directory.CreateDirectory(logDir);
                }

                var psi = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = Config.BrowserPath,
                    UseShellExecute = false,
                    Arguments = $"--ssl-key-log-file=\"{Config.SslKeyLogPath}\" --user-data-dir=\"{System.IO.Path.Combine(logDir, "TempBrowserProfile")}\" --disable-quic"
                };
                psi.EnvironmentVariables["SSLKEYLOGFILE"] = Config.SslKeyLogPath;
                System.Diagnostics.Debug.WriteLine($"[LAUNCH_BROWSER] FileName: {psi.FileName}");
                System.Diagnostics.Debug.WriteLine($"[LAUNCH_BROWSER] Arguments: {psi.Arguments}");
                System.Diagnostics.Debug.WriteLine($"[LAUNCH_BROWSER] EnvVar: {psi.EnvironmentVariables["SSLKEYLOGFILE"]}");
                System.Diagnostics.Process.Start(psi);
            }
            catch (Exception ex)
            {
                System.Windows.MessageBox.Show($"Failed to launch browser: {ex.Message}\n\nCheck your appconfig.json paths.", "Launch Error", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Error);
            }
        }

        private void CaptureService_OnPacketCaptured(object? sender, PacketModel packet)
        {
            // Start async DNS lookups; callbacks will update the model on background threads
            // The ViewModelBase INotifyPropertyChanged will automatically bounce UI updates to the dispatcher if correctly configured,
            // but we must be careful with collections. The PacketModel properties are thread safe via UI databinding in WPF.
            packet.ResolvedSourceIp = _dnsResolver.GetResolvedNameOrIP(packet.SourceIp, (ip, name) => 
            {
                packet.ResolvedSourceIp = name;
            });

            packet.ResolvedDestinationIp = _dnsResolver.GetResolvedNameOrIP(packet.DestinationIp, (ip, name) => 
            {
                packet.ResolvedDestinationIp = name;
            });

            // Process TLS Decryption
            try
            {
                 var decrypted = _tlsService.ProcessPacket(packet);
                 if (decrypted != null)
                 {
                     packet.DecryptedPayload = decrypted;
                     packet.Info += " [Decrypted]";
                 }
            }
            catch
            {
                // Ignore decryption exceptions for individual packets to keep pipeline flowing
            }

            // Update UI on main thread efficiently
            _uiDispatcher.BeginInvoke(() =>
            {
                TotalPacketsCaptured++;
                Packets.Add(packet);
                // Optionally limit the collection size to avoid memory issues on long captures
                if (Packets.Count > 10000)
                {
                    Packets.RemoveAt(0);
                }
            }, DispatcherPriority.Background);
        }

        private void CaptureService_OnCaptureError(object? sender, string errorMessage)
        {
            _uiDispatcher.Invoke(() =>
            {
                IsCapturing = false;
                MessageBox.Show(errorMessage, "Capture Error", MessageBoxButton.OK, MessageBoxImage.Error);
            });
        }
    }
}
