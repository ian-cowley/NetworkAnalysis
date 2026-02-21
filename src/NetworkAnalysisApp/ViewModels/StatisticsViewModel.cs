using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Runtime.CompilerServices;
using NetworkAnalysisApp.Models;

namespace NetworkAnalysisApp.ViewModels
{
    public class ProtocolStat
    {
        public string Protocol { get; set; } = string.Empty;
        public int Count { get; set; }
        public long Bytes { get; set; }
        public double Percentage { get; set; }
    }

    public class StatisticsViewModel : INotifyPropertyChanged
    {
        private ObservableCollection<PacketModel> _packets;

        private int _totalPackets;
        public int TotalPackets
        {
            get => _totalPackets;
            set { _totalPackets = value; OnPropertyChanged(); }
        }

        private long _totalBytes;
        public long TotalBytes
        {
            get => _totalBytes;
            set { _totalBytes = value; OnPropertyChanged(); }
        }

        public ObservableCollection<ProtocolStat> ProtocolStats { get; } = new ObservableCollection<ProtocolStat>();

        public StatisticsViewModel(ObservableCollection<PacketModel> packets)
        {
            _packets = packets;
            _packets.CollectionChanged += Packets_CollectionChanged;
            CalculateStats();
        }

        private void Packets_CollectionChanged(object? sender, System.Collections.Specialized.NotifyCollectionChangedEventArgs e)
        {
            // For performance, we might want to throttle this in a real high-throughput scenario,
            // but for simplicity we'll recalculate.
            CalculateStats();
        }

        private void CalculateStats()
        {
            if (_packets == null || _packets.Count == 0) return;

            var stats = _packets.GroupBy(p => p.Protocol)
                .Select(g => new ProtocolStat
                {
                    Protocol = g.Key,
                    Count = g.Count(),
                    Bytes = g.Sum(p => (long)p.Length)
                })
                .OrderByDescending(s => s.Count)
                .ToList();

            TotalPackets = stats.Sum(s => s.Count);
            TotalBytes = stats.Sum(s => s.Bytes);

            System.Windows.Application.Current.Dispatcher.Invoke(() =>
            {
                ProtocolStats.Clear();
                foreach (var s in stats)
                {
                    s.Percentage = TotalPackets > 0 ? ((double)s.Count / TotalPackets) * 100 : 0;
                    ProtocolStats.Add(s);
                }
            });
        }

        public event PropertyChangedEventHandler? PropertyChanged;
        protected virtual void OnPropertyChanged([CallerMemberName] string? propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }
}
