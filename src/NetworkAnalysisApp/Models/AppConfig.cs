using System.Collections.Generic;

namespace NetworkAnalysisApp.Models
{
    public class AppConfig
    {
        public string BrowserPath { get; set; } = @"C:\Program Files\Google\Chrome\Application\chrome.exe";
        public string SslKeyLogPath { get; set; } = @"C:\temp\sslkeys.log";

        public List<string> SrcIpHistory { get; set; } = new List<string> { "192.168.1.1", "10.0.0.1" };
        public List<string> DstIpHistory { get; set; } = new List<string> { "8.8.8.8", "1.1.1.1" };
        public List<string> FilterHistory { get; set; } = new List<string> { "port 443", "port 80", "icmp" };
        public List<string> SearchHistory { get; set; } = new List<string> { "HTTP", "GET", "POST", "password", "error" };
    }
}
