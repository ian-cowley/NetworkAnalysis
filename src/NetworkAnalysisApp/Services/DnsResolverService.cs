using System;
using System.Collections.Concurrent;
using System.Net;
using System.Threading.Tasks;

namespace NetworkAnalysisApp.Services
{
    public class DnsResolverService
    {
        // Thread-safe cache of Ip Address -> Domain Name
        private readonly ConcurrentDictionary<string, string> _dnsCache = new ConcurrentDictionary<string, string>();
        
        // Prevents querying the same IP multiple times simultaneously
        private readonly ConcurrentDictionary<string, byte> _pendingLookups = new ConcurrentDictionary<string, byte>();

        public string GetResolvedNameOrIP(string ipAddress, Action<string, string> onResolvedCallback)
        {
            if (string.IsNullOrWhiteSpace(ipAddress))
                return string.Empty;

            // Immediately return if cached
            if (_dnsCache.TryGetValue(ipAddress, out var resolvedName))
            {
                return resolvedName;
            }

            // Localhost shortcut
            if (ipAddress == "127.0.0.1" || ipAddress == "::1")
            {
                _dnsCache[ipAddress] = "localhost";
                return "localhost";
            }

            // Not in cache, start background resolution if not already pending
            if (_pendingLookups.TryAdd(ipAddress, 0))
            {
                Task.Run(async () =>
                {
                    try
                    {
                        var hostEntry = await Dns.GetHostEntryAsync(ipAddress);
                        if (!string.IsNullOrEmpty(hostEntry.HostName))
                        {
                            _dnsCache[ipAddress] = hostEntry.HostName;
                            onResolvedCallback?.Invoke(ipAddress, hostEntry.HostName);
                        }
                        else
                        {
                            _dnsCache[ipAddress] = ipAddress; // Cache the raw IP to prevent re-querying failures
                        }
                    }
                    catch
                    {
                        // DNS resolution failed (common for private IPs or untracked addresses)
                        _dnsCache[ipAddress] = ipAddress;
                    }
                    finally
                    {
                        _pendingLookups.TryRemove(ipAddress, out _);
                    }
                });
            }

            // Return the raw IP while lookup happens
            return ipAddress;
        }
        
        public void ClearCache()
        {
            _dnsCache.Clear();
            _pendingLookups.Clear();
        }
    }
}
