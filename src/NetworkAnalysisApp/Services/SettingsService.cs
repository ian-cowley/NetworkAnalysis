using System.IO;
using System.Text.Json;
using NetworkAnalysisApp.Models;

namespace NetworkAnalysisApp.Services
{
    public class SettingsService
    {
        private readonly string _configPath = "appconfig.json";

        public AppConfig LoadConfig()
        {
            if (File.Exists(_configPath))
            {
                try
                {
                    var json = File.ReadAllText(_configPath);
                    return JsonSerializer.Deserialize<AppConfig>(json) ?? new AppConfig();
                }
                catch
                {
                    return new AppConfig();
                }
            }
            
            var defaultConfig = new AppConfig();
            SaveConfig(defaultConfig);
            return defaultConfig;
        }

        public void SaveConfig(AppConfig config)
        {
            try
            {
                var options = new JsonSerializerOptions { WriteIndented = true };
                var json = JsonSerializer.Serialize(config, options);
                File.WriteAllText(_configPath, json);
            }
            catch { }
        }
    }
}
