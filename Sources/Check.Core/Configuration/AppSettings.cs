namespace Check.Core.Configuration;

public class AppSettings
{
    public string XrayPath { get; set; } = "/app/xray/xray";
    public int XrayTimeoutSeconds { get; set; } = 5;
    public int MaxQueueSize { get; set; } = 1000;
    public int MaxConcurrentTests { get; set; } = 5;
    public int CacheTtlSeconds { get; set; } = 10;
    public int TestCooldownSeconds { get; set; } = 5;
}