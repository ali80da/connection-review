using System;

namespace Check.Core.Models.Receive;

public class ProtocolData
{
    public string Link { get; set; } = string.Empty;
    public string? Protocol { get; set; }
}

public class ConfigDetails
{
    public string Id { get; set; } = string.Empty;
    public string Address { get; set; } = string.Empty;
    public int Port { get; set; }
    public string Network { get; set; } = "tcp";
    public string Security { get; set; } = string.Empty;
    public string Sni { get; set; } = string.Empty;
    public string Path { get; set; } = string.Empty;
    public string Encryption { get; set; } = "none";
    public int AlterId { get; set; } // For VMess
    public string SecurityType { get; set; } = "auto"; // For VMess
}