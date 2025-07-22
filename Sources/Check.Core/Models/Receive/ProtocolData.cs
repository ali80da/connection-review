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
    public string Network { get; set; } = string.Empty;
    public string Security { get; set; } = string.Empty;
    public string Sni { get; set; } = string.Empty;
    public string Path { get; set; } = string.Empty;
    public string Encryption { get; set; } = string.Empty;
    public int AlterId { get; set; }
    public string SecurityType { get; set; } = string.Empty;
    public string Method { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public string Username { get; set; } = string.Empty;
    public string PublicKey { get; set; } = string.Empty;
    public string PrivateKey { get; set; } = string.Empty;
    public string AllowedIPs { get; set; } = string.Empty;
    public string Endpoint { get; set; } = string.Empty;
}