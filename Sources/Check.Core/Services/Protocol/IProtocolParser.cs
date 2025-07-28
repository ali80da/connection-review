using System.Text;
using System.Text.Json;
using System.Web;
using Check.Core.Models.Common;
using Check.Core.Models.Receive;
using Microsoft.Extensions.Caching.Memory;

namespace Check.Core.Services.Protocol;

public interface IProtocolParser
{
    bool TryParse(string link, out ConfigDetails config, ResultStatus result);
}

#region Protocol Parser

public abstract class BaseProtocolParser : IProtocolParser
{
    private readonly IMemoryCache Cache;

    protected BaseProtocolParser(IMemoryCache Cache)
    {
        this.Cache = Cache ?? throw new ArgumentNullException(nameof(Cache));
    }

    public bool TryParse(string link, out ConfigDetails config, ResultStatus result)
    {
        var cacheKey = $"ProtocolParser_{GetType().Name}_{link}";
        if (Cache.TryGetValue(cacheKey, out ConfigDetails? cachedConfig))
        {
            config = cachedConfig!;
            result.AddStep("Config Parsing", $"Retrieved {GetType().Name} configuration from cache.", true);
            return true;
        }

        bool success = TryParseInternal(link, out config, result);

        if (success)
        {
            Cache.Set(cacheKey, config, TimeSpan.FromMinutes(10));
        }

        return success;
    }

    protected abstract bool TryParseInternal(string link, out ConfigDetails config, ResultStatus result);
}


/// <summary>
/// Parses Vless protocol links into configuration details.
/// </summary>
public class VlessProtocolParser : BaseProtocolParser
{
    public VlessProtocolParser(IMemoryCache cache) : base(cache)
    {
    }

    protected override bool TryParseInternal(string link, out ConfigDetails config, ResultStatus result)
    {
        config = new ConfigDetails();
        try
        {
            var uri = new Uri(link);
            var query = HttpUtility.ParseQueryString(uri.Query);
            var userInfo = uri.UserInfo.Split(':');
            if (userInfo.Length == 0 || string.IsNullOrEmpty(userInfo[0]))
            {
                result.AddStep("Config Parsing", "Invalid user info in URL.", false);
                return false;
            }

            config = new ConfigDetails
            {
                Id = userInfo[0],
                Address = uri.Host,
                Port = uri.Port > 0 ? uri.Port : 443,
                Network = query["type"]?.ToLowerInvariant() ?? "tcp",
                Security = query["security"]?.ToLowerInvariant() ?? "",
                Sni = query["sni"] ?? query["host"] ?? uri.Host,
                Path = query["path"] ?? "",
                Encryption = query["encryption"]?.ToLowerInvariant() ?? "none",
                AlterId = 0,
                SecurityType = "none"
            };

            result.AddStep("Config Parsing", "Successfully parsed VLESS configuration.", true);
            return true;
        }
        catch (Exception ex)
        {
            result.AddStep("Config Parsing", $"Failed to parse VLESS configuration: {ex.Message}", false);
            return false;
        }
    }
}


/// <summary>
/// Parses Vmess protocol links into configuration details.
/// </summary>
public class VmessProtocolParser : BaseProtocolParser
{
    public VmessProtocolParser(IMemoryCache cache) : base(cache)
    {
    }

    protected override bool TryParseInternal(string link, out ConfigDetails config, ResultStatus result)
    {
        config = new ConfigDetails();
        try
        {
            var uri = new Uri(link);
            var query = HttpUtility.ParseQueryString(uri.Query);
            var userInfo = uri.UserInfo.Split(':');
            if (userInfo.Length == 0 || string.IsNullOrEmpty(userInfo[0]))
            {
                result.AddStep("Config Parsing", "Invalid user info in URL.", false);
                return false;
            }

            config = new ConfigDetails
            {
                Id = userInfo[0],
                Address = uri.Host,
                Port = uri.Port > 0 ? uri.Port : 443,
                Network = query["type"]?.ToLowerInvariant() ?? "tcp",
                Security = query["security"]?.ToLowerInvariant() ?? "",
                Sni = query["sni"] ?? query["host"] ?? uri.Host,
                Path = query["path"] ?? "",
                Encryption = query["encryption"]?.ToLowerInvariant() ?? "none",
                AlterId = query["aid"] != null && int.TryParse(query["aid"], out var aid) ? aid : 0,
                SecurityType = query["scy"]?.ToLowerInvariant() ?? "auto"
            };

            try
            {
                var payload = link[(link.IndexOf("://", StringComparison.Ordinal) + 3)..].Trim();
                int mod4 = payload.Length % 4;
                if (mod4 > 0) payload += new string('=', 4 - mod4);
                var json = Encoding.UTF8.GetString(Convert.FromBase64String(payload));
                var vmessConfig = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(json);

                if (vmessConfig != null)
                {
                    if (vmessConfig.TryGetValue("id", out var idElement) && idElement.ValueKind == JsonValueKind.String)
                    {
                        config.Id = idElement.GetString() ?? config.Id;
                    }
                    if (vmessConfig.TryGetValue("add", out var addElement) && addElement.ValueKind == JsonValueKind.String)
                    {
                        config.Address = addElement.GetString() ?? config.Address;
                    }
                    if (vmessConfig.TryGetValue("port", out var portElement) && portElement.ValueKind == JsonValueKind.Number)
                    {
                        config.Port = portElement.GetInt32();
                    }
                    if (vmessConfig.TryGetValue("net", out var netElement) && netElement.ValueKind == JsonValueKind.String)
                    {
                        config.Network = netElement.GetString()?.ToLowerInvariant() ?? config.Network;
                    }
                    if (vmessConfig.TryGetValue("tls", out var tlsElement) && tlsElement.ValueKind == JsonValueKind.String)
                    {
                        config.Security = tlsElement.GetString()?.ToLowerInvariant() ?? config.Security;
                    }
                    if (vmessConfig.TryGetValue("aid", out var aidElement) && aidElement.ValueKind == JsonValueKind.Number)
                    {
                        config.AlterId = aidElement.GetInt32();
                    }
                    if (vmessConfig.TryGetValue("scy", out var scyElement) && scyElement.ValueKind == JsonValueKind.String)
                    {
                        config.SecurityType = scyElement.GetString()?.ToLowerInvariant() ?? config.SecurityType;
                    }
                }
            }
            catch (FormatException ex)
            {
                result.AddStep("Config Parsing", $"Invalid Base64 format for VMess: {ex.Message}", false);
                return false;
            }
            catch (JsonException ex)
            {
                result.AddStep("Config Parsing", $"Invalid JSON format for VMess: {ex.Message}", false);
                return false;
            }

            result.AddStep("Config Parsing", "Successfully parsed VMess configuration.", true);
            return true;
        }
        catch (Exception ex)
        {
            result.AddStep("Config Parsing", $"Failed to parse VMess configuration: {ex.Message}", false);
            return false;
        }
    }
}


/// <summary>
/// Parses Trojan protocol links into configuration details.
/// </summary>
public class TrojanProtocolParser : BaseProtocolParser
{
    public TrojanProtocolParser(IMemoryCache cache) : base(cache)
    {
    }

    protected override bool TryParseInternal(string link, out ConfigDetails config, ResultStatus result)
    {
        config = new ConfigDetails();
        if (!link.StartsWith("trojan://", StringComparison.OrdinalIgnoreCase))
        {
            result.AddStep("Config Parsing", "Link must start with 'trojan://'.", false, "INVALID_FORMAT");
            return false;
        }

        try
        {
            var uri = new Uri(link);
            var query = HttpUtility.ParseQueryString(uri.Query);
            var password = uri.UserInfo;

            if (string.IsNullOrEmpty(password))
            {
                result.AddStep("Config Parsing", "Password is required in the link.", false, "MISSING_PASSWORD");
                return false;
            }

            config = new ConfigDetails
            {
                Id = password,
                Address = uri.Host,
                Port = uri.Port > 0 ? uri.Port : 443,
                Network = query["type"]?.ToLowerInvariant() ?? "tcp",
                Security = query["security"]?.ToLowerInvariant() ?? "tls",
                Sni = query["sni"] ?? query["host"] ?? uri.Host,
                Path = query["path"] ?? string.Empty,
                Encryption = "none",
                AlterId = 0,
                SecurityType = "none"
            };

            if (string.IsNullOrEmpty(config.Address))
            {
                result.AddStep("Config Parsing", "Server address is missing.", false, "MISSING_ADDRESS");
                return false;
            }

            if (config.Security == "tls" && string.IsNullOrEmpty(config.Sni))
            {
                result.AddStep("Config Parsing", "SNI is required for TLS connections.", false, "MISSING_SNI");
                return false;
            }

            result.AddStep("Config Parsing", "Successfully parsed Trojan configuration.", true);
            return true;
        }
        catch (UriFormatException ex)
        {
            result.AddStep("Config Parsing", $"Invalid link format: {ex.Message}.", false, "INVALID_URI");
            return false;
        }
        catch (Exception ex)
        {
            result.AddStep("Config Parsing", $"Unexpected error: {ex.Message}.", false, "UNKNOWN_ERROR");
            return false;
        }
    }
}


/// <summary>
/// Parses Shadowsocks protocol links into configuration details.
/// </summary>
public class ShadowsocksProtocolParser : BaseProtocolParser
{
    public ShadowsocksProtocolParser(IMemoryCache cache) : base(cache)
    {
    }

    protected override bool TryParseInternal(string link, out ConfigDetails config, ResultStatus result)
    {
        config = new ConfigDetails();
        if (!link.StartsWith("ss://", StringComparison.OrdinalIgnoreCase))
        {
            result.AddStep("Config Parsing", "Link must start with 'ss://'.", false, "INVALID_FORMAT");
            return false;
        }

        try
        {
            var uri = new Uri(link);
            var query = HttpUtility.ParseQueryString(uri.Query);
            var userInfo = uri.UserInfo;

            if (string.IsNullOrEmpty(userInfo))
            {
                result.AddStep("Config Parsing", "Method and password are required.", false, "MISSING_USERINFO");
                return false;
            }

            string method, password;
            try
            {
                var decodedUserInfo = Encoding.UTF8.GetString(Convert.FromBase64String(userInfo.PadRight((userInfo.Length + 3) & ~3, '=')));
                var parts = decodedUserInfo.Split(':');
                if (parts.Length != 2 || string.IsNullOrEmpty(parts[0]) || string.IsNullOrEmpty(parts[1]))
                {
                    result.AddStep("Config Parsing", "Invalid method:password format.", false, "INVALID_USERINFO");
                    return false;
                }
                method = parts[0];
                password = parts[1];
            }
            catch (FormatException ex)
            {
                result.AddStep("Config Parsing", $"Invalid Base64 encoding: {ex.Message}.", false, "INVALID_BASE64");
                return false;
            }

            config = new ConfigDetails
            {
                Id = password,
                Password = password,
                Method = method.ToLowerInvariant(),
                Address = uri.Host,
                Port = uri.Port > 0 ? uri.Port : 8388,
                Network = "tcp",
                Security = query["security"]?.ToLowerInvariant() ?? "none",
                Sni = query["sni"] ?? query["host"] ?? uri.Host,
                Path = query["path"] ?? string.Empty,
                Encryption = method,
                AlterId = 0,
                SecurityType = "none"
            };

            if (string.IsNullOrEmpty(config.Address))
            {
                result.AddStep("Config Parsing", "Server address is missing.", false, "MISSING_ADDRESS");
                return false;
            }

            if (string.IsNullOrEmpty(config.Method) || string.IsNullOrEmpty(config.Password))
            {
                result.AddStep("Config Parsing", "Method or password is missing.", false, "MISSING_CREDENTIALS");
                return false;
            }

            result.AddStep("Config Parsing", "Successfully parsed Shadowsocks configuration.", true);
            return true;
        }
        catch (UriFormatException ex)
        {
            result.AddStep("Config Parsing", $"Invalid link format: {ex.Message}.", false, "INVALID_URI");
            return false;
        }
        catch (Exception ex)
        {
            result.AddStep("Config Parsing", $"Unexpected error: {ex.Message}.", false, "UNKNOWN_ERROR");
            return false;
        }
    }
}


/// <summary>
/// Parses HTTP/2 protocol links into configuration details.
/// </summary>
public class Http2ProtocolParser : BaseProtocolParser
{
    public Http2ProtocolParser(IMemoryCache cache) : base(cache)
    {
    }

    protected override bool TryParseInternal(string link, out ConfigDetails config, ResultStatus result)
    {
        config = new ConfigDetails();
        if (!link.StartsWith("http2://", StringComparison.OrdinalIgnoreCase))
        {
            result.AddStep("Config Parsing", "Link must start with 'http2://'.", false, "INVALID_FORMAT");
            return false;
        }

        try
        {
            var uri = new Uri(link);
            var query = HttpUtility.ParseQueryString(uri.Query);
            var userInfo = uri.UserInfo.Split(':');
            if (userInfo.Length < 2 || string.IsNullOrEmpty(userInfo[0]) || string.IsNullOrEmpty(userInfo[1]))
            {
                result.AddStep("Config Parsing", "Username and password are required.", false, "MISSING_CREDENTIALS");
                return false;
            }

            config = new ConfigDetails
            {
                Id = userInfo[0],
                Username = userInfo[0],
                Password = userInfo[1],
                Address = uri.Host,
                Port = uri.Port > 0 ? uri.Port : 443,
                Network = "h2",
                Security = query["security"]?.ToLowerInvariant() ?? "tls",
                Sni = query["sni"] ?? query["host"] ?? uri.Host,
                Path = query["path"] ?? string.Empty,
                Encryption = "none",
                AlterId = 0,
                SecurityType = "none"
            };

            if (string.IsNullOrEmpty(config.Address))
            {
                result.AddStep("Config Parsing", "Server address is missing.", false, "MISSING_ADDRESS");
                return false;
            }

            if (config.Security == "tls" && string.IsNullOrEmpty(config.Sni))
            {
                result.AddStep("Config Parsing", "SNI is required for TLS connections.", false, "MISSING_SNI");
                return false;
            }

            result.AddStep("Config Parsing", "Successfully parsed HTTP/2 configuration.", true);
            return true;
        }
        catch (UriFormatException ex)
        {
            result.AddStep("Config Parsing", $"Invalid link format: {ex.Message}.", false, "INVALID_URI");
            return false;
        }
        catch (Exception ex)
        {
            result.AddStep("Config Parsing", $"Unexpected error: {ex.Message}.", false, "UNKNOWN_ERROR");
            return false;
        }
    }
}


/// <summary>
/// Parses SOCKS5 protocol links into configuration details.
/// </summary>
public class Socks5ProtocolParser : BaseProtocolParser
{
    public Socks5ProtocolParser(IMemoryCache cache) : base(cache)
    {
    }

    protected override bool TryParseInternal(string link, out ConfigDetails config, ResultStatus result)
    {
        config = new ConfigDetails();
        if (!link.StartsWith("socks5://", StringComparison.OrdinalIgnoreCase))
        {
            result.AddStep("Config Parsing", "Link must start with 'socks5://'.", false, "INVALID_FORMAT");
            return false;
        }

        try
        {
            var uri = new Uri(link);
            var query = HttpUtility.ParseQueryString(uri.Query);
            var userInfo = uri.UserInfo.Split(':');
            var username = userInfo.Length > 0 ? userInfo[0] : string.Empty;
            var password = userInfo.Length > 1 ? userInfo[1] : string.Empty;

            config = new ConfigDetails
            {
                Id = username,
                Username = username,
                Password = password,
                Address = uri.Host,
                Port = uri.Port > 0 ? uri.Port : 1080,
                Network = "tcp",
                Security = query["security"]?.ToLowerInvariant() ?? "none",
                Sni = query["sni"] ?? query["host"] ?? uri.Host,
                Path = query["path"] ?? string.Empty,
                Encryption = "none",
                AlterId = 0,
                SecurityType = "none"
            };

            if (string.IsNullOrEmpty(config.Address))
            {
                result.AddStep("Config Parsing", "Server address is missing.", false, "MISSING_ADDRESS");
                return false;
            }

            if (config.Security == "tls" && string.IsNullOrEmpty(config.Sni))
            {
                result.AddStep("Config Parsing", "SNI is required for TLS connections.", false, "MISSING_SNI");
                return false;
            }

            result.AddStep("Config Parsing", "Successfully parsed SOCKS5 configuration.", true);
            return true;
        }
        catch (UriFormatException ex)
        {
            result.AddStep("Config Parsing", $"Invalid link format: {ex.Message}.", false, "INVALID_URI");
            return false;
        }
        catch (Exception ex)
        {
            result.AddStep("Config Parsing", $"Unexpected error: {ex.Message}.", false, "UNKNOWN_ERROR");
            return false;
        }
    }
}


/// <summary>
/// Parses WireGuard protocol links into configuration details.
/// </summary>
public class WireguardProtocolParser : BaseProtocolParser
{
    public WireguardProtocolParser(IMemoryCache cache) : base(cache)
    {
    }

    protected override bool TryParseInternal(string link, out ConfigDetails config, ResultStatus result)
    {
        config = new ConfigDetails();
        if (!link.StartsWith("wg://", StringComparison.OrdinalIgnoreCase))
        {
            result.AddStep("Config Parsing", "Link must start with 'wg://'.", false, "INVALID_FORMAT");
            return false;
        }

        try
        {
            var uri = new Uri(link);
            var query = HttpUtility.ParseQueryString(uri.Query);
            var publicKey = uri.UserInfo;

            if (string.IsNullOrEmpty(publicKey))
            {
                result.AddStep("Config Parsing", "Public key is required.", false, "MISSING_PUBLIC_KEY");
                return false;
            }

            var privateKey = query["privateKey"];
            var allowedIPs = query["allowedIPs"] ?? "0.0.0.0/0,::/0";
            var endpoint = query["endpoint"] ?? uri.Host;

            config = new ConfigDetails
            {
                Id = publicKey,
                PublicKey = publicKey,
                PrivateKey = privateKey ?? string.Empty,
                AllowedIPs = allowedIPs,
                Endpoint = endpoint,
                Address = uri.Host,
                Port = uri.Port > 0 ? uri.Port : 51820,
                Network = "udp",
                Security = "none",
                Sni = query["sni"] ?? string.Empty,
                Path = string.Empty,
                Encryption = "wireguard",
                AlterId = 0,
                SecurityType = "none"
            };

            if (string.IsNullOrEmpty(config.Address))
            {
                result.AddStep("Config Parsing", "Server address is missing.", false, "MISSING_ADDRESS");
                return false;
            }

            if (string.IsNullOrEmpty(config.PrivateKey))
            {
                result.AddStep("Config Parsing", "Private key is required.", false, "MISSING_PRIVATE_KEY");
                return false;
            }

            result.AddStep("Config Parsing", "Successfully parsed WireGuard configuration.", true);
            return true;
        }
        catch (UriFormatException ex)
        {
            result.AddStep("Config Parsing", $"Invalid link format: {ex.Message}.", false, "INVALID_URI");
            return false;
        }
        catch (Exception ex)
        {
            result.AddStep("Config Parsing", $"Unexpected error: {ex.Message}.", false, "UNKNOWN_ERROR");
            return false;
        }
    }
}


/// <summary>
/// Parses Hysteria protocol links into configuration details.
/// </summary>
public class HysteriaProtocolParser : BaseProtocolParser
{
    public HysteriaProtocolParser(IMemoryCache cache) : base(cache)
    {
    }

    protected override bool TryParseInternal(string link, out ConfigDetails config, ResultStatus result)
    {
        config = new ConfigDetails();
        if (!link.StartsWith("hysteria://", StringComparison.OrdinalIgnoreCase))
        {
            result.AddStep("Config Parsing", "Link must start with 'hysteria://'.", false, "INVALID_FORMAT");
            return false;
        }

        try
        {
            var uri = new Uri(link);
            var query = HttpUtility.ParseQueryString(uri.Query);
            var auth = uri.UserInfo;

            if (string.IsNullOrEmpty(auth))
            {
                result.AddStep("Config Parsing", "Authentication key is required.", false, "MISSING_AUTH");
                return false;
            }

            config = new ConfigDetails
            {
                Id = auth,
                Address = uri.Host,
                Port = uri.Port > 0 ? uri.Port : 443,
                Network = query["protocol"]?.ToLowerInvariant() ?? "udp",
                Security = query["security"]?.ToLowerInvariant() ?? "tls",
                Sni = query["sni"] ?? query["host"] ?? uri.Host,
                Path = query["path"] ?? string.Empty,
                Encryption = "none",
                AlterId = 0,
                SecurityType = "none",
                Method = query["obfs"] ?? "none" // Hysteria-specific obfuscation
            };

            if (string.IsNullOrEmpty(config.Address))
            {
                result.AddStep("Config Parsing", "Server address is missing.", false, "MISSING_ADDRESS");
                return false;
            }

            if (config.Security == "tls" && string.IsNullOrEmpty(config.Sni))
            {
                result.AddStep("Config Parsing", "SNI is required for TLS connections.", false, "MISSING_SNI");
                return false;
            }

            result.AddStep("Config Parsing", "Successfully parsed Hysteria configuration.", true);
            return true;
        }
        catch (UriFormatException ex)
        {
            result.AddStep("Config Parsing", $"Invalid link format: {ex.Message}.", false, "INVALID_URI");
            return false;
        }
        catch (Exception ex)
        {
            result.AddStep("Config Parsing", $"Unexpected error: {ex.Message}.", false, "UNKNOWN_ERROR");
            return false;
        }
    }
}





#endregion

