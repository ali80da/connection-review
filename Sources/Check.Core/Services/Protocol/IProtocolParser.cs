using System.Text;
using System.Text.Json;
using System.Web;
using Check.Core.Models.Common;
using Check.Core.Models.Receive;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Check.Core.Configuration;

namespace Check.Core.Services.Protocol;

public interface IProtocolParser
{
    bool TryParse(string link, out ConfigDetails config, ResultStatus result);
}

public abstract class BaseProtocolParser : IProtocolParser
{
    protected readonly IMemoryCache Cache;
    protected readonly ILogger Logger;
    protected readonly AppSettings AppSettings;

    protected BaseProtocolParser(IMemoryCache cache, ILogger logger, IOptions<AppSettings> appSettings)
    {
        Cache = cache ?? throw new ArgumentNullException(nameof(cache));
        Logger = logger ?? throw new ArgumentNullException(nameof(logger));
        AppSettings = appSettings?.Value ?? throw new ArgumentNullException(nameof(appSettings));
    }

    public bool TryParse(string link, out ConfigDetails config, ResultStatus result)
    {
        var cacheKey = $"ProtocolParser_{GetType().Name}_{link}";
        if (Cache.TryGetValue(cacheKey, out ConfigDetails? cachedConfig))
        {
            config = cachedConfig!;
            Logger.LogInformation("Retrieved cached {Protocol} configuration for {Link}", GetType().Name, link);
            result.AddStep("Config Parsing", $"Retrieved {GetType().Name} configuration from cache.", true);
            return true;
        }

        bool success = TryParseInternal(link, out config, result);

        if (success)
        {
            Cache.Set(cacheKey, config, TimeSpan.FromMinutes(AppSettings?.CacheTtlSeconds ?? 10));
            result.AddStep("Config Parsing", $"Successfully parsed {GetType().Name} configuration.", true);
        }

        return success;
    }

    protected abstract bool TryParseInternal(string link, out ConfigDetails config, ResultStatus result);
}

public class VlessProtocolParser : BaseProtocolParser
{
    public VlessProtocolParser(IMemoryCache cache, ILogger<VlessProtocolParser> logger, IOptions<AppSettings> appSettings)
        : base(cache, logger, appSettings)
    {
    }

    protected override bool TryParseInternal(string link, out ConfigDetails config, ResultStatus result)
    {
        config = new ConfigDetails();
        try
        {
            if (!link.StartsWith("vless://", StringComparison.OrdinalIgnoreCase))
            {
                Logger.LogWarning("Invalid VLESS link format: {Link}", link);
                result.AddStep("Config Parsing", "Link must start with 'vless://'.", false, "INVALID_FORMAT");
                return false;
            }

            var uri = new Uri(link);
            var userInfo = uri.UserInfo.Split(':');
            if (userInfo.Length == 0 || string.IsNullOrEmpty(userInfo[0]))
            {
                Logger.LogWarning("Invalid user info in VLESS link: {Link}", link);
                result.AddStep("Config Parsing", "Invalid user info in URL.", false, "INVALID_USERINFO");
                return false;
            }

            var query = HttpUtility.ParseQueryString(uri.Query);
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

            if (string.IsNullOrEmpty(config.Address))
            {
                Logger.LogWarning("Missing server address in VLESS link: {Link}", link);
                result.AddStep("Config Parsing", "Server address is missing.", false, "MISSING_ADDRESS");
                return false;
            }

            if (config.Security == "tls" && string.IsNullOrEmpty(config.Sni))
            {
                Logger.LogWarning("Missing SNI for TLS in VLESS link: {Link}", link);
                result.AddStep("Config Parsing", "SNI is required for TLS connections.", false, "MISSING_SNI");
                return false;
            }

            Logger.LogInformation("Parsed VLESS link: {Link}, Security={Security}, Port={Port}, Sni={Sni}, Encryption={Encryption}, Network={Network}",
                link, config.Security, config.Port, config.Sni, config.Encryption, config.Network);
            return true;
        }
        catch (UriFormatException ex)
        {
            Logger.LogError(ex, "Invalid URI format for VLESS link: {Link}", link);
            result.AddStep("Config Parsing", $"Invalid link format: {ex.Message}.", false, "INVALID_URI");
            return false;
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "Unexpected error parsing VLESS link: {Link}", link);
            result.AddStep("Config Parsing", $"Unexpected error: {ex.Message}.", false, "UNKNOWN_ERROR");
            return false;
        }
    }
}

public class VmessProtocolParser : BaseProtocolParser
{
    public VmessProtocolParser(IMemoryCache cache, ILogger<VmessProtocolParser> logger, IOptions<AppSettings> appSettings)
        : base(cache, logger, appSettings)
    {
    }

    protected override bool TryParseInternal(string link, out ConfigDetails config, ResultStatus result)
    {
        config = new ConfigDetails();
        try
        {
            if (!link.StartsWith("vmess://", StringComparison.OrdinalIgnoreCase))
            {
                Logger.LogWarning("Invalid VMess link format: {Link}", link);
                result.AddStep("Config Parsing", "Link must start with 'vmess://'.", false, "INVALID_FORMAT");
                return false;
            }

            var payload = link[(link.IndexOf("://", StringComparison.Ordinal) + 3)..].Trim();
            int mod4 = payload.Length % 4;
            if (mod4 > 0) payload += new string('=', 4 - mod4);
            var json = Encoding.UTF8.GetString(Convert.FromBase64String(payload));
            var vmessConfig = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(json);

            if (vmessConfig == null)
            {
                Logger.LogWarning("Invalid JSON format for VMess link: {Link}", link);
                result.AddStep("Config Parsing", "Invalid JSON format for VMess.", false, "INVALID_JSON");
                return false;
            }

            config = new ConfigDetails
            {
                Id = vmessConfig.TryGetValue("id", out var idElement) && idElement.ValueKind == JsonValueKind.String ? idElement.GetString() ?? "" : "",
                Address = vmessConfig.TryGetValue("add", out var addElement) && addElement.ValueKind == JsonValueKind.String ? addElement.GetString() ?? "" : "",
                Port = vmessConfig.TryGetValue("port", out var portElement) && portElement.ValueKind == JsonValueKind.Number ? portElement.GetInt32() : 443,
                Network = vmessConfig.TryGetValue("net", out var netElement) && netElement.ValueKind == JsonValueKind.String ? netElement.GetString()?.ToLowerInvariant() ?? "tcp" : "tcp",
                Security = vmessConfig.TryGetValue("tls", out var tlsElement) && tlsElement.ValueKind == JsonValueKind.String ? tlsElement.GetString()?.ToLowerInvariant() ?? "" : "",
                Sni = vmessConfig.TryGetValue("sni", out var sniElement) && sniElement.ValueKind == JsonValueKind.String ? sniElement.GetString() ?? "" : "",
                Path = vmessConfig.TryGetValue("path", out var pathElement) && pathElement.ValueKind == JsonValueKind.String ? pathElement.GetString() ?? "" : "",
                Encryption = vmessConfig.TryGetValue("type", out var typeElement) && typeElement.ValueKind == JsonValueKind.String ? typeElement.GetString()?.ToLowerInvariant() ?? "none" : "none",
                AlterId = vmessConfig.TryGetValue("aid", out var aidElement) && aidElement.ValueKind == JsonValueKind.Number ? aidElement.GetInt32() : 0,
                SecurityType = vmessConfig.TryGetValue("scy", out var scyElement) && scyElement.ValueKind == JsonValueKind.String ? scyElement.GetString()?.ToLowerInvariant() ?? "auto" : "auto"
            };

            if (string.IsNullOrEmpty(config.Id))
            {
                Logger.LogWarning("Missing ID in VMess link: {Link}", link);
                result.AddStep("Config Parsing", "User ID is required.", false, "MISSING_ID");
                return false;
            }

            if (string.IsNullOrEmpty(config.Address))
            {
                Logger.LogWarning("Missing server address in VMess link: {Link}", link);
                result.AddStep("Config Parsing", "Server address is missing.", false, "MISSING_ADDRESS");
                return false;
            }

            if (config.Security == "tls" && string.IsNullOrEmpty(config.Sni))
            {
                Logger.LogWarning("Missing SNI for TLS in VMess link: {Link}", link);
                result.AddStep("Config Parsing", "SNI is required for TLS connections.", false, "MISSING_SNI");
                return false;
            }

            Logger.LogInformation("Parsed VMess link: {Link}, Security={Security}, Port={Port}, Sni={Sni}, Encryption={Encryption}, Network={Network}",
                link, config.Security, config.Port, config.Sni, config.Encryption, config.Network);
            return true;
        }
        catch (FormatException ex)
        {
            Logger.LogError(ex, "Invalid Base64 format for VMess link: {Link}", link);
            result.AddStep("Config Parsing", $"Invalid Base64 format: {ex.Message}.", false, "INVALID_BASE64");
            return false;
        }
        catch (JsonException ex)
        {
            Logger.LogError(ex, "Invalid JSON format for VMess link: {Link}", link);
            result.AddStep("Config Parsing", $"Invalid JSON format: {ex.Message}.", false, "INVALID_JSON");
            return false;
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "Unexpected error parsing VMess link: {Link}", link);
            result.AddStep("Config Parsing", $"Unexpected error: {ex.Message}.", false, "UNKNOWN_ERROR");
            return false;
        }
    }
}

public class TrojanProtocolParser : BaseProtocolParser
{
    public TrojanProtocolParser(IMemoryCache cache, ILogger<TrojanProtocolParser> logger, IOptions<AppSettings> appSettings)
        : base(cache, logger, appSettings)
    {
    }

    protected override bool TryParseInternal(string link, out ConfigDetails config, ResultStatus result)
    {
        config = new ConfigDetails();
        try
        {
            if (!link.StartsWith("trojan://", StringComparison.OrdinalIgnoreCase))
            {
                Logger.LogWarning("Invalid Trojan link format: {Link}", link);
                result.AddStep("Config Parsing", "Link must start with 'trojan://'.", false, "INVALID_FORMAT");
                return false;
            }

            var uri = new Uri(link);
            var query = HttpUtility.ParseQueryString(uri.Query);
            var password = uri.UserInfo;

            if (string.IsNullOrEmpty(password))
            {
                Logger.LogWarning("Missing password in Trojan link: {Link}", link);
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
                Path = query["path"] ?? "",
                Encryption = "none",
                AlterId = 0,
                SecurityType = "none"
            };

            if (string.IsNullOrEmpty(config.Address))
            {
                Logger.LogWarning("Missing server address in Trojan link: {Link}", link);
                result.AddStep("Config Parsing", "Server address is missing.", false, "MISSING_ADDRESS");
                return false;
            }

            if (config.Security == "tls" && string.IsNullOrEmpty(config.Sni))
            {
                Logger.LogWarning("Missing SNI for TLS in Trojan link: {Link}", link);
                result.AddStep("Config Parsing", "SNI is required for TLS connections.", false, "MISSING_SNI");
                return false;
            }

            Logger.LogInformation("Parsed Trojan link: {Link}, Security={Security}, Port={Port}, Sni={Sni}, Encryption={Encryption}, Network={Network}",
                link, config.Security, config.Port, config.Sni, config.Encryption, config.Network);
            return true;
        }
        catch (UriFormatException ex)
        {
            Logger.LogError(ex, "Invalid URI format for Trojan link: {Link}", link);
            result.AddStep("Config Parsing", $"Invalid link format: {ex.Message}.", false, "INVALID_URI");
            return false;
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "Unexpected error parsing Trojan link: {Link}", link);
            result.AddStep("Config Parsing", $"Unexpected error: {ex.Message}.", false, "UNKNOWN_ERROR");
            return false;
        }
    }
}

public class ShadowsocksProtocolParser : BaseProtocolParser
{
    public ShadowsocksProtocolParser(IMemoryCache cache, ILogger<ShadowsocksProtocolParser> logger, IOptions<AppSettings> appSettings)
        : base(cache, logger, appSettings)
    {
    }

    protected override bool TryParseInternal(string link, out ConfigDetails config, ResultStatus result)
    {
        config = new ConfigDetails();
        try
        {
            if (!link.StartsWith("ss://", StringComparison.OrdinalIgnoreCase))
            {
                Logger.LogWarning("Invalid Shadowsocks link format: {Link}", link);
                result.AddStep("Config Parsing", "Link must start with 'ss://'.", false, "INVALID_FORMAT");
                return false;
            }

            var uri = new Uri(link);
            var query = HttpUtility.ParseQueryString(uri.Query);
            var userInfo = uri.UserInfo;

            if (string.IsNullOrEmpty(userInfo))
            {
                Logger.LogWarning("Missing user info in Shadowsocks link: {Link}", link);
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
                    Logger.LogWarning("Invalid method:password format in Shadowsocks link: {Link}", link);
                    result.AddStep("Config Parsing", "Invalid method:password format.", false, "INVALID_USERINFO");
                    return false;
                }
                method = parts[0];
                password = parts[1];
            }
            catch (FormatException ex)
            {
                Logger.LogError(ex, "Invalid Base64 encoding in Shadowsocks link: {Link}", link);
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
                Path = query["path"] ?? "",
                Encryption = method,
                AlterId = 0,
                SecurityType = "none"
            };

            if (string.IsNullOrEmpty(config.Address))
            {
                Logger.LogWarning("Missing server address in Shadowsocks link: {Link}", link);
                result.AddStep("Config Parsing", "Server address is missing.", false, "MISSING_ADDRESS");
                return false;
            }

            if (string.IsNullOrEmpty(config.Method) || string.IsNullOrEmpty(config.Password))
            {
                Logger.LogWarning("Missing method or password in Shadowsocks link: {Link}", link);
                result.AddStep("Config Parsing", "Method or password is missing.", false, "MISSING_CREDENTIALS");
                return false;
            }

            Logger.LogInformation("Parsed Shadowsocks link: {Link}, Method={Method}, Security={Security}, Port={Port}, Sni={Sni}, Network={Network}",
                link, config.Method, config.Security, config.Port, config.Sni, config.Network);
            return true;
        }
        catch (UriFormatException ex)
        {
            Logger.LogError(ex, "Invalid URI format for Shadowsocks link: {Link}", link);
            result.AddStep("Config Parsing", $"Invalid link format: {ex.Message}.", false, "INVALID_URI");
            return false;
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "Unexpected error parsing Shadowsocks link: {Link}", link);
            result.AddStep("Config Parsing", $"Unexpected error: {ex.Message}.", false, "UNKNOWN_ERROR");
            return false;
        }
    }
}

public class Http2ProtocolParser : BaseProtocolParser
{
    public Http2ProtocolParser(IMemoryCache cache, ILogger<Http2ProtocolParser> logger, IOptions<AppSettings> appSettings)
        : base(cache, logger, appSettings)
    {
    }

    protected override bool TryParseInternal(string link, out ConfigDetails config, ResultStatus result)
    {
        config = new ConfigDetails();
        try
        {
            if (!link.StartsWith("http2://", StringComparison.OrdinalIgnoreCase))
            {
                Logger.LogWarning("Invalid HTTP/2 link format: {Link}", link);
                result.AddStep("Config Parsing", "Link must start with 'http2://'.", false, "INVALID_FORMAT");
                return false;
            }

            var uri = new Uri(link);
            var query = HttpUtility.ParseQueryString(uri.Query);
            var userInfo = uri.UserInfo.Split(':');
            if (userInfo.Length < 2 || string.IsNullOrEmpty(userInfo[0]) || string.IsNullOrEmpty(userInfo[1]))
            {
                Logger.LogWarning("Missing username or password in HTTP/2 link: {Link}", link);
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
                Path = query["path"] ?? "",
                Encryption = "none",
                AlterId = 0,
                SecurityType = "none"
            };

            if (string.IsNullOrEmpty(config.Address))
            {
                Logger.LogWarning("Missing server address in HTTP/2 link: {Link}", link);
                result.AddStep("Config Parsing", "Server address is missing.", false, "MISSING_ADDRESS");
                return false;
            }

            if (config.Security == "tls" && string.IsNullOrEmpty(config.Sni))
            {
                Logger.LogWarning("Missing SNI for TLS in HTTP/2 link: {Link}", link);
                result.AddStep("Config Parsing", "SNI is required for TLS connections.", false, "MISSING_SNI");
                return false;
            }

            Logger.LogInformation("Parsed HTTP/2 link: {Link}, Security={Security}, Port={Port}, Sni={Sni}, Encryption={Encryption}, Network={Network}",
                link, config.Security, config.Port, config.Sni, config.Encryption, config.Network);
            return true;
        }
        catch (UriFormatException ex)
        {
            Logger.LogError(ex, "Invalid URI format for HTTP/2 link: {Link}", link);
            result.AddStep("Config Parsing", $"Invalid link format: {ex.Message}.", false, "INVALID_URI");
            return false;
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "Unexpected error parsing HTTP/2 link: {Link}", link);
            result.AddStep("Config Parsing", $"Unexpected error: {ex.Message}.", false, "UNKNOWN_ERROR");
            return false;
        }
    }
}

public class Socks5ProtocolParser : BaseProtocolParser
{
    public Socks5ProtocolParser(IMemoryCache cache, ILogger<Socks5ProtocolParser> logger, IOptions<AppSettings> appSettings)
        : base(cache, logger, appSettings)
    {
    }

    protected override bool TryParseInternal(string link, out ConfigDetails config, ResultStatus result)
    {
        config = new ConfigDetails();
        try
        {
            if (!link.StartsWith("socks5://", StringComparison.OrdinalIgnoreCase))
            {
                Logger.LogWarning("Invalid SOCKS5 link format: {Link}", link);
                result.AddStep("Config Parsing", "Link must start with 'socks5://'.", false, "INVALID_FORMAT");
                return false;
            }

            var uri = new Uri(link);
            var query = HttpUtility.ParseQueryString(uri.Query);
            var userInfo = uri.UserInfo.Split(':');
            var username = userInfo.Length > 0 ? userInfo[0] : "";
            var password = userInfo.Length > 1 ? userInfo[1] : "";

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
                Path = query["path"] ?? "",
                Encryption = "none",
                AlterId = 0,
                SecurityType = "none"
            };

            if (string.IsNullOrEmpty(config.Address))
            {
                Logger.LogWarning("Missing server address in SOCKS5 link: {Link}", link);
                result.AddStep("Config Parsing", "Server address is missing.", false, "MISSING_ADDRESS");
                return false;
            }

            if (config.Security == "tls" && string.IsNullOrEmpty(config.Sni))
            {
                Logger.LogWarning("Missing SNI for TLS in SOCKS5 link: {Link}", link);
                result.AddStep("Config Parsing", "SNI is required for TLS connections.", false, "MISSING_SNI");
                return false;
            }

            Logger.LogInformation("Parsed SOCKS5 link: {Link}, Security={Security}, Port={Port}, Sni={Sni}, Encryption={Encryption}, Network={Network}",
                link, config.Security, config.Port, config.Sni, config.Encryption, config.Network);
            return true;
        }
        catch (UriFormatException ex)
        {
            Logger.LogError(ex, "Invalid URI format for SOCKS5 link: {Link}", link);
            result.AddStep("Config Parsing", $"Invalid link format: {ex.Message}.", false, "INVALID_URI");
            return false;
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "Unexpected error parsing SOCKS5 link: {Link}", link);
            result.AddStep("Config Parsing", $"Unexpected error: {ex.Message}.", false, "UNKNOWN_ERROR");
            return false;
        }
    }
}

public class WireguardProtocolParser : BaseProtocolParser
{
    public WireguardProtocolParser(IMemoryCache cache, ILogger<WireguardProtocolParser> logger, IOptions<AppSettings> appSettings)
        : base(cache, logger, appSettings)
    {
    }

    protected override bool TryParseInternal(string link, out ConfigDetails config, ResultStatus result)
    {
        config = new ConfigDetails();
        try
        {
            if (!link.StartsWith("wg://", StringComparison.OrdinalIgnoreCase))
            {
                Logger.LogWarning("Invalid WireGuard link format: {Link}", link);
                result.AddStep("Config Parsing", "Link must start with 'wg://'.", false, "INVALID_FORMAT");
                return false;
            }

            var uri = new Uri(link);
            var query = HttpUtility.ParseQueryString(uri.Query);
            var publicKey = uri.UserInfo;

            if (string.IsNullOrEmpty(publicKey))
            {
                Logger.LogWarning("Missing public key in WireGuard link: {Link}", link);
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
                PrivateKey = privateKey ?? "",
                AllowedIPs = allowedIPs,
                Endpoint = endpoint,
                Address = uri.Host,
                Port = uri.Port > 0 ? uri.Port : 51820,
                Network = "udp",
                Security = "none",
                Sni = query["sni"] ?? "",
                Path = "",
                Encryption = "wireguard",
                AlterId = 0,
                SecurityType = "none"
            };

            if (string.IsNullOrEmpty(config.Address))
            {
                Logger.LogWarning("Missing server address in WireGuard link: {Link}", link);
                result.AddStep("Config Parsing", "Server address is missing.", false, "MISSING_ADDRESS");
                return false;
            }

            if (string.IsNullOrEmpty(config.PrivateKey))
            {
                Logger.LogWarning("Missing private key in WireGuard link: {Link}", link);
                result.AddStep("Config Parsing", "Private key is required.", false, "MISSING_PRIVATE_KEY");
                return false;
            }

            // Validate public and private key formats (basic check for length)
            if (publicKey.Length < 32 || privateKey!.Length < 32)
            {
                Logger.LogWarning("Invalid key format in WireGuard link: {Link}", link);
                result.AddStep("Config Parsing", "Invalid public or private key format.", false, "INVALID_KEY_FORMAT");
                return false;
            }

            Logger.LogInformation("Parsed WireGuard link: {Link}, PublicKey={PublicKey}, Port={Port}, Endpoint={Endpoint}, Network={Network}",
                link, config.PublicKey, config.Port, config.Endpoint, config.Network);
            return true;
        }
        catch (UriFormatException ex)
        {
            Logger.LogError(ex, "Invalid URI format for WireGuard link: {Link}", link);
            result.AddStep("Config Parsing", $"Invalid link format: {ex.Message}.", false, "INVALID_URI");
            return false;
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "Unexpected error parsing WireGuard link: {Link}", link);
            result.AddStep("Config Parsing", $"Unexpected error: {ex.Message}.", false, "UNKNOWN_ERROR");
            return false;
        }
    }
}

public class HysteriaProtocolParser : BaseProtocolParser
{
    public HysteriaProtocolParser(IMemoryCache cache, ILogger<HysteriaProtocolParser> logger, IOptions<AppSettings> appSettings)
        : base(cache, logger, appSettings)
    {
    }

    protected override bool TryParseInternal(string link, out ConfigDetails config, ResultStatus result)
    {
        config = new ConfigDetails();
        try
        {
            if (!link.StartsWith("hysteria://", StringComparison.OrdinalIgnoreCase))
            {
                Logger.LogWarning("Invalid Hysteria link format: {Link}", link);
                result.AddStep("Config Parsing", "Link must start with 'hysteria://'.", false, "INVALID_FORMAT");
                return false;
            }

            var uri = new Uri(link);
            var query = HttpUtility.ParseQueryString(uri.Query);
            var auth = uri.UserInfo;

            if (string.IsNullOrEmpty(auth))
            {
                Logger.LogWarning("Missing authentication key in Hysteria link: {Link}", link);
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
                Path = query["path"] ?? "",
                Encryption = "none",
                AlterId = 0,
                SecurityType = "none",
                Method = query["obfs"]?.ToLowerInvariant() ?? "none"
            };

            if (string.IsNullOrEmpty(config.Address))
            {
                Logger.LogWarning("Missing server address in Hysteria link: {Link}", link);
                result.AddStep("Config Parsing", "Server address is missing.", false, "MISSING_ADDRESS");
                return false;
            }

            if (config.Security == "tls" && string.IsNullOrEmpty(config.Sni))
            {
                Logger.LogWarning("Missing SNI for TLS in Hysteria link: {Link}", link);
                result.AddStep("Config Parsing", "SNI is required for TLS connections.", false, "MISSING_SNI");
                return false;
            }

            Logger.LogInformation("Parsed Hysteria link: {Link}, Security={Security}, Port={Port}, Sni={Sni}, Network={Network}, Obfs={Method}",
                link, config.Security, config.Port, config.Sni, config.Network, config.Method);
            return true;
        }
        catch (UriFormatException ex)
        {
            Logger.LogError(ex, "Invalid URI format for Hysteria link: {Link}", link);
            result.AddStep("Config Parsing", $"Invalid link format: {ex.Message}.", false, "INVALID_URI");
            return false;
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "Unexpected error parsing Hysteria link: {Link}", link);
            result.AddStep("Config Parsing", $"Unexpected error: {ex.Message}.", false, "UNKNOWN_ERROR");
            return false;
        }
    }
}