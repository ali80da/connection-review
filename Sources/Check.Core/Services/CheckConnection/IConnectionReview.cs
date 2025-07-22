using System;
using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Net;
using System.Net.Http;
using Check.Core.Extensions.Bootst;
using Check.Core.Models.Common;
using Check.Core.Models.Receive;
using System.Web;

namespace Check.Core.Services.CheckConnection;

#region Review

public interface IConnectionReview
{
    Task<ResultStatus> AnalyzeAsync(ProtocolData data);
}

public class ConnectionReview : IConnectionReview
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly     Dictionary<string, IProtocolParser> _parsers;

    public ConnectionReview(IHttpClientFactory httpClientFactory)
    {
        _httpClientFactory = httpClientFactory ?? throw new ArgumentNullException(nameof(httpClientFactory));
        _parsers = new Dictionary<string, IProtocolParser>
        {
            { "vless", new VlessProtocolParser() },
            { "vmess", new VmessProtocolParser() },
            { "trojan", new TrojanProtocolParser() },
            { "ss", new ShadowsocksProtocolParser() },
            { "http2", new Http2ProtocolParser() }
        };
    }

    public async Task<ResultStatus> AnalyzeAsync(ProtocolData data)
    {
        var result = new ResultStatus();

        // Step 1: Validate input
        result.AddStep("Input Validation", "Checking if the provided link is valid.");
        if (string.IsNullOrWhiteSpace(data.Link))
        {
            result.AddStep("Input Validation", "Link cannot be empty.", false);
            return result;
        }

        if (!data.Link.Contains("://"))
        {
            result.AddStep("Link Format Check", "Invalid link format.", false);
            return result;
        }

        // Step 2: Extract protocol
        var protocol = data.Protocol?.ToLowerInvariant() ?? ExtractProtocol(data.Link);
        result.AddStep("Protocol Extraction", $"Determined protocol: {protocol ?? "unknown"}.");
        if (string.IsNullOrWhiteSpace(protocol))
        {
            result.AddStep("Protocol Validation", "Unable to determine protocol.", false);
            return result;
        }

        if (!_parsers.ContainsKey(protocol))
        {
            result.AddStep("Protocol Support", $"Unsupported protocol: {protocol}", false);
            return result;
        }

        // Step 3: Parse configuration
        result.AddStep("Config Parsing", "Attempting to parse the configuration.");
        if (!_parsers[protocol].TryParse(data.Link, out var config, result))
        {
            return result;
        }

        // Step 4: Validate security
        result.AddStep("Security Check", "Checking TLS and encryption settings.");
        result.IsSecure = config.Security.Equals("tls", StringComparison.OrdinalIgnoreCase);
        if (!result.IsSecure && protocol != "ss") // Shadowsocks may not use TLS
        {
            result.AddStep("Security Check", "TLS is not enabled, which is less secure.", false);
        }

        if (config.Encryption == "none" && protocol != "trojan" && protocol != "http2") // Trojan and HTTP/2 rely on TLS
        {
            result.AddStep("Encryption Check", "No encryption specified, highly insecure.", false);
            result.IsSecure = false;
        }

        // Step 5: Validate port
        bool isStandardPort = config.Port == 443 || config.Port == 80 || config.Port == 8443 || config.Port == 8388; // 8388 for Shadowsocks
        result.AddStep("Port Check", isStandardPort
            ? $"Port {config.Port} is a standard port."
            : $"Port {config.Port} is non-standard, which may indicate a custom setup.", isStandardPort);

        // Step 6: Build and test Xray configuration
        result.AddStep("Xray Config Generation", "Generating Xray configuration.");
        try
        {
            var configJson = JsonSerializer.Serialize(
                BuildXrayConfig(config, protocol),
                new JsonSerializerOptions { WriteIndented = true });

            var tempPath = Path.GetTempFileName();
            try
            {
                await File.WriteAllTextAsync(tempPath, configJson);
                result.AddStep("Xray Binary Preparation", "Ensuring Xray binary is available.");

                var xrayPath = await XrayBootstrapper.EnsureXrayExistsAsync(_httpClientFactory);
                result.AddStep("Xray Binary Preparation", "Xray binary is ready.", true);

                result.AddStep("Xray Execution", "Running Xray process to test connection.");
                var (success, error, latency) = await RunXrayProcessAsync(xrayPath, tempPath);

                if (!success)
                {
                    result.AddStep("Xray Execution", error ?? "Unknown error during Xray execution.", false);
                    return result;
                }

                result.Success = true;
                result.LatencyMs = latency;
                result.AddStep("Xray Execution", $"Connection successful. Latency: {latency}ms.", true);
            }
            finally
            {
                if (File.Exists(tempPath))
                {
                    File.Delete(tempPath);
                }
            }

            // Step 7: Validate SNI and network
            result.AddStep("SNI Validation", string.IsNullOrEmpty(config.Sni)
                ? "SNI not specified, may cause issues with some servers."
                : $"SNI is set to {config.Sni}.", !string.IsNullOrEmpty(config.Sni));

            result.AddStep("Network Validation", $"Network type: {config.Network}.",
                config.Network == "tcp" || config.Network == "ws" || config.Network == "grpc" || config.Network == "h2" || config.Network == "udp");

            // Step 8: Optional SSL certificate check (if TLS is enabled)
            if (result.IsSecure)
            {
                result.AddStep("SSL Certificate Check", $"Attempting to validate SSL certificate for {config.Address}:{config.Port}.");
                try
                {
                    using var client = _httpClientFactory.CreateClient();
                    var request = new HttpRequestMessage(HttpMethod.Get, $"https://{config.Address}:{config.Port}");
                    var response = await client.SendAsync(request);
                    result.AddStep("SSL Certificate Check", "Successfully validated SSL certificate.", true);
                }
                catch (HttpRequestException ex)
                {
                    result.AddStep("SSL Certificate Check", $"Failed to validate SSL certificate: {ex.Message}", false);
                    result.IsSecure = false;
                }
            }
        }
        catch (Exception ex)
        {
            result.AddStep("Unexpected Error", $"An error occurred: {ex.Message}", false);
        }

        return result;
    }

    private static string? ExtractProtocol(string link)
    {
        var parts = link.Split("://", StringSplitOptions.None);
        return parts.Length == 2 ? parts[0].ToLowerInvariant() : null;
    }

    private static object BuildXrayConfig(ConfigDetails config, string protocol)
    {
        object userConfig;
        object settings;

        if (protocol == "trojan")
        {
            userConfig = new
            {
                password = config.Id
            };
            settings = new
            {
                servers = new[]
                {
                    new
                    {
                        address = config.Address,
                        port = config.Port,
                        password = config.Id
                    }
                }
            };
        }
        else if (protocol == "ss")
        {
            userConfig = new
            {
                method = config.Method,
                password = config.Password
            };
            settings = new
            {
                servers = new[]
                {
                    new
                    {
                        address = config.Address,
                        port = config.Port,
                        method = config.Method,
                        password = config.Password
                    }
                }
            };
        }
        else if (protocol == "http2")
        {
            userConfig = new
            {
                user = config.Username,
                pass = config.Password
            };
            settings = new
            {
                vnext = new[]
                {
                    new
                    {
                        address = config.Address,
                        port = config.Port,
                        users = new[] { userConfig }
                    }
                }
            };
        }
        else
        {
            userConfig = new
            {
                id = config.Id,
                encryption = protocol == "vless" ? config.Encryption : null,
                alterId = protocol == "vmess" ? config.AlterId : 0,
                security = protocol == "vmess" ? config.SecurityType : null
            };
            settings = new
            {
                vnext = new[]
                {
                    new
                    {
                        address = config.Address,
                        port = config.Port,
                        users = new[] { userConfig }
                    }
                }
            };
        }

        var outbound = new
        {
            protocol = protocol == "http2" ? "http" : protocol, // Xray uses "http" for HTTP/2
            settings,
            streamSettings = new
            {
                network = config.Network,
                security = config.Security,
                tlsSettings = string.IsNullOrEmpty(config.Sni) ? null : new { serverName = config.Sni },
                wsSettings = config.Network == "ws" ? new { path = config.Path } : null,
                grpcSettings = config.Network == "grpc" ? new { serviceName = config.Path } : null,
                httpSettings = config.Network == "h2" ? new { path = config.Path } : null
            }
        };

        return new
        {
            log = new { loglevel = "warning" },
            outbounds = new[] { outbound },
            stats = new { },
            routing = new
            {
                rules = new[]
                {
                    new
                    {
                        type = "field",
                        outboundTag = "direct",
                        domain = new[] { "example.com" }
                    }
                }
            },
            outbounds_extra = new[]
            {
                new { protocol = "freedom", tag = "direct" },
                new { protocol = "blackhole", tag = "blocked" }
            }
        };
    }

    private static async Task<(bool Success, string? Error, int? Latency)> RunXrayProcessAsync(string xrayPath, string configPath)
    {
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = xrayPath,
                Arguments = $"run -c \"{configPath}\"",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            }
        };

        try
        {
            var stopwatch = Stopwatch.StartNew();
            process.Start();

            var outputTask = process.StandardOutput.ReadToEndAsync();
            var errorTask = process.StandardError.ReadToEndAsync();

            if (!await Task.Run(() => process.WaitForExit(10000)))
            {
                try { process.Kill(true); } catch { }
                return (false, "Xray process timed out.", null);
            }

            stopwatch.Stop();
            var output = await outputTask;
            var error = await errorTask;

            var hasError = output.Contains("error", StringComparison.OrdinalIgnoreCase)
                        || error.Contains("failed", StringComparison.OrdinalIgnoreCase);

            return (!hasError, hasError ? error : null, (int)stopwatch.ElapsedMilliseconds);
        }
        catch (Exception ex)
        {
            return (false, $"Process execution failed: {ex.Message}", null);
        }
    }

    
}

#endregion

#region Protocol Parser

public interface IProtocolParser
{
    bool TryParse(string link, out ConfigDetails config, ResultStatus result);
}

public class VlessProtocolParser : IProtocolParser
{
    public bool TryParse(string link, out ConfigDetails config, ResultStatus result)
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


public class VmessProtocolParser : IProtocolParser
{
    public bool TryParse(string link, out ConfigDetails config, ResultStatus result)
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


public class TrojanProtocolParser : IProtocolParser
{
    public bool TryParse(string link, out ConfigDetails config, ResultStatus result)
    {
        config = new ConfigDetails();
        try
        {
            // Validate and parse the URI
            if (!link.StartsWith("trojan://", StringComparison.OrdinalIgnoreCase))
            {
                result.AddStep("Config Parsing", "Invalid Trojan link format.", false);
                return false;
            }

            var uri = new Uri(link);
            var query = HttpUtility.ParseQueryString(uri.Query);
            var userInfo = uri.UserInfo;

            // Check password (userInfo is the password in Trojan)
            if (string.IsNullOrEmpty(userInfo))
            {
                result.AddStep("Config Parsing", "Password is missing in the URL.", false);
                return false;
            }

            // Populate ConfigDetails
            config = new ConfigDetails
            {
                Id = userInfo, // In Trojan, userInfo is the password
                Address = uri.Host,
                Port = uri.Port > 0 ? uri.Port : 443, // Default to 443 for TLS
                Network = query["type"]?.ToLowerInvariant() ?? "tcp",
                Security = query["security"]?.ToLowerInvariant() ?? "tls", // Trojan typically uses TLS
                Sni = query["sni"] ?? query["host"] ?? uri.Host,
                Path = query["path"] ?? "",
                Encryption = "none", // Trojan uses TLS for encryption, no additional encryption
                AlterId = 0, // Not used in Trojan
                SecurityType = "none" // Not used in Trojan
            };

            // Validate critical fields
            if (string.IsNullOrEmpty(config.Address))
            {
                result.AddStep("Config Parsing", "Server address is missing.", false);
                return false;
            }

            if (config.Security == "tls" && string.IsNullOrEmpty(config.Sni))
            {
                result.AddStep("Config Parsing", "SNI is required for TLS but not provided.", false);
                return false;
            }

            result.AddStep("Config Parsing", "Successfully parsed Trojan configuration.", true);
            return true;
        }
        catch (UriFormatException ex)
        {
            result.AddStep("Config Parsing", $"Invalid URI format: {ex.Message}", false);
            return false;
        }
        catch (Exception ex)
        {
            result.AddStep("Config Parsing", $"Failed to parse Trojan configuration: {ex.Message}", false);
            return false;
        }
    }
}


public class ShadowsocksProtocolParser : IProtocolParser
{
    public bool TryParse(string link, out ConfigDetails config, ResultStatus result)
    {
        config = new ConfigDetails();
        try
        {
            if (!link.StartsWith("ss://", StringComparison.OrdinalIgnoreCase))
            {
                result.AddStep("Config Parsing", "Invalid Shadowsocks link format.", false);
                return false;
            }

            var uri = new Uri(link);
            var userInfo = uri.UserInfo;

            // Decode base64-encoded userInfo (method:password)
            string method, password;
            try
            {
                var decodedUserInfo = Encoding.UTF8.GetString(Convert.FromBase64String(userInfo));
                var userInfoParts = decodedUserInfo.Split(':');
                if (userInfoParts.Length != 2)
                {
                    result.AddStep("Config Parsing", "Invalid user info format (method:password).", false);
                    return false;
                }
                method = userInfoParts[0];
                password = userInfoParts[1];
            }
            catch (FormatException ex)
            {
                result.AddStep("Config Parsing", $"Invalid Base64 format in user info: {ex.Message}", false);
                return false;
            }

            var query = HttpUtility.ParseQueryString(uri.Query);

            config = new ConfigDetails
            {
                Id = password, // For compatibility with other protocols
                Password = password,
                Method = method.ToLowerInvariant(),
                Address = uri.Host,
                Port = uri.Port > 0 ? uri.Port : 8388, // Default Shadowsocks port
                Network = "tcp", // Shadowsocks supports TCP and UDP, default to TCP
                Security = query["security"]?.ToLowerInvariant() ?? "none",
                Sni = query["sni"] ?? query["host"] ?? uri.Host,
                Path = query["path"] ?? "",
                Encryption = method, // Shadowsocks uses method as encryption
                AlterId = 0,
                SecurityType = "none"
            };

            // Validate critical fields
            if (string.IsNullOrEmpty(config.Address))
            {
                result.AddStep("Config Parsing", "Server address is missing.", false);
                return false;
            }

            if (string.IsNullOrEmpty(config.Method) || string.IsNullOrEmpty(config.Password))
            {
                result.AddStep("Config Parsing", "Method or password is missing.", false);
                return false;
            }

            result.AddStep("Config Parsing", "Successfully parsed Shadowsocks configuration.", true);
            return true;
        }
        catch (UriFormatException ex)
        {
            result.AddStep("Config Parsing", $"Invalid URI format: {ex.Message}", false);
            return false;
        }
        catch (Exception ex)
        {
            result.AddStep("Config Parsing", $"Failed to parse Shadowsocks configuration: {ex.Message}", false);
            return false;
        }
    }
}


public class Http2ProtocolParser : IProtocolParser
{
    public bool TryParse(string link, out ConfigDetails config, ResultStatus result)
    {
        config = new ConfigDetails();
        try
        {
            if (!link.StartsWith("http2://", StringComparison.OrdinalIgnoreCase))
            {
                result.AddStep("Config Parsing", "Invalid HTTP/2 link format.", false);
                return false;
            }

            var uri = new Uri(link);
            var query = HttpUtility.ParseQueryString(uri.Query);
            var userInfo = uri.UserInfo.Split(':');
            if (userInfo.Length < 2 || string.IsNullOrEmpty(userInfo[0]) || string.IsNullOrEmpty(userInfo[1]))
            {
                result.AddStep("Config Parsing", "Invalid user info format (username:password).", false);
                return false;
            }

            config = new ConfigDetails
            {
                Id = userInfo[0], // Username as Id for compatibility
                Username = userInfo[0],
                Password = userInfo[1],
                Address = uri.Host,
                Port = uri.Port > 0 ? uri.Port : 443, // Default to 443 for HTTP/2
                Network = "h2", // HTTP/2 uses h2 network
                Security = query["security"]?.ToLowerInvariant() ?? "tls", // HTTP/2 typically uses TLS
                Sni = query["sni"] ?? query["host"] ?? uri.Host,
                Path = query["path"] ?? "",
                Encryption = "none", // HTTP/2 relies on TLS
                AlterId = 0,
                SecurityType = "none"
            };

            // Validate critical fields
            if (string.IsNullOrEmpty(config.Address))
            {
                result.AddStep("Config Parsing", "Server address is missing.", false);
                return false;
            }

            if (config.Security == "tls" && string.IsNullOrEmpty(config.Sni))
            {
                result.AddStep("Config Parsing", "SNI is required for TLS but not provided.", false);
                return false;
            }

            result.AddStep("Config Parsing", "Successfully parsed HTTP/2 configuration.", true);
            return true;
        }
        catch (UriFormatException ex)
        {
            result.AddStep("Config Parsing", $"Invalid URI format: {ex.Message}", false);
            return false;
        }
        catch (Exception ex)
        {
            result.AddStep("Config Parsing", $"Failed to parse HTTP/2 configuration: {ex.Message}", false);
            return false;
        }
    }
}


public class Socks5ProtocolParser : IProtocolParser
{
    public bool TryParse(string link, out ConfigDetails config, ResultStatus result)
    {
        config = new ConfigDetails();
        try
        {
            if (!link.StartsWith("socks5://", StringComparison.OrdinalIgnoreCase))
            {
                result.AddStep("Config Parsing", "Invalid SOCKS5 link format.", false);
                return false;
            }

            var uri = new Uri(link);
            var query = HttpUtility.ParseQueryString(uri.Query);
            var userInfo = uri.UserInfo.Split(':');
            string username = userInfo.Length > 0 ? userInfo[0] : string.Empty;
            string password = userInfo.Length > 1 ? userInfo[1] : string.Empty;

            config = new ConfigDetails
            {
                Id = username, // Username as Id for compatibility
                Username = username,
                Password = password,
                Address = uri.Host,
                Port = uri.Port > 0 ? uri.Port : 1080, // Default SOCKS5 port
                Network = "tcp", // SOCKS5 typically uses TCP
                Security = query["security"]?.ToLowerInvariant() ?? "none",
                Sni = query["sni"] ?? query["host"] ?? uri.Host,
                Path = query["path"] ?? "",
                Encryption = "none", // SOCKS5 relies on external encryption (e.g., TLS)
                AlterId = 0,
                SecurityType = "none"
            };

            // Validate critical fields
            if (string.IsNullOrEmpty(config.Address))
            {
                result.AddStep("Config Parsing", "Server address is missing.", false);
                return false;
            }

            if (config.Security == "tls" && string.IsNullOrEmpty(config.Sni))
            {
                result.AddStep("Config Parsing", "SNI is required for TLS but not provided.", false);
                return false;
            }

            result.AddStep("Config Parsing", "Successfully parsed SOCKS5 configuration.", true);
            return true;
        }
        catch (UriFormatException ex)
        {
            result.AddStep("Config Parsing", $"Invalid URI format: {ex.Message}", false);
            return false;
        }
        catch (Exception ex)
        {
            result.AddStep("Config Parsing", $"Failed to parse SOCKS5 configuration: {ex.Message}", false);
            return false;
        }
    }
}


public class WireguardProtocolParser : IProtocolParser
{
    public bool TryParse(string link, out ConfigDetails config, ResultStatus result)
    {
        config = new ConfigDetails();
        try
        {
            if (!link.StartsWith("wg://", StringComparison.OrdinalIgnoreCase))
            {
                result.AddStep("Config Parsing", "Invalid WireGuard link format.", false);
                return false;
            }

            var uri = new Uri(link);
            var query = HttpUtility.ParseQueryString(uri.Query);
            var publicKey = uri.UserInfo;

            if (string.IsNullOrEmpty(publicKey))
            {
                result.AddStep("Config Parsing", "Public key is missing.", false);
                return false;
            }

            var privateKey = query["privateKey"];
            var allowedIPs = query["allowedIPs"] ?? "0.0.0.0/0,::/0"; // Default to route all traffic
            var endpoint = query["endpoint"] ?? uri.Host;

            config = new ConfigDetails
            {
                Id = publicKey, // Public key as Id for compatibility
                PublicKey = publicKey,
                PrivateKey = privateKey ?? string.Empty,
                AllowedIPs = allowedIPs,
                Endpoint = endpoint,
                Address = uri.Host,
                Port = uri.Port > 0 ? uri.Port : 51820, // Default WireGuard port
                Network = "udp", // WireGuard uses UDP
                Security = "none", // WireGuard has its own encryption
                Sni = query["sni"] ?? string.Empty,
                Path = string.Empty,
                Encryption = "wireguard", // Custom encryption identifier
                AlterId = 0,
                SecurityType = "none"
            };

            // Validate critical fields
            if (string.IsNullOrEmpty(config.Address))
            {
                result.AddStep("Config Parsing", "Server address is missing.", false);
                return false;
            }

            if (string.IsNullOrEmpty(config.PrivateKey))
            {
                result.AddStep("Config Parsing", "Private key is missing.", false);
                return false;
            }

            result.AddStep("Config Parsing", "Successfully parsed WireGuard configuration.", true);
            return true;
        }
        catch (UriFormatException ex)
        {
            result.AddStep("Config Parsing", $"Invalid URI format: {ex.Message}", false);
            return false;
        }
        catch (Exception ex)
        {
            result.AddStep("Config Parsing", $"Failed to parse WireGuard configuration: {ex.Message}", false);
            return false;
        }
    }
}

#endregion
