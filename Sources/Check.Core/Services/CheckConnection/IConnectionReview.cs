using System;
using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Web;
using Check.Core.Extensions.Bootst;
using Check.Core.Models.Common;
using Check.Core.Models.Receive;
using System.Net;

namespace Check.Core.Services.CheckConnection;

public interface IConnectionReview
{
    Task<ResultStatus> AnalyzeAsync(ProtocolData data);
}

public class ConnectionReview : IConnectionReview
{
    private readonly IHttpClientFactory _httpClientFactory;

    public ConnectionReview(IHttpClientFactory httpClientFactory)
    {
        _httpClientFactory = httpClientFactory ?? throw new ArgumentNullException(nameof(httpClientFactory));
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

        if (protocol != "vmess" && protocol != "vless")
        {
            result.AddStep("Protocol Support", $"Unsupported protocol: {protocol}", false);
            return result;
        }

        // Step 3: Parse configuration
        result.AddStep("Config Parsing", "Attempting to parse the configuration.");
        if (!TryParseConfig(data.Link, protocol, out var config, result))
        {
            return result;
        }

        // Step 4: Validate security
        result.AddStep("Security Check", "Checking TLS and encryption settings.");
        result.IsSecure = config.Security.Equals("tls", StringComparison.OrdinalIgnoreCase);
        if (!result.IsSecure)
        {
            result.AddStep("Security Check", "TLS is not enabled, which is less secure.", false);
        }

        if (config.Encryption == "none")
        {
            result.AddStep("Encryption Check", "No encryption specified, highly insecure.", false);
            result.IsSecure = false;
        }

        // Step 5: Validate port
        bool isStandardPort = config.Port == 443 || config.Port == 80 || config.Port == 8443;
        result.AddStep("Port Check", isStandardPort
            ? $"Port {config.Port} is a standard port (HTTP/HTTPS)."
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

            result.AddStep("Network Validation", $"Network type: {config.Network}.", config.Network == "tcp" || config.Network == "ws");

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

    private static bool TryParseConfig(string link, string protocol, out ConfigDetails config, ResultStatus result)
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
                Port = uri.Port > 0 ? uri.Port : 443, // Default to 443 if port is not specified
                Network = query["type"]?.ToLowerInvariant() ?? "tcp",
                Security = query["security"]?.ToLowerInvariant() ?? "",
                Sni = query["sni"] ?? query["host"] ?? uri.Host,
                Path = query["path"] ?? "",
                Encryption = query["encryption"]?.ToLowerInvariant() ?? "none",
                AlterId = protocol == "vmess" && query["aid"] != null && int.TryParse(query["aid"], out var aid) ? aid : 0,
                SecurityType = protocol == "vmess" ? (query["scy"]?.ToLowerInvariant() ?? "auto") : "none"
            };

            if (protocol == "vmess")
            {
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
            }

            result.AddStep("Config Parsing", "Successfully parsed configuration.", true);
            return true;
        }
        catch (Exception ex)
        {
            result.AddStep("Config Parsing", $"Failed to parse configuration: {ex.Message}", false);
            return false;
        }
    }

    private static object BuildXrayConfig(ConfigDetails config, string protocol)
    {
        var userConfig = new
        {
            id = config.Id,
            encryption = protocol == "vless" ? config.Encryption : null,
            alterId = protocol == "vmess" ? config.AlterId : 0,
            security = protocol == "vmess" ? config.SecurityType : null
        };

        var outbound = new
        {
            protocol,
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
            },
            streamSettings = new
            {
                network = config.Network,
                security = config.Security,
                tlsSettings = string.IsNullOrEmpty(config.Sni) ? null : new { serverName = config.Sni },
                wsSettings = config.Network == "ws" ? new { path = config.Path } : null
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