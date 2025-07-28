using System.Diagnostics;
using System.Text.Json;
using System.Threading.Tasks;
using Check.Core.Extensions.Bootst;
using Check.Core.Models.Common;
using Check.Core.Models.Receive;
using System.Web;
using Check.Core.Services.Protocol;
using Microsoft.Extensions.DependencyInjection;

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

    public ConnectionReview(
            IHttpClientFactory httpClientFactory,
            VlessProtocolParser vlessParser,
            VmessProtocolParser vmessParser,
            TrojanProtocolParser trojanParser,
            ShadowsocksProtocolParser shadowsocksParser,
            Http2ProtocolParser http2Parser,
            Socks5ProtocolParser socks5Parser,
            WireguardProtocolParser wireguardParser,
            HysteriaProtocolParser hysteriaParser)
    {
        _httpClientFactory = httpClientFactory ?? throw new ArgumentNullException(nameof(httpClientFactory));
        _parsers = new Dictionary<string, IProtocolParser>
            {
                { "vless", vlessParser },
                { "vmess", vmessParser },
                { "trojan", trojanParser },
                { "ss", shadowsocksParser },
                { "http2", http2Parser },
                { "socks5", socks5Parser },
                { "wg", wireguardParser },
                { "hysteria", hysteriaParser }
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

    // Builds Xray Configuration JSON Based on Protocol And Configuration Details
    private static object BuildXrayConfig(ConfigDetails config, string protocol)
    {
        // Initialize User Configuration Based on Protocol
        object userConfig;
        object settings;

        // Handle Trojan Protocol
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

    //private static async Task<(bool Success, string? Error, int? Latency)> RunXrayProcessAsync(string xrayPath, string configPath)
    //{
    //    using var process = new Process
    //    {
    //        StartInfo = new ProcessStartInfo
    //        {
    //            FileName = xrayPath,
    //            Arguments = $"run -c \"{configPath}\"",
    //            RedirectStandardOutput = true,
    //            RedirectStandardError = true,
    //            UseShellExecute = false,
    //            CreateNoWindow = true
    //        }
    //    };

    //    try
    //    {
    //        var stopwatch = Stopwatch.StartNew();
    //        process.Start();

    //        var outputTask = process.StandardOutput.ReadToEndAsync();
    //        var errorTask = process.StandardError.ReadToEndAsync();

    //        if (!await Task.Run(() => process.WaitForExit(10000)))
    //        {
    //            try { process.Kill(true); } catch { }
    //            return (false, "Xray process timed out.", null);
    //        }

    //        stopwatch.Stop();
    //        var output = await outputTask;
    //        var error = await errorTask;

    //        var hasError = output.Contains("error", StringComparison.OrdinalIgnoreCase)
    //                    || error.Contains("failed", StringComparison.OrdinalIgnoreCase);

    //        return (!hasError, hasError ? error : null, (int)stopwatch.ElapsedMilliseconds);
    //    }
    //    catch (Exception ex)
    //    {
    //        return (false, $"Process execution failed: {ex.Message}", null);
    //    }
    //}

    private static async Task<(bool Success, string? Error, int? Latency)> RunXrayProcessAsync(string xrayPath, string configPath, CancellationToken cancellationToken = default)
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cts.Token, cancellationToken);

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

            var outputTask = process.StandardOutput.ReadToEndAsync(linkedCts.Token);
            var errorTask = process.StandardError.ReadToEndAsync(linkedCts.Token);

            await process.WaitForExitAsync(linkedCts.Token);
            stopwatch.Stop();

            var output = await outputTask;
            var error = await errorTask;

            var hasError = output.Contains("error", StringComparison.OrdinalIgnoreCase) || error.Contains("failed", StringComparison.OrdinalIgnoreCase);
            return (!hasError, hasError ? error : null, (int)stopwatch.ElapsedMilliseconds);
        }
        catch (OperationCanceledException)
        {
            try { process.Kill(true); } catch { }
            return (false, "Xray process was cancelled or timed out.", null);
        }
        catch (Exception ex)
        {
            return (false, $"Process execution failed: {ex.Message}", null);
        }
    }
}

#endregion

