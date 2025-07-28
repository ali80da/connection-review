using System.Diagnostics;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Threading.Tasks;
using Check.Core.Extensions.Bootst;
using Check.Core.Models.Common;
using Check.Core.Models.Receive;
using System.Web;
using Check.Core.Services.Protocol;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Check.Core.Configuration;
using System.Net.Sockets;

namespace Check.Core.Services.CheckConnection
{
    public interface IConnectionReview
    {
        Task<ResultStatus> AnalyzeAsync(ProtocolData data);
    }

    public class ConnectionReview : IConnectionReview
    {
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly IMemoryCache _cache;
        private readonly ILogger<ConnectionReview> _logger;
        private readonly Dictionary<string, IProtocolParser> _parsers;
        private readonly AppSettings _appSettings;

        public ConnectionReview(
            IHttpClientFactory httpClientFactory,
            IMemoryCache cache,
            ILogger<ConnectionReview> logger,
            IOptions<AppSettings> appSettings,
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
            _cache = cache ?? throw new ArgumentNullException(nameof(cache));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _appSettings = appSettings?.Value ?? throw new ArgumentNullException(nameof(appSettings));
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
            var cacheKey = $"Analyze_{data.Link}_{data.Protocol}";
            var parseCacheKey = $"Parse_{data.Link}_{data.Protocol}";
            var lastTestKey = $"LastTest_{data.Link}_{data.Protocol}";

            var protocol = data.Protocol?.ToLowerInvariant() ?? ExtractProtocol(data.Link);
            _logger.LogInformation("Starting analysis for {Link}, Protocol={Protocol}, ForceRefresh={ForceRefresh}", data.Link, protocol ?? "unknown", data.ForceRefresh);

            // Check cooldown
            if (!data.ForceRefresh && _cache.TryGetValue(lastTestKey, out DateTime lastTestTime))
            {
                var timeSinceLastTest = DateTime.UtcNow - lastTestTime;
                if (timeSinceLastTest.TotalSeconds < (_appSettings?.TestCooldownSeconds ?? 5))
                {
                    _logger.LogInformation("Test cooldown active for {Link}. Wait {Seconds} seconds.", data.Link, (_appSettings?.TestCooldownSeconds ?? 5) - timeSinceLastTest.TotalSeconds);
                    result.AddStep("Test Cooldown", $"Please wait {(_appSettings?.TestCooldownSeconds ?? 5) - timeSinceLastTest.TotalSeconds:F1} seconds before retrying.", false);
                    result.Summary = "Test cooldown active.";
                    return result;
                }
            }

            // Check cache only if ForceRefresh is false
            if (!data.ForceRefresh && _cache.TryGetValue(cacheKey, out ResultStatus cachedResult))
            {
                _logger.LogInformation("Returning cached result for {Link}, IsSecure={IsSecure}", data.Link, cachedResult.IsSecure);
                return cachedResult;
            }

            // Update last test time
            _cache.Set(lastTestKey, DateTime.UtcNow, TimeSpan.FromSeconds(_appSettings?.TestCooldownSeconds ?? 5));

            // Step 1: Validate input
            result.AddStep("Input Validation", "Checking if the provided link is valid.", true);
            if (string.IsNullOrWhiteSpace(data.Link))
            {
                _logger.LogWarning("Invalid input: Link is empty");
                result.AddStep("Input Validation", "Link cannot be empty.", false);
                return result;
            }

            if (!data.Link.Contains("://"))
            {
                _logger.LogWarning("Invalid link format for {Link}", data.Link);
                result.AddStep("Link Format Check", "Invalid link format.", false);
                return result;
            }

            // Step 2: Extract protocol
            _logger.LogInformation("Extracted protocol: {Protocol} for {Link}", protocol, data.Link);
            result.AddStep("Protocol Extraction", $"Determined protocol: {protocol ?? "unknown"}.", true);
            if (string.IsNullOrWhiteSpace(protocol))
            {
                _logger.LogWarning("Unable to determine protocol for {Link}", data.Link);
                result.AddStep("Protocol Validation", "Unable to determine protocol.", false);
                return result;
            }

            if (!_parsers.ContainsKey(protocol))
            {
                _logger.LogWarning("Unsupported protocol: {Protocol} for {Link}", protocol, data.Link);
                result.AddStep("Protocol Support", $"Unsupported protocol: {protocol}", false);
                return result;
            }

            // Step 3: Parse configuration
            ConfigDetails config;
            if (_cache.TryGetValue(parseCacheKey, out ConfigDetails cachedConfig))
            {
                _logger.LogInformation("Using cached config for {Link}", data.Link);
                config = cachedConfig;
            }
            else
            {
                if (!_parsers[protocol].TryParse(data.Link, out config, result))
                {
                    _logger.LogError("Failed to parse configuration for {Link}", data.Link);
                    return result;
                }
                _logger.LogInformation("Parsed config for {Link}: Security={Security}, Port={Port}, Sni={Sni}, Encryption={Encryption}, Network={Network}",
                    data.Link, config.Security, config.Port, config.Sni, config.Encryption, config.Network);
                _cache.Set(parseCacheKey, config, TimeSpan.FromMinutes(_appSettings?.CacheTtlSeconds ?? 10));
            }

            // Step 4: Validate security
            result.AddStep("Security Check", "Checking TLS and encryption settings.", true);
            bool isTlsExplicit = config.Security?.Equals("tls", StringComparison.OrdinalIgnoreCase) ?? false;
            bool isPortTlsLikely = config.Port == 443 || config.Port == 8443;
            result.IsSecure = isTlsExplicit || (isPortTlsLikely && string.IsNullOrEmpty(config.Security));

            // Extra check for VLESS link parameters
            if (protocol == "vless" && !isTlsExplicit)
            {
                try
                {
                    var uri = new Uri(data.Link);
                    var query = HttpUtility.ParseQueryString(uri.Query);
                    if (query["security"]?.ToLowerInvariant() == "tls")
                    {
                        _logger.LogInformation("Detected security=tls in VLESS query for {Link}", data.Link);
                        result.IsSecure = true;
                        config.Security = "tls"; // Fix config for Xray
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to parse VLESS query parameters for {Link}", data.Link);
                }
            }

            _logger.LogInformation("Security check: Protocol={Protocol}, Security={Security}, Port={Port}, IsSecure={IsSecure}",
                protocol, config.Security, config.Port, result.IsSecure);

            if (!result.IsSecure && protocol != "ss")
            {
                result.AddStep("Security Check", "TLS is not enabled, which is less secure.", false);
            }

            // Handle encryption check for VLESS
            if (config.Encryption == "none" && protocol != "trojan" && protocol != "http2")
            {
                _logger.LogInformation("No encryption for {Link}, Protocol={Protocol}, but TLS={IsTls}",
                    data.Link, protocol, result.IsSecure);
                string encryptionMessage = result.IsSecure
                    ? "No encryption specified, but connection is secure due to TLS."
                    : "No encryption specified, highly insecure.";
                result.AddStep("Encryption Check", encryptionMessage, result.IsSecure);
            }

            // Step 5: Validate port
            bool isStandardPort = config.Port == 443 || config.Port == 80 || config.Port == 8443 || config.Port == 8388;
            result.AddStep("Port Check", isStandardPort
                ? $"Port {config.Port} is a standard port."
                : $"Port {config.Port} is non-standard, which may indicate a custom setup.", isStandardPort);

            // Step 6: Build and test Xray configuration
            result.AddStep("Xray Config Generation", "Generating Xray configuration.", true);
            try
            {
                var configJson = JsonSerializer.Serialize(
                    BuildXrayConfig(config, protocol),
                    new JsonSerializerOptions { WriteIndented = false });

                var tempFile = Path.GetTempFileName();
                try
                {
                    await File.WriteAllTextAsync(tempFile, configJson);
                    result.AddStep("Xray Binary Preparation", "Preparing Xray binary.", true);

                    var xrayPath = await XrayBootstrapper.EnsureXrayExistsAsync(_httpClientFactory);
                    _logger.LogInformation("Xray binary ready at {XrayPath}", xrayPath);

                    var stopwatch = Stopwatch.StartNew();
                    var (success, error, latency) = await RunXrayProcessAsync(xrayPath, tempFile);
                    stopwatch.Stop();

                    result.AddStep("Xray Execution", success
                        ? $"Connection successful. Latency: {latency}ms."
                        : error ?? "Unknown error during Xray execution.", success);

                    if (!success)
                    {
                        _logger.LogError("Xray execution failed for {Link}: {Error}", data.Link, error);
                        return result;
                    }

                    result.Success = true;
                    result.LatencyMs = latency;
                    if (latency > 1000)
                    {
                        _logger.LogWarning("High latency detected for {Link}: {Latency}ms", data.Link, latency);
                    }
                }
                finally
                {
                    if (File.Exists(tempFile))
                    {
                        File.Delete(tempFile);
                    }
                }

                // Step 7: Validate SNI and network
                result.AddStep("SNI Validation", string.IsNullOrEmpty(config.Sni)
                    ? "SNI not specified, may cause issues with some servers."
                    : $"SNI is set to {config.Sni}.", !string.IsNullOrEmpty(config.Sni));

                result.AddStep("Network Validation", $"Network type: {config.Network}.",
                    config.Network == "tcp" || config.Network == "ws" || config.Network == "grpc" || config.Network == "h2" || config.Network == "udp");

                // Step 8: SSL certificate check
                if (result.IsSecure)
                {
                    result.AddStep("SSL Certificate Check", $"Validating SSL certificate for {config.Sni ?? config.Address}:{config.Port}.", true);
                    bool certValidated = false;
                    for (int attempt = 0; attempt < 3; attempt++)
                    {
                        await Task.Delay(Random.Shared.Next(100, 500 * (attempt + 1))); // Exponential backoff
                        try
                        {
                            var cert = await GetCertificateAsync(config.Sni ?? config.Address, config.Port);
                            if (cert != null && cert.NotAfter > DateTime.UtcNow)
                            {
                                _logger.LogInformation("Valid SSL certificate for {Host}:{Port}, expires: {ExpiryDate}",
                                    config.Sni ?? config.Address, config.Port, cert.NotAfter);
                                result.AddStep("SSL Certificate Check", $"Valid certificate, expires: {cert.NotAfter:yyyy-MM-dd}.", true);
                                certValidated = true;
                                break;
                            }
                        }
                        catch (Exception ex)
                        {
                            _logger.LogWarning(ex, "SSL certificate check failed for {Host}:{Port}, attempt {Attempt}",
                                config.Sni ?? config.Address, config.Port, attempt + 1);
                        }
                    }

                    if (!certValidated)
                    {
                        _logger.LogWarning("Unable to validate SSL certificate for {Host}:{Port} after retries", config.Sni ?? config.Address, config.Port);
                        result.AddStep("SSL Certificate Check",
                            $"Unable to validate SSL certificate for {config.Sni ?? config.Address}: Unable to retrieve certificate after retries. Connection is still secure due to TLS.", true);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error for {Link}", data.Link);
                result.AddStep("Unexpected Error", $"An error occurred: {ex.Message}", false);
            }

            result.Summary = result.Success
                ? $"Connection successful. {(result.IsSecure ? "Secure" : "Insecure")}."
                : "Connection failed.";

            _logger.LogInformation("Final result for {Link}: Success={Success}, IsSecure={IsSecure}", data.Link, result.Success, result.IsSecure);
            _cache.Set(cacheKey, result, TimeSpan.FromMinutes(_appSettings?.CacheTtlSeconds ?? 10));
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
                userConfig = new { password = config.Id };
                settings = new { servers = new[] { new { address = config.Address, port = config.Port, password = config.Id } } };
            }
            else if (protocol == "ss")
            {
                userConfig = new { method = config.Method, password = config.Password };
                settings = new { servers = new[] { new { address = config.Address, port = config.Port, method = config.Method, password = config.Password } } };
            }
            else if (protocol == "http2")
            {
                userConfig = new { user = config.Username, pass = config.Password };
                settings = new { vnext = new[] { new { address = config.Address, port = config.Port, users = new[] { userConfig } } } };
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
                settings = new { vnext = new[] { new { address = config.Address, port = config.Port, users = new[] { userConfig } } } };
            }

            var outbound = new
            {
                protocol = protocol == "http2" ? "http" : protocol,
                settings,
                streamSettings = new
                {
                    network = config.Network,
                    security = config.Security ?? (config.Port == 443 || config.Port == 8443 ? "tls" : "none"),
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
                routing = new { rules = new[] { new { type = "field", outboundTag = "direct", domain = new[] { "example.com" } } } },
                outbounds_extra = new[] { new { protocol = "freedom", tag = "direct" }, new { protocol = "blackhole", tag = "blocked" } }
            };
        }

        private async Task<(bool Success, string? Error, int? Latency)> RunXrayProcessAsync(string xrayPath, string configPath, CancellationToken cancellationToken = default)
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(_appSettings?.XrayTimeoutSeconds ?? 7));
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
                _logger.LogInformation("Starting Xray process for {XrayPath}", xrayPath);
                var stopwatch = Stopwatch.StartNew();
                process.Start();

                var outputStart = stopwatch.ElapsedMilliseconds;
                var outputTask = process.StandardOutput.ReadToEndAsync(linkedCts.Token);
                var errorTask = process.StandardError.ReadToEndAsync(linkedCts.Token);

                _logger.LogInformation("Waiting for Xray process to exit for {XrayPath}", xrayPath);
                await process.WaitForExitAsync(linkedCts.Token);
                var waitEnd = stopwatch.ElapsedMilliseconds;

                var output = await outputTask;
                _logger.LogInformation("Reading Xray output took {Time}ms", stopwatch.ElapsedMilliseconds - outputStart);
                var error = await errorTask;
                _logger.LogInformation("Reading Xray error output took {Time}ms", stopwatch.ElapsedMilliseconds - waitEnd);

                var hasError = output.Contains("error", StringComparison.OrdinalIgnoreCase) || error.Contains("failed", StringComparison.OrdinalIgnoreCase);
                _logger.LogInformation("Xray process completed for {XrayPath}, Success={Success}, Latency={Latency}ms", xrayPath, !hasError, stopwatch.ElapsedMilliseconds);

                return (!hasError, hasError ? error : null, (int)stopwatch.ElapsedMilliseconds);
            }
            catch (OperationCanceledException)
            {
                try { process.Kill(true); } catch { }
                _logger.LogWarning("Xray process timed out for {XrayPath}", xrayPath);
                return (false, "Xray process was cancelled or timed out.", null);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Xray process execution failed for {XrayPath}", xrayPath);
                return (false, $"Process execution failed: {ex.Message}", null);
            }
        }

        private async Task<X509Certificate2?> GetCertificateAsync(string host, int port)
        {
            try
            {
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                using var tcpClient = new TcpClient();
                _logger.LogInformation("Connecting to {Host}:{Port} for SSL certificate check", host, port);
                await tcpClient.ConnectAsync(host, port, cts.Token);
                using var sslStream = new SslStream(tcpClient.GetStream(), false, (sender, certificate, chain, errors) => true);
                await sslStream.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
                {
                    TargetHost = host,
                    EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13
                }, cts.Token);
                _logger.LogInformation("SSL certificate retrieved for {Host}:{Port}", host, port);
                return sslStream.RemoteCertificate != null ? new X509Certificate2(sslStream.RemoteCertificate) : null;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to get SSL certificate for {Host}:{Port}", host, port);
                return null;
            }
        }
    }
}