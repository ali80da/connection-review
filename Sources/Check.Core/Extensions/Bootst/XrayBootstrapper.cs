using System;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Net.Http;
using System.Threading.Tasks;

namespace Check.Core.Extensions.Bootst;

public static class XrayBootstrapper
{
    private const string XrayVersion = "v1.8.8"; // قابل تنظیم در آینده
    private static readonly string XrayDir = Path.Combine(AppContext.BaseDirectory, "Xray");
    private static readonly string XrayFileName = OperatingSystem.IsWindows() ? "xray.exe" : "xray";
    private static readonly string XrayZipFile = "xray.zip";

    public static async Task<string> EnsureXrayExistsAsync(IHttpClientFactory httpClientFactory)
    {
        if (httpClientFactory == null) throw new ArgumentNullException(nameof(httpClientFactory));

        var xrayFile = Path.Combine(XrayDir, XrayFileName);

        // Step 1: Check if Xray binary already exists
        if (File.Exists(xrayFile))
        {
            return xrayFile;
        }

        // Step 2: Create Xray directory if it doesn't exist
        Directory.CreateDirectory(XrayDir);

        // Step 3: Download Xray
        var downloadUrl = OperatingSystem.IsWindows()
            ? $"https://github.com/XTLS/Xray-core/releases/download/{XrayVersion}/Xray-windows-64.zip"
            : $"https://github.com/XTLS/Xray-core/releases/download/{XrayVersion}/Xray-linux-64.zip";

        var zipPath = Path.Combine(XrayDir, XrayZipFile);

        try
        {
            using var client = httpClientFactory.CreateClient();
            client.Timeout = TimeSpan.FromSeconds(30); // Timeout for download

            var bytes = await client.GetByteArrayAsync(downloadUrl);
            await File.WriteAllBytesAsync(zipPath, bytes);

            // Step 4: Extract zip
            ZipFile.ExtractToDirectory(zipPath, XrayDir, overwriteFiles: true);

            // Step 5: Find the extracted binary
            var extracted = Directory.GetFiles(XrayDir, XrayFileName, SearchOption.AllDirectories)
                                    .FirstOrDefault();

            if (string.IsNullOrEmpty(extracted) || !File.Exists(extracted))
            {
                throw new FileNotFoundException("Xray binary not found after extraction.");
            }

            // Step 6: Copy to target path if necessary
            if (!File.Exists(xrayFile))
            {
                File.Copy(extracted, xrayFile, overwrite: true);
            }

            // Step 7: Set executable permissions for Linux
            if (!OperatingSystem.IsWindows())
            {
                using var chmod = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "chmod",
                        Arguments = $"+x \"{xrayFile}\"",
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }
                };

                chmod.Start();
                var error = await chmod.StandardError.ReadToEndAsync();
                await chmod.WaitForExitAsync();

                if (chmod.ExitCode != 0)
                {
                    throw new InvalidOperationException($"Failed to set executable permissions: {error}");
                }
            }

            return xrayFile;
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"Failed to prepare Xray: {ex.Message}", ex);
        }
        finally
        {
            // Step 8: Clean up zip file
            if (File.Exists(zipPath))
            {
                File.Delete(zipPath);
            }
        }
    }
}