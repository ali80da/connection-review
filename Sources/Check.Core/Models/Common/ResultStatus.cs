using System.Collections.Generic;

namespace Check.Core.Models.Common;

public class ReportStep
{
    public string Step { get; set; } = string.Empty;
    public string Details { get; set; } = string.Empty;
    public bool IsSuccess { get; set; }
}

public class ResultStatus
{
    public bool Success { get; set; }
    public int? LatencyMs { get; set; }
    public bool IsSecure { get; set; }
    //public double? DownloadSpeedMbps { get; set; }
    //public double? UploadSpeedMbps { get; set; }
    public List<ReportStep> Steps { get; set; } = new List<ReportStep>();
    //public string Summary => Success
    //    ? $"Connection successful with latency {LatencyMs}ms, download speed {DownloadSpeedMbps:F2} Mbps, upload speed {UploadSpeedMbps:F2} Mbps. {(IsSecure ? "Secure" : "Insecure")}."
    //    : "Connection failed. Check steps for details.";
    public string Summary => Success
        ? $"Connection successful . {(IsSecure ? "Secure" : "Insecure")}."
        : "Connection failed. Check steps for details.";

    public void AddStep(string step, string details, bool isSuccess = true)
    {
        Steps.Add(new ReportStep { Step = step, Details = details, IsSuccess = isSuccess });
    }
}


