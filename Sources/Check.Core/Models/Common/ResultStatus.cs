using System.Collections.Generic;

namespace Check.Core.Models.Common;

public class ResultStatus
{
    public bool Success { get; set; }
    public int? LatencyMs { get; set; }
    public bool IsSecure { get; set; }
    public List<ReportStep> Steps { get; set; } = new();

    public void AddStep(string step, string details, bool isSuccess = true)
    {
        Steps.Add(new ReportStep { Step = step, Details = details, IsSuccess = isSuccess });
    }
}

public class ReportStep
{
    public string Step { get; set; } = string.Empty;
    public string Details { get; set; } = string.Empty;
    public bool IsSuccess { get; set; }
}