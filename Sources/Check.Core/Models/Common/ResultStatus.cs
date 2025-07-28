using System.Text.Json.Serialization;

namespace Check.Core.Models.Common
{
    public class ResultStatus
    {
        [JsonPropertyName("success")]
        public bool Success { get; set; }

        [JsonPropertyName("latencyMs")]
        public int? LatencyMs { get; set; }

        [JsonPropertyName("isSecure")]
        public bool IsSecure { get; set; }

        [JsonPropertyName("steps")]
        public List<Step> Steps { get; set; } = new List<Step>();

        [JsonPropertyName("summary")]
        public string Summary { get; set; } = string.Empty;

        public void AddStep(string step, string message, bool success = true, string? code = null)
        {
            Steps.Add(new Step { Name = step, Message = message, Success = success, Code = code });
        }
    }

    public class Step
    {
        [JsonPropertyName("name")]
        public string Name { get; set; } = string.Empty;

        [JsonPropertyName("message")]
        public string Message { get; set; } = string.Empty;

        [JsonPropertyName("success")]
        public bool Success { get; set; }

        [JsonPropertyName("code")]
        public string? Code { get; set; }
    }
}