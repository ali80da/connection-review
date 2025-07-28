using System.Text.RegularExpressions;

namespace Check.Web.Utilities.Routes;

public class LowercaseTransformer : IOutboundParameterTransformer
{

    /// <inheritdoc/>
    public string? TransformOutbound(object? value)
    {
        if (value == null) return null;
        return Regex.Replace(value.ToString()!, "([a-z])([A-Z])", "$1-$2").ToLower();
    }

}