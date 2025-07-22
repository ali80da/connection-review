using Check.Core.Models.Common;
using Check.Core.Models.Receive;
using Check.Core.Services.CheckConnection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Check.Web.Controllers;

public class ProtocolController : SharedController
{

    private readonly IConnectionReview Review;
    public ProtocolController(IConnectionReview Review)
    {
        this.Review = Review;
    }



    [HttpPost("review-time")]
    public async Task<ActionResult<ResultStatus>> Analyze([FromBody] ProtocolData data)
    {
        var result = await Review.AnalyzeAsync(data);
        return Ok(result);
    }

}