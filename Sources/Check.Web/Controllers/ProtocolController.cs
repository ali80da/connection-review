using Check.Core.Models.Common;
using Check.Core.Models.Receive;
using Check.Core.Services.Behind;
using Check.Core.Services.CheckConnection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Check.Web.Controllers;

public class ProtocolController : SharedController
{

    private readonly IConnectionReview ReviewService;
    private readonly BehindService BehindService;
    private readonly ILogger<ProtocolController> Logger;

    public ProtocolController(IConnectionReview ReviewService, BehindService BehindService, ILogger<ProtocolController> Logger)
    {
        this.ReviewService = ReviewService ?? throw new ArgumentNullException(nameof(ReviewService));
        this.BehindService = BehindService ?? throw new ArgumentNullException(nameof(BehindService));
        this.Logger = Logger ?? throw new ArgumentNullException(nameof(Logger));
    }




    /// <summary>
    /// Analyzes a network protocol link and returns the connection status.
    /// </summary>
    /// <param name="data">The protocol link and optional protocol type.</param>
    /// <returns>A ResultStatus object containing analysis results.</returns>
    /// <response code="200">Analysis completed successfully.</response>
    /// <response code="400">Invalid input data.</response>
    [HttpPost("review-time")]
    public async Task<ActionResult<ResultStatus>> Analyze([FromBody] ProtocolData data)
    {
        //if (data is null || string.IsNullOrWhiteSpace(data.Link))
        //    return BadRequest(new ResultStatus { Steps = new() { ("Input Validation", "Link is required.", false) } });

        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        Logger.LogInformation("Received review-time request for link: {Link}", data.Link);

        var result = await ReviewService.AnalyzeAsync(data);
        BehindService.Enqueue(data); // Optionally enqueue for background processing
        return result.Success ? Ok(result) : BadRequest(result);
    }





}