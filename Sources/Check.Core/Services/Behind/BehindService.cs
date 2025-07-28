using Check.Core.Models.Receive;
using Check.Core.Services.CheckConnection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System.Collections.Concurrent;

namespace Check.Core.Services.Behind;

public class BehindService : BackgroundService
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ILogger<BehindService> _logger;
    private readonly ConcurrentQueue<ProtocolData> _queue = new();

    public BehindService(IServiceScopeFactory scopeFactory, ILogger<BehindService> logger)
    {
        _scopeFactory = scopeFactory ?? throw new ArgumentNullException(nameof(scopeFactory));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public void Enqueue(ProtocolData data)
    {
        _logger.LogInformation("Enqueuing protocol data: {Link}", data.Link);
        _queue.Enqueue(data);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("Starting background service.");
        while (!stoppingToken.IsCancellationRequested)
        {
            if (_queue.TryDequeue(out var data))
            {
                try
                {
                    _logger.LogInformation("Processing protocol data: {Link}", data.Link);
                    using var scope = _scopeFactory.CreateScope();
                    var reviewService = scope.ServiceProvider.GetRequiredService<IConnectionReview>();
                    await reviewService.AnalyzeAsync(data);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Failed to process protocol data: {Link}", data.Link);
                }
            }
            await Task.Delay(100, stoppingToken);
        }
        _logger.LogInformation("Background service stopped.");
    }
}