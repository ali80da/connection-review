using Check.Core.Models.Receive;
using Check.Core.Services.CheckConnection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;
using Check.Core.Configuration;
using Microsoft.Extensions.Hosting;

namespace Check.Core.Services.Behind;

public class BehindService : BackgroundService
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ILogger<BehindService> _logger;
    private readonly ConcurrentQueue<ProtocolData> _queue = new();
    private readonly SemaphoreSlim _semaphore;
    private readonly int _maxQueueSize;

    public BehindService(
        IServiceScopeFactory scopeFactory,
        ILogger<BehindService> logger,
        IOptions<AppSettings> appSettings)
    {
        _scopeFactory = scopeFactory ?? throw new ArgumentNullException(nameof(scopeFactory));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        var settings = appSettings?.Value ?? throw new ArgumentNullException(nameof(appSettings));
        _maxQueueSize = settings.MaxQueueSize;
        _semaphore = new SemaphoreSlim(settings.MaxConcurrentTests, settings.MaxConcurrentTests);
    }

    public bool Enqueue(ProtocolData data)
    {
        if (_queue.Count >= _maxQueueSize)
        {
            _logger.LogWarning("Queue is full. Dropping protocol data: {Link}", data.Link);
            return false;
        }

        _logger.LogInformation("Enqueuing protocol data: {Link}", data.Link);
        _queue.Enqueue(data);
        return true;
    }

    public int GetQueueSize() => _queue.Count;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("Starting background service.");
        while (!stoppingToken.IsCancellationRequested)
        {
            if (_queue.TryDequeue(out var data))
            {
                await _semaphore.WaitAsync(stoppingToken);
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
                finally
                {
                    _semaphore.Release();
                }
            }
            else
            {
                await Task.Delay(100, stoppingToken);
            }
        }
        _logger.LogInformation("Background service stopped.");
    }
}