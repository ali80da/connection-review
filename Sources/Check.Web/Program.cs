using Check.Core.Services.CheckConnection;

var builder = WebApplication.CreateBuilder(args);
{


    // Add services to the container.

    builder.Services.AddControllers();
    // Learn more about configuring OpenAPI
    builder.Services.AddOpenApi(options =>
    {
        options.AddDocumentTransformer((document, context, cancellationToken) =>
        {
            document.Info = new()
            {
                Title = "",
                Version = "v1",
                Description = "API for Processing Check."
            };
            return Task.CompletedTask;
        });
    });

    builder.Services.AddEndpointsApiExplorer();
    builder.Services.AddSwaggerGen();

    builder.Services.AddHttpClient(); // Register IHttpClientFactory

    builder.Services.AddScoped<IConnectionReview, ConnectionReview>();



}
var app = builder.Build();
{

    // Configure the HTTP request pipeline.
    if (app.Environment.IsDevelopment())
    {
        app.MapOpenApi();

        app.UseSwagger();
        app.UseSwaggerUI();
    }

    app.UseHttpsRedirection();
    app.UseRouting();

    app.UseAuthentication();
    app.UseAuthorization();

    app.MapControllers();


}
app.Run();
