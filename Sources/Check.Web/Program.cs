using System.Text.Json;
using System.Text.Json.Serialization;
using Check.Core.Services.Behind;
using Check.Core.Services.CheckConnection;
using Check.Core.Services.Protocol;
using Check.Web.Utilities.Routes;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc.ApplicationModels;
using Microsoft.Extensions.Options;
using Microsoft.OpenApi.Models;

var builder = WebApplication.CreateBuilder(args);
{


    // Add services to the container.

    builder.Services.AddControllers(opt =>
    {
        opt.Conventions.Add(new RouteTokenTransformerConvention(new LowercaseTransformer()));
    }).AddJsonOptions(options =>
    {
        options.JsonSerializerOptions.PropertyNamingPolicy = JsonNamingPolicy.CamelCase;
        options.JsonSerializerOptions.WriteIndented = true;
        options.JsonSerializerOptions.DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull;
    });

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
    builder.Services.AddSwaggerGen(c =>
    {
        c.SwaggerDoc("v1", new OpenApiInfo { Title = "Connection Review API", Version = "v1" });
        c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
        {
            Type = SecuritySchemeType.Http,
            Scheme = "bearer",
            BearerFormat = "JWT"
        });
    });

    builder.Services.AddHttpClient(); // Register IHttpClientFactory
    builder.Services.AddMemoryCache();



    // Register services as Singleton
    builder.Services.AddScoped<IConnectionReview, ConnectionReview>();
    builder.Services.AddScoped<VlessProtocolParser>();
    builder.Services.AddScoped<VmessProtocolParser>();
    builder.Services.AddScoped<TrojanProtocolParser>();
    builder.Services.AddScoped<ShadowsocksProtocolParser>();
    builder.Services.AddScoped<Http2ProtocolParser>();
    builder.Services.AddScoped<Socks5ProtocolParser>();
    builder.Services.AddScoped<WireguardProtocolParser>();
    builder.Services.AddScoped<HysteriaProtocolParser>();

    // Register BehindService explicitly
    builder.Services.AddSingleton<BehindService>();
    builder.Services.AddHostedService<BehindService>(provider => provider.GetRequiredService<BehindService>());





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

    app.UseExceptionHandler(errorApp =>
    {
        errorApp.Run(async context =>
        {
            var error = context.Features.Get<IExceptionHandlerFeature>();
            if (error != null)
            {
                context.Response.StatusCode = 500;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(JsonSerializer.Serialize(new
                {
                    error = "An unexpected error occurred.",
                    detail = error.Error.Message
                }));
            }
        });
    });



    app.UseHttpsRedirection();
    app.UseRouting();


    app.UseAuthentication();
    app.UseAuthorization();


    app.MapControllers();


}
app.Run();
