using System.Text;

using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

using Serilog;

DotNetEnv.Env.Load();

// 1. Initialize Logger Early
Log.Logger = new LoggerConfiguration()
        .MinimumLevel.Debug()
        .WriteTo.Console()
        .WriteTo.File("Logs/log.txt", rollingInterval: RollingInterval.Day)
        .CreateLogger();

try
{
    var appName = Environment.GetEnvironmentVariable("APP_NAME");
    Log.Information($"Starting up {appName} Web API Engine...");

    var builder = WebApplication.CreateBuilder(args);

    // Enable Serilog instead of default Logger
    builder.Host.UseSerilog();

    // Bind mail environment vars to MailSettings class
    builder.Services.Configure<MailSettings>(builder.Configuration.GetSection("MailSettings"));

    // Register MailService
    builder.Services.AddTransient<IMailService, DefaultMailService>();

    // Read environment variables for JWT auth
    // TODO: Ensure JWT_SECRET_KEY is at least 32 characters long in your local .env or production environment.
    var secretKey = Environment.GetEnvironmentVariable("JWT_SECRET_KEY")
        ?? throw new InvalidOperationException("Critical Failure: JWT_SECRET_KEY environment variable is not set.");
    var issuer = Environment.GetEnvironmentVariable("JWT_ISSUER") ?? $"{appName}DefaultIssuer";
    var audience = Environment.GetEnvironmentVariable("JWT_AUDIENCE") ?? $"{appName}DefaultAudience";

    // Register JWT Authentication
    builder.Services.AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    })
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = issuer,
            ValidAudience = audience,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey)),
            ClockSkew = TimeSpan.Zero
        };
    });

    // Build DB Connection String
    // TODO: Modify these variables to inject your production database credentials or switch to a full connection string.
    var dbHost = "localhost";
    var dbPort = "5432";
    var dbName = Environment.GetEnvironmentVariable("DB_NAME") ?? "enterprisedb";
    var dbUser = Environment.GetEnvironmentVariable("DB_USER") ?? "devuser";
    var dbPass = Environment.GetEnvironmentVariable("DB_PASSWORD") ?? "devpassword";

    var connectionString = $"Host={dbHost};Port={dbPort};Database={dbName};Username={dbUser};Password={dbPass}";

    builder.Services.AddDbContext<DefaultDbContext>(options => options.UseNpgsql(connectionString));
    builder.Services.AddControllers();
    builder.Services.AddOpenApi();

    // Register the custom Global Exception Handler
    builder.Services.AddExceptionHandler<GlobalExceptionHandler>();
    builder.Services.AddProblemDetails();

    var app = builder.Build();

    // Clean up internal HTTP logging noise
    app.UseSerilogRequestLogging();

    // Maps the IExceptionHandler middleware into the pipeline
    app.UseExceptionHandler();

    if (app.Environment.IsDevelopment())
    {
        app.MapOpenApi();
    }

    app.UseHttpsRedirection();
    app.UseAuthentication();
    app.UseAuthorization();
    app.MapControllers();

    app.Run();
}
catch (Exception ex)
{
    Log.Fatal(ex, "The application host terminated unexpectedly during initialization.");
}
finally
{
    // Forces Serilog to dump remaining memory streams to disk before app dies
    Log.CloseAndFlush();
}