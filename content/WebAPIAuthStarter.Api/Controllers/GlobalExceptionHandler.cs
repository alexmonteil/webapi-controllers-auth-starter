using Microsoft.AspNetCore.Diagnostics;

public class GlobalExceptionHandler : IExceptionHandler
{
    private readonly ILogger<GlobalExceptionHandler> _logger;

    public GlobalExceptionHandler(ILogger<GlobalExceptionHandler> logger)
    {
        _logger = logger;
    }

    public async ValueTask<bool> TryHandleAsync(
        HttpContext httpContext,
        Exception exception,
        CancellationToken cancellationToken)
    {
        // Log the actual exception details internally
        _logger.LogError(exception, "An unhandled exception occurred: {Message}", exception.Message);

        // Return a clean, safe response to the client
        var response = new OperationStatusResponse(false, "An unexpected error occurred. Please try again later.");
        httpContext.Response.StatusCode = StatusCodes.Status500InternalServerError;
        await httpContext.Response.WriteAsJsonAsync(response, cancellationToken);

        return true; // Indicates the exception was successfully handled
    }
}