using Microsoft.AspNetCore.Authorization;

namespace NewApi.Middleware;

public class ApiKeyMiddleware
{
    private readonly RequestDelegate _next;
    private readonly IConfiguration _configuration;

    public ApiKeyMiddleware(RequestDelegate next, IConfiguration configuration)
    {
        _next = next ?? throw new ArgumentNullException(nameof(next));
        _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
    }

    public async Task InvokeAsync(HttpContext context)
    {
        // Skip if endpoint allows anonymous access
        var endpoint = context.GetEndpoint();
        if (endpoint?.Metadata?.GetMetadata<AllowAnonymousAttribute>() != null)
        {
            await _next(context);
            return;
        }

        // Allow auth endpoints (token, send-otp, verify-otp) and admin register to be called without an API key
        if (context.Request.Path.StartsWithSegments("/api/auth", StringComparison.OrdinalIgnoreCase) ||
            context.Request.Path.StartsWithSegments("/api/admin/register", StringComparison.OrdinalIgnoreCase))
        {
            await _next(context);
            return;
        }

        // If an Authorization: Bearer <token> header exists, skip API key check (JWT will be validated elsewhere)
        var authHeader = context.Request.Headers["Authorization"].FirstOrDefault();
        if (!string.IsNullOrEmpty(authHeader) && authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            await _next(context);
            return;
        }

        // If no ApiKey configured, don't enforce (useful for local/dev)
        var configuredKey = _configuration["ApiKey"];
        if (string.IsNullOrEmpty(configuredKey))
        {
            await _next(context);
            return;
        }

        // Validate X-API-KEY header
        var providedKey = context.Request.Headers["X-API-KEY"].FirstOrDefault();
        if (string.IsNullOrEmpty(providedKey) || !string.Equals(providedKey, configuredKey, StringComparison.Ordinal))
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            await context.Response.WriteAsync("API Key missing or invalid.");
            return;
        }

        await _next(context);
    }
}

public static class ApiKeyMiddlewareExtensions
{
    public static IApplicationBuilder UseApiKeyMiddleware(this IApplicationBuilder builder)
    {
        return builder.UseMiddleware<ApiKeyMiddleware>();
    }
}
