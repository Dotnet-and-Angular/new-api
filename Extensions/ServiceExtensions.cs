using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

namespace NewApi.Extensions;

/// <summary>
/// Registers application services: controllers, optional DB and optional JWT auth.
/// Keep registrations idempotent and conditional on configuration to make local/dev simpler.
/// </summary>
public static class ServiceExtensions
{
    /// <summary>
    /// Add controllers and optional infrastructure services (SQLite + JWT) based on configuration.
    /// </summary>
    public static IServiceCollection AddAppServices(this IServiceCollection services, IConfiguration configuration)
    {
        if (services is null) throw new ArgumentNullException(nameof(services));
        if (configuration is null) throw new ArgumentNullException(nameof(configuration));

        // MVC controllers
        services.AddControllers();

        // Database (SQLite) - register only when connection string is present
        AddSqliteIfConfigured(services, configuration);

        // JWT authentication - register only when Jwt:Key is provided
        AddJwtAuthenticationIfConfigured(services, configuration);

        // Always add authorization services
        services.AddAuthorization();

        return services;
    }

    private static void AddSqliteIfConfigured(IServiceCollection services, IConfiguration configuration)
    {
        var conn = configuration.GetConnectionString("DefaultConnection");
        if (string.IsNullOrWhiteSpace(conn)) return;

        // Use SQLite for simple local development. Migrations or EnsureCreated may be used at startup.
        services.AddDbContext<AppDbContext>(options => options.UseSqlite(conn));
    }

    private static void AddJwtAuthenticationIfConfigured(IServiceCollection services, IConfiguration configuration)
    {
        var jwt = configuration.GetSection("Jwt");
        var jwtKey = jwt["Key"];
        if (string.IsNullOrWhiteSpace(jwtKey)) return;

        var key = Encoding.UTF8.GetBytes(jwtKey);

        services.AddAuthentication(options =>
        {
            options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
        })
        .AddJwtBearer(options =>
        {
            // For local development we allow HTTP; enforce HTTPS in production.
            options.RequireHttpsMetadata = false;
            options.SaveToken = false;
            options.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateIssuer = !string.IsNullOrEmpty(jwt["Issuer"]),
                ValidIssuer = jwt["Issuer"],
                ValidateAudience = !string.IsNullOrEmpty(jwt["Audience"]),
                ValidAudience = jwt["Audience"],
                ValidateLifetime = true,
                ClockSkew = TimeSpan.FromSeconds(30)
            };
        });
    }
}
