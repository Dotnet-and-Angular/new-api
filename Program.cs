
using nexus_bank.Extensions;
using nexus_bank.Middleware;

var builder = WebApplication.CreateBuilder(args);

// Register application services (controllers, authentication, db)
builder.Services.AddAppServices(builder.Configuration);


// Add a CORS policy for development that allows credentials and echoes origin
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowLocalDev", policy =>
    {
        policy.WithOrigins("http://localhost:4200")
              .AllowAnyMethod()
              .AllowAnyHeader()
              .AllowCredentials();
    });
});
var app = builder.Build();

// Ensure the database file and schema exist. This is fine for local dev.
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    db.Database.EnsureCreated();
}

// --- Middleware pipeline ---
app.UseHttpsRedirection();

app.UseCors("AllowLocalDev");
// Routing must be enabled so endpoint metadata is available to middleware
app.UseRouting();
// Use the API key middleware (skips token issuance / AllowAnonymous endpoints)
app.UseApiKeyMiddleware();


app.UseAuthentication();
app.UseAuthorization();

// Map controllers
app.MapControllers();
app.Run();
