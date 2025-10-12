using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.Collections.Concurrent;

namespace MyFirstApi.Controllers;

[ApiController]
[Route("api/auth")]
public class OtpAuthController : ControllerBase
{
    private static readonly ConcurrentDictionary<string, (string Code, DateTime ExpiresAt)> _otpStore = new();
    private readonly IConfiguration _config;

    public OtpAuthController(IConfiguration config) => _config = config;

    // Sends an OTP to the provided phone number (demo: returns 200 and logs OTP)
    [HttpPost("send-otp")]
    [Microsoft.AspNetCore.Authorization.AllowAnonymous]
    public ActionResult SendOtp([FromBody] OtpRequest request)
    {
        if (request == null || string.IsNullOrWhiteSpace(request.Phone))
            return BadRequest(new { error = "Phone is required" });

        // Generate a 6-digit OTP
        var rnd = new Random();
        var code = rnd.Next(100000, 999999).ToString();
        var expires = DateTime.UtcNow.AddMinutes(5);

        _otpStore.AddOrUpdate(request.Phone, (code, expires), (k, v) => (code, expires));

        // In real app: send SMS via provider (Twilio, etc.). Here we log it for demo.
        Console.WriteLine($"[OTP] Phone={request.Phone} Code={code} ExpiresAt={expires:O}");

        return Ok(new { message = "OTP sent (demo). Check server logs for the code." });
    }

    // Verifies the OTP and issues a JWT token on success
    [HttpPost("verify-otp")]
    [Microsoft.AspNetCore.Authorization.AllowAnonymous]
    public ActionResult VerifyOtp([FromBody] OtpVerifyRequest request)
    {
        if (request == null || string.IsNullOrWhiteSpace(request.Phone) || string.IsNullOrWhiteSpace(request.Code))
            return BadRequest(new { error = "Phone and Code are required" });

        if (!_otpStore.TryGetValue(request.Phone, out var entry))
            return Unauthorized(new { error = "Invalid or expired code" });

        if (entry.ExpiresAt < DateTime.UtcNow)
        {
            _otpStore.TryRemove(request.Phone, out _);
            return Unauthorized(new { error = "Code expired" });
        }

        if (!string.Equals(entry.Code, request.Code, StringComparison.Ordinal))
            return Unauthorized(new { error = "Invalid code" });

        // Remove used OTP
        _otpStore.TryRemove(request.Phone, out _);

        // Issue JWT token (reuse Jwt section)
        var jwtSection = _config.GetSection("Jwt");
        var keyText = jwtSection["Key"] ?? throw new InvalidOperationException("JWT Key is missing in configuration.");
        var key = Encoding.UTF8.GetBytes(keyText);

        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, request.Phone),
            new Claim(ClaimTypes.Name, request.Phone),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };

        var token = new JwtSecurityToken(
            issuer: jwtSection["Issuer"],
            audience: jwtSection["Audience"],
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(int.Parse(jwtSection["ExpireMinutes"] ?? "60")),
            signingCredentials: new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256)
        );

        var tokenString = new JwtSecurityTokenHandler().WriteToken(token);
        return Ok(new { token = tokenString });
    }
}

public record OtpRequest(string Phone);
public record OtpVerifyRequest(string Phone, string Code);
