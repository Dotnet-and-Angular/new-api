using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using MyFirstApi.Models;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly IConfiguration _config;
    private readonly AppDbContext _db;

    public AuthController(IConfiguration config, AppDbContext db)
    {
        _config = config;
        _db = db;
    }

    [HttpPost("token")]
    [Microsoft.AspNetCore.Authorization.AllowAnonymous]
    public async Task<ActionResult> GetToken([FromBody] LoginModel login)
    {
        if (login == null || string.IsNullOrWhiteSpace(login.Username) || string.IsNullOrWhiteSpace(login.Password))
            return Unauthorized(new { message = "Invalid username or password" });

        // Find admin in database
        var admin = await _db.Admins.FirstOrDefaultAsync(a => a.Username == login.Username);
        if (admin == null)
            return Unauthorized(new { message = "Invalid username or password" });

        // Verify password using PBKDF2
        if (!VerifyPassword(login.Password, admin.PasswordHash, admin.PasswordSalt))
            return Unauthorized(new { message = "Invalid username or password" });

        var jwtSection = _config.GetSection("Jwt");
        var key = Encoding.UTF8.GetBytes(jwtSection["Key"] ?? throw new InvalidOperationException("JWT Key is missing in configuration."));
        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, login.Username),
            new Claim(ClaimTypes.Name, login.Username),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };

        var token = new JwtSecurityToken(
            issuer: jwtSection["Issuer"],
            audience: jwtSection["Audience"],
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(int.Parse(jwtSection["ExpireMinutes"] ?? "60")),
            signingCredentials: new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256)
        );

        return Ok(new { token = new JwtSecurityTokenHandler().WriteToken(token) });
    }

    private bool VerifyPassword(string password, string hash, string salt)
    {
        var saltBytes = Convert.FromBase64String(salt);
        var hashBytes = Convert.FromBase64String(hash);
        var derivedBytes = Rfc2898DeriveBytes.Pbkdf2(password, saltBytes, 10000, HashAlgorithmName.SHA256, 32);
        return CryptographicOperations.FixedTimeEquals(derivedBytes, hashBytes);
    }
}