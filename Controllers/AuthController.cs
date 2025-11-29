using System.Collections.Concurrent;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using nexus_bank.models;

namespace nexus_bank.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly IConfiguration _config;
    private readonly AppDbContext _db;
    private static readonly ConcurrentDictionary<string, (string Code, DateTime ExpiresAt)> _otpStore = new();

    public AuthController(IConfiguration config, AppDbContext db)
    {
        _config = config;
        _db = db;
    }

    [AllowAnonymous]
    [HttpPost("register")]
    public async Task<ActionResult> Register([FromBody] RegisterRequest request)
    {
        if (request == null || string.IsNullOrWhiteSpace(request.UsernameOrEmail) ||
            string.IsNullOrWhiteSpace(request.Password) || string.IsNullOrWhiteSpace(request.Role))
            return BadRequest(new { message = "Username/Email, password, and role are required" });

        if (request.Role != "admin" && request.Role != "user")
            return BadRequest(new { message = "Role must be 'admin' or 'user'" });

        var (hash, salt) = HashPassword(request.Password);

        if (request.Role == "user")
        {
            var existingUser = await _db.Users.FirstOrDefaultAsync(u =>
                u.Username == request.UsernameOrEmail || u.Email == request.UsernameOrEmail);
            if (existingUser != null)
                return BadRequest(new { message = "Username or email already exists" });

            var user = new User
            {
                Username = request.UsernameOrEmail,
                Email = request.UsernameOrEmail,
                PasswordHash = hash,
                PasswordSalt = salt
            };

            _db.Users.Add(user);
            await _db.SaveChangesAsync();
            return Ok(new { message = "User registered successfully", userId = user.Id });
        }
        else
        {
            var existingAdmin = await _db.Admins.FirstOrDefaultAsync(a =>
                a.Username == request.UsernameOrEmail || a.Email == request.UsernameOrEmail);
            if (existingAdmin != null)
                return BadRequest(new { message = "Username or email already exists" });

            var admin = new Admin
            {
                Username = request.UsernameOrEmail,
                Email = request.UsernameOrEmail,
                PasswordHash = hash,
                PasswordSalt = salt
            };

            _db.Admins.Add(admin);
            await _db.SaveChangesAsync();
            return Ok(new { message = "Admin registered successfully", adminId = admin.Id });
        }
    }

    [AllowAnonymous]
    [HttpPost("login")]
    public async Task<ActionResult> Login([FromBody] LoginRequest request)
    {
        if (request == null || string.IsNullOrWhiteSpace(request.UsernameOrEmail) ||
            string.IsNullOrWhiteSpace(request.Password) || string.IsNullOrWhiteSpace(request.Role))
            return Unauthorized(new { message = "Invalid credentials" });

        if (request.Role == "user")
        {
            var user = await _db.Users.FirstOrDefaultAsync(u =>
                u.Username == request.UsernameOrEmail || u.Email == request.UsernameOrEmail);
            if (user == null || !VerifyPassword(request.Password, user.PasswordHash, user.PasswordSalt))
                return Unauthorized(new { message = "Invalid credentials" });

            var token = GenerateJwtToken(user.Username, "user");
            var profile = new { id = user.Id, username = user.Username, email = user.Email };
            return Ok(new { token, role = "user", profile });
        }
        else
        {
            var admin = await _db.Admins.FirstOrDefaultAsync(a =>
                a.Username == request.UsernameOrEmail || a.Email == request.UsernameOrEmail);
            if (admin == null || !VerifyPassword(request.Password, admin.PasswordHash, admin.PasswordSalt))
                return Unauthorized(new { message = "Invalid credentials" });

            var token = GenerateJwtToken(admin.Username, "admin");
            var profile = new { id = admin.Id, username = admin.Username, email = admin.Email };
            return Ok(new { token, role = "admin", profile });
        }
    }

    [AllowAnonymous]
    [HttpPost("send-otp")]
    public ActionResult SendOtp([FromBody] SendOtpRequest request)
    {
        if (request == null || string.IsNullOrWhiteSpace(request.UsernameOrEmail))
            return BadRequest(new { message = "Username or Email is required" });

        // Generate a 6-digit OTP
        var rnd = new Random();
        var code = rnd.Next(100000, 999999).ToString();
        var expires = DateTime.UtcNow.AddMinutes(5);

        _otpStore.AddOrUpdate(request.UsernameOrEmail, (code, expires), (k, v) => (code, expires));

        Console.WriteLine($"[OTP] UsernameOrEmail={request.UsernameOrEmail} Code={code} ExpiresAt={expires:O}");

        return Ok(new { message = "OTP sent successfully. Check server logs for the code." });
    }

    [AllowAnonymous]
    [HttpPost("verify-otp")]
    public async Task<ActionResult> VerifyOtp([FromBody] VerifyOtpRequest request)
    {
        if (request == null || string.IsNullOrWhiteSpace(request.UsernameOrEmail) ||
            string.IsNullOrWhiteSpace(request.Code) || string.IsNullOrWhiteSpace(request.Role))
            return BadRequest(new { message = "UsernameOrEmail, Code, and Role are required" });

        if (!_otpStore.TryGetValue(request.UsernameOrEmail, out var entry))
            return Unauthorized(new { message = "Invalid or expired OTP" });

        if (entry.ExpiresAt < DateTime.UtcNow)
        {
            _otpStore.TryRemove(request.UsernameOrEmail, out _);
            return Unauthorized(new { message = "OTP expired" });
        }

        if (!string.Equals(entry.Code, request.Code, StringComparison.Ordinal))
            return Unauthorized(new { message = "Invalid OTP" });

        // Remove used OTP
        _otpStore.TryRemove(request.UsernameOrEmail, out _);

        // Auto-register user/admin if doesn't exist and generate token
        if (request.Role == "user")
        {
            var user = await _db.Users.FirstOrDefaultAsync(u =>
                u.Username == request.UsernameOrEmail || u.Email == request.UsernameOrEmail);

            bool isNewUser = false;
            if (user == null)
            {
                // Auto-register new user with OTP-based temporary password
                var (hash, salt) = HashPassword(Guid.NewGuid().ToString());
                user = new User
                {
                    Username = request.UsernameOrEmail,
                    Email = request.UsernameOrEmail,
                    PasswordHash = hash,
                    PasswordSalt = salt
                };
                _db.Users.Add(user);
                await _db.SaveChangesAsync();
                isNewUser = true;
            }

            var token = GenerateJwtToken(user.Username, "user");
            var profile = new { id = user.Id, username = user.Username, email = user.Email };
            return Ok(new { token, role = "user", isNewUser, profile });
        }
        else
        {
            var admin = await _db.Admins.FirstOrDefaultAsync(a =>
                a.Username == request.UsernameOrEmail || a.Email == request.UsernameOrEmail);

            bool isNewUser = false;
            if (admin == null)
            {
                // Auto-register new admin with OTP-based temporary password
                var (hash, salt) = HashPassword(Guid.NewGuid().ToString());
                admin = new Admin
                {
                    Username = request.UsernameOrEmail,
                    Email = request.UsernameOrEmail,
                    PasswordHash = hash,
                    PasswordSalt = salt
                };
                _db.Admins.Add(admin);
                await _db.SaveChangesAsync();
                isNewUser = true;
            }

            var token = GenerateJwtToken(admin.Username, "admin");
            var profile = new { id = admin.Id, username = admin.Username, email = admin.Email };
            return Ok(new { token, role = "admin", isNewUser, profile });
        }
    }

    private string GenerateJwtToken(string username, string role)
    {
        var jwtSection = _config.GetSection("Jwt");
        var key = Encoding.UTF8.GetBytes(jwtSection["Key"] ??
            throw new InvalidOperationException("JWT Key is missing in configuration."));

        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, username),
            new Claim(ClaimTypes.Name, username),
            new Claim(ClaimTypes.Role, role),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };

        var token = new JwtSecurityToken(
            issuer: jwtSection["Issuer"],
            audience: jwtSection["Audience"],
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(int.Parse(jwtSection["ExpireMinutes"] ?? "60")),
            signingCredentials: new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256)
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private bool VerifyPassword(string password, string hash, string salt)
    {
        var saltBytes = Convert.FromBase64String(salt);
        var hashBytes = Convert.FromBase64String(hash);
        var derivedBytes = Rfc2898DeriveBytes.Pbkdf2(password, saltBytes, 10000, HashAlgorithmName.SHA256, 32);
        return CryptographicOperations.FixedTimeEquals(derivedBytes, hashBytes);
    }

    private (string hash, string salt) HashPassword(string password)
    {
        var saltBytes = new byte[16];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(saltBytes);
        }

        var hashBytes = Rfc2898DeriveBytes.Pbkdf2(password, saltBytes, 10000, HashAlgorithmName.SHA256, 32);
        return (Convert.ToBase64String(hashBytes), Convert.ToBase64String(saltBytes));
    }
}

public class RegisterRequest
{
    public string UsernameOrEmail { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public string Role { get; set; } = string.Empty; // "user" or "admin"
}

public class LoginRequest
{
    public string UsernameOrEmail { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public string Role { get; set; } = string.Empty; // "user" or "admin"
}

public class SendOtpRequest
{
    public string UsernameOrEmail { get; set; } = string.Empty;
}

public class VerifyOtpRequest
{
    public string UsernameOrEmail { get; set; } = string.Empty;
    public string Code { get; set; } = string.Empty;
    public string Role { get; set; } = string.Empty; // "user" or "admin"
}
