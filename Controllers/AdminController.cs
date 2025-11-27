using System.Security.Cryptography;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using MyFirstApi.Models;

[ApiController]
[Route("api/[controller]")]
public class AdminController : ControllerBase
{
    private readonly AppDbContext _db;

    public AdminController(AppDbContext db) => _db = db;

    [AllowAnonymous]
    [HttpPost("register")]
    public async Task<ActionResult<Admin>> Register([FromBody] RegisterAdminRequest request)
    {
        if (request == null || string.IsNullOrWhiteSpace(request.Username) || string.IsNullOrWhiteSpace(request.Password))
            return BadRequest(new { message = "Username and password are required" });

        // Check if admin already exists
        var existingAdmin = await _db.Admins.FirstOrDefaultAsync(a => a.Username == request.Username);
        if (existingAdmin != null)
            return BadRequest(new { message = "Username already exists" });

        // Generate salt and hash password
        var (hash, salt) = HashPassword(request.Password);

        var admin = new Admin
        {
            Username = request.Username,
            PasswordHash = hash,
            PasswordSalt = salt
        };

        _db.Admins.Add(admin);
        await _db.SaveChangesAsync();

        return CreatedAtAction(nameof(GetById), new { id = admin.Id }, new { admin.Id, admin.Username });
    }

    [Authorize]
    [HttpGet("{id}")]
    public async Task<ActionResult<Admin>> GetById(int id)
    {
        var admin = await _db.Admins.FindAsync(id);
        if (admin == null)
            return NotFound();

        return Ok(new { admin.Id, admin.Username });
    }

    private (string hash, string salt) HashPassword(string password)
    {
        // Generate a random salt
        var saltBytes = new byte[16];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(saltBytes);
        }

        // Derive the hash from the password and salt
        var hashBytes = Rfc2898DeriveBytes.Pbkdf2(password, saltBytes, 10000, HashAlgorithmName.SHA256, 32);

        // Return Base64-encoded hash and salt
        return (Convert.ToBase64String(hashBytes), Convert.ToBase64String(saltBytes));
    }
}

public class RegisterAdminRequest
{
    public string Username { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
}
