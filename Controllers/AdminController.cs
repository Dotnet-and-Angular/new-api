using System.Security.Cryptography;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using nexus_bank.models;

namespace nexus_bank.Controllers;

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
        if (request == null || string.IsNullOrWhiteSpace(request.Username) || string.IsNullOrWhiteSpace(request.Email) || string.IsNullOrWhiteSpace(request.Password))
            return BadRequest(new { message = "Username, email, and password are required" });

        // Check if admin already exists
        var existingAdmin = await _db.Admins.FirstOrDefaultAsync(a => a.Username == request.Username || a.Email == request.Email);
        if (existingAdmin != null)
            return BadRequest(new { message = "Username or email already exists" });

        // Generate salt and hash password
        var (hash, salt) = HashPassword(request.Password);

        var admin = new Admin
        {
            Username = request.Username,
            Email = request.Email,
            PasswordHash = hash,
            PasswordSalt = salt
        };

        _db.Admins.Add(admin);
        await _db.SaveChangesAsync();

        return CreatedAtAction(nameof(GetAdminById), new { id = admin.Id }, new { id = admin.Id, username = admin.Username, email = admin.Email });
    }

    [Authorize]
    [HttpGet("get-admin/{id}")]
    public async Task<ActionResult<Admin>> GetAdminById(int id)
    {
        var admin = await _db.Admins.FindAsync(id);
        if (admin == null)
            return NotFound(new { message = "Admin not found" });

        return Ok(new { id = admin.Id, username = admin.Username, email = admin.Email });
    }

    [Authorize]
    [HttpGet("list-all-admins")]
    public async Task<ActionResult<IEnumerable<Admin>>> ListAllAdmins()
    {
        var admins = await _db.Admins.Select(a => new { id = a.Id, username = a.Username, email = a.Email }).ToListAsync();
        return Ok(admins);
    }

    [Authorize]
    [HttpGet("search-admin")]
    public async Task<ActionResult> SearchAdmin([FromQuery] string username)
    {
        if (string.IsNullOrWhiteSpace(username))
            return BadRequest(new { message = "Username is required" });

        var admin = await _db.Admins.FirstOrDefaultAsync(a => a.Username == username);
        if (admin is null)
            return NotFound(new { message = "Admin not found" });
        return Ok(new { id = admin.Id, username = admin.Username, email = admin.Email });
    }

    [Authorize]
    [HttpDelete("delete-admin/{id}")]
    public async Task<ActionResult> DeleteAdmin(int id)
    {
        var admin = await _db.Admins.FindAsync(id);
        if (admin is null)
            return NotFound(new { message = "Admin not found" });

        _db.Admins.Remove(admin);
        await _db.SaveChangesAsync();
        return Ok(new { message = "Admin deleted successfully" });
    }

    [Authorize]
    [HttpPut("update-admin/{id}")]
    public async Task<ActionResult> UpdateAdmin(int id, [FromBody] UpdateAdminRequest request)
    {
        if (request == null)
            return BadRequest(new { message = "Request body is required" });

        var admin = await _db.Admins.FindAsync(id);
        if (admin is null)
            return NotFound(new { message = "Admin not found" });

        if (!string.IsNullOrWhiteSpace(request.Username))
        {
            var existingAdmin = await _db.Admins.FirstOrDefaultAsync(a => a.Username == request.Username && a.Id != id);
            if (existingAdmin != null)
                return BadRequest(new { message = "Username already exists" });
            admin.Username = request.Username;
        }

        if (!string.IsNullOrWhiteSpace(request.Email))
        {
            var existingEmail = await _db.Admins.FirstOrDefaultAsync(a => a.Email == request.Email && a.Id != id);
            if (existingEmail != null)
                return BadRequest(new { message = "Email already exists" });
            admin.Email = request.Email;
        }

        _db.Admins.Update(admin);
        await _db.SaveChangesAsync();
        return Ok(new { message = "Admin updated successfully", admin = new { id = admin.Id, username = admin.Username, email = admin.Email } });
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
    public string Email { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
}

public class UpdateAdminRequest
{
    public string? Username { get; set; }
    public string? Email { get; set; }
}
