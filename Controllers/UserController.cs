using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using nexus_bank.models;

namespace nexus_bank.Controllers;

[ApiController]
[Route("api/[controller]")]
public class UserController : ControllerBase
{
    private readonly AppDbContext _db;
    public UserController(AppDbContext db) => _db = db;

    [Authorize]
    [HttpPost("add-user")]
    public async Task<ActionResult<User>> AddUser([FromBody] CreateUserRequest request)
    {
        if (request == null || string.IsNullOrWhiteSpace(request.Username) || string.IsNullOrWhiteSpace(request.Email))
            return BadRequest(new { message = "Username and Email are required" });

        var existingUser = await _db.Users.FirstOrDefaultAsync(u => u.Username == request.Username || u.Email == request.Email);
        if (existingUser != null)
            return BadRequest(new { message = "Username or Email already exists" });

        var user = new User
        {
            Username = request.Username,
            Email = request.Email,
            PasswordHash = request.PasswordHash ?? string.Empty,
            PasswordSalt = request.PasswordSalt ?? string.Empty
        };

        _db.Users.Add(user);
        await _db.SaveChangesAsync();
        return CreatedAtAction(nameof(GetUserById), new { id = user.Id }, new { id = user.Id, username = user.Username, email = user.Email });
    }

    [Authorize]
    [HttpGet("get-user/{id}")]
    public async Task<ActionResult<User>> GetUserById(int id)
    {
        var user = await _db.Users.FindAsync(id);
        if (user is null)
            return NotFound(new { message = "User not found" });
        return Ok(new { id = user.Id, username = user.Username, email = user.Email });
    }

    [Authorize]
    [HttpGet("list-all-users")]
    public async Task<ActionResult<IEnumerable<User>>> ListAllUsers()
    {
        var users = await _db.Users.Select(u => new { id = u.Id, username = u.Username, email = u.Email }).ToListAsync();
        return Ok(users);
    }

    [Authorize]
    [HttpGet("search-user")]
    public async Task<ActionResult> SearchUser([FromQuery] string username)
    {
        if (string.IsNullOrWhiteSpace(username))
            return BadRequest(new { message = "Username is required" });

        var user = await _db.Users.FirstOrDefaultAsync(u => u.Username == username);
        if (user is null)
            return NotFound(new { message = "User not found" });
        return Ok(new { id = user.Id, username = user.Username, email = user.Email });
    }

    [Authorize]
    [HttpDelete("delete-user/{id}")]
    public async Task<ActionResult> DeleteUser(int id)
    {
        var user = await _db.Users.FindAsync(id);
        if (user is null)
            return NotFound(new { message = "User not found" });

        _db.Users.Remove(user);
        await _db.SaveChangesAsync();
        return Ok(new { message = "User deleted successfully" });
    }

    [Authorize]
    [HttpPut("update-user/{id}")]
    public async Task<ActionResult> UpdateUser(int id, [FromBody] UpdateUserRequest request)
    {
        if (request == null)
            return BadRequest(new { message = "Request body is required" });

        var user = await _db.Users.FindAsync(id);
        if (user is null)
            return NotFound(new { message = "User not found" });

        if (!string.IsNullOrWhiteSpace(request.Username))
        {
            var existingUser = await _db.Users.FirstOrDefaultAsync(u => u.Username == request.Username && u.Id != id);
            if (existingUser != null)
                return BadRequest(new { message = "Username already exists" });
            user.Username = request.Username;
        }

        if (!string.IsNullOrWhiteSpace(request.Email))
        {
            var existingEmail = await _db.Users.FirstOrDefaultAsync(u => u.Email == request.Email && u.Id != id);
            if (existingEmail != null)
                return BadRequest(new { message = "Email already exists" });
            user.Email = request.Email;
        }

        _db.Users.Update(user);
        await _db.SaveChangesAsync();
        return Ok(new { message = "User updated successfully", user = new { id = user.Id, username = user.Username, email = user.Email } });
    }
}

public class CreateUserRequest
{
    public string Username { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string? PasswordHash { get; set; }
    public string? PasswordSalt { get; set; }
}

public class UpdateUserRequest
{
    public string? Username { get; set; }
    public string? Email { get; set; }
}
