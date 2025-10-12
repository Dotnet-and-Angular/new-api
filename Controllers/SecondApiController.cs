using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
namespace MyFirstApi.Controllers;

using MyFirstApi.Models;

using Microsoft.AspNetCore.Authorization;

[ApiController]
[Route("api/[controller]")]
public class PersonController : ControllerBase
{
    private readonly AppDbContext _db;
    public PersonController(AppDbContext db) => _db = db;

    // GET /api/person/info
    [HttpGet("info")]
    public ActionResult GetInfo()
    {
        return Ok(new { Message = "Hello from PersonApi", Timestamp = DateTime.UtcNow });
    }

    [HttpPost("create")]
    public async Task<ActionResult<Person>> Create(Person person)
    {
        Console.WriteLine($"Creating person: {person}");
        _db.People.Add(person);
        await _db.SaveChangesAsync();
        return CreatedAtAction(nameof(GetById), new { id = person.Id }, person);
    }

    [Authorize]
    [HttpGet("{id}")]
    public async Task<ActionResult<Person>> GetById(int id)
    {
        var p = await _db.People.FindAsync(id);
        return p is null ? NotFound() : Ok(p);
    }

    [Authorize]
    [HttpGet("all")]
    public async Task<ActionResult<Person>> GetAll()
    {
        var p = await _db.People.ToListAsync();
        return p is null ? NotFound() : Ok(p);
    }
}
