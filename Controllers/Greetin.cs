using Microsoft.AspNetCore.Mvc;

namespace MyFirstApi.Controllers;

[ApiController]
[Route("api/[controller]")]
public class FirstApiController : ControllerBase
{
    // GET /api/firstapi/{id}
    [HttpGet("{id}")]
    public ActionResult GetById(int id)
    {
        // demo: return a sample person or fetch from DB
        return Ok(new { Id = id, Name = "Demo", Age = 30, Email = "demo@example.com" });
    }

    // GET /api/firstapi/all
    [HttpGet("all")]
    public ActionResult GetAll()
    {
        var items = new[] {
            new { Id = 1, Name = "Alice", Age = 28, Email = "alice@example.com" },
            new { Id = 2, Name = "Bob", Age = 34, Email = "bob@example.com" },
        };
        return Ok(items);
    }
}
