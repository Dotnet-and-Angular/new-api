namespace MyFirstApi.Models;

public class Person
{
    public int Id { get; set; }
    public string? Name { get; set; }
    public int Age { get; set; }
    public string? Email { get; set; }
}

public class Admin
{
    public int Id { get; set; }
    public string Username { get; set; } = string.Empty;
    public string PasswordHash { get; set; } = string.Empty;
    public string PasswordSalt { get; set; } = string.Empty;
}