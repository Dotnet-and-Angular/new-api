using Microsoft.EntityFrameworkCore;
using MyFirstApi.Models;


public class AppDbContext : DbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

    public DbSet<Person> People => Set<Person>();
    public DbSet<Admin> Admins => Set<Admin>();
}