using Microsoft.EntityFrameworkCore;
using RBACApp.Models;

namespace RBACApp.Data;

public class AppDbContext : DbContext
{
    public DbSet<User> Users { get; set; } = null!;

    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }
}
