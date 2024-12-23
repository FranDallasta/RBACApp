using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using DotNetEnv;
using RBACApp.Data;
using RBACApp.Models;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;

// Load environment variables
Env.Load();

var builder = WebApplication.CreateBuilder(args);

// Configure services
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlServer(Environment.GetEnvironmentVariable("CONNECTION_STRING") ?? throw new InvalidOperationException("La cadena de conexión no está configurada.")));

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = Environment.GetEnvironmentVariable("JWT_ISSUER") ?? "YourIssuer",
        ValidAudience = Environment.GetEnvironmentVariable("JWT_AUDIENCE") ?? "YourAudience",
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Environment.GetEnvironmentVariable("JWT_SECRET") ?? throw new InvalidOperationException("La clave secreta JWT no está configurada.")))
    };

    // Setting up JwtBearer events
    options.Events = new JwtBearerEvents
    {
        OnMessageReceived = context =>
        {
            var token = context.Request.Headers["Authorization"].FirstOrDefault()?.Split(" ").Last();
            if (!string.IsNullOrEmpty(token))
            {
                Console.WriteLine($"Token received: {token}");
            }
            else
            {
                Console.WriteLine("No token was received in the request.");
            }
            return Task.CompletedTask;
        },
        OnAuthenticationFailed = context =>
        {
            Console.WriteLine($"Authentication failed: {context.Exception.Message}");
            return Task.CompletedTask;
        },
        OnTokenValidated = context =>
        {
            Console.WriteLine($"Token validated for the user: {context.Principal?.Identity?.Name}");
            return Task.CompletedTask;
        },
        OnChallenge = context =>
        {
            Console.WriteLine("An authentication challenge has been initiated.");
            return Task.CompletedTask;
        }
    };
});

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AdminOnly", policy => policy.RequireRole("Admin"));
    options.AddPolicy("UserOnly", policy => policy.RequireRole("User"));
});

var app = builder.Build();

// Seeding the database
using (var scope = app.Services.CreateScope())
{
    var dbContext = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    dbContext.Database.EnsureCreated();

    if (!dbContext.Users.Any())
    {
        dbContext.Users.AddRange(
            new User
            {
                Username = "admin",
                PasswordHash = BCrypt.Net.BCrypt.HashPassword("admin123"),
                Role = Roles.Admin
            },
            new User
            {
                Username = "user",
                PasswordHash = BCrypt.Net.BCrypt.HashPassword("user123"),
                Role = Roles.User
            });
        dbContext.SaveChanges();
    }
}

app.UseAuthentication();
app.UseAuthorization();


// Login Endpoint
app.MapPost("/login", async (AppDbContext dbContext, LoginRequest loginRequest) =>
{
    var user = await dbContext.Users.SingleOrDefaultAsync(u => u.Username == loginRequest.Username);
    if (user == null || !BCrypt.Net.BCrypt.Verify(loginRequest.Password, user.PasswordHash))
        return Results.Unauthorized();

    var claims = new[]
    {
        new Claim(ClaimTypes.Name, user.Username),
        new Claim(ClaimTypes.Role, user.Role.ToString())
    };

    var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Environment.GetEnvironmentVariable("JWT_SECRET") ?? throw new InvalidOperationException("La clave secreta JWT no está configurada.")));
    var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
    var token = new JwtSecurityToken(
        issuer: Environment.GetEnvironmentVariable("JWT_ISSUER") ?? "YourIssuer",
        audience: Environment.GetEnvironmentVariable("JWT_AUDIENCE") ?? "YourAudience",
        claims: claims,
        expires: DateTime.Now.AddHours(1),
        signingCredentials: creds);

    

    return Results.Ok(new { Token = new JwtSecurityTokenHandler().WriteToken(token) });
});

// Endpoint for administrators only
app.MapGet("/secure/admin-panel", () => "Este es el panel de administración.")
    .RequireAuthorization("AdminOnly");

// Endpoint for users only
app.MapGet("/secure/user-profile", () => "Este es el perfil de usuario.")
    .RequireAuthorization("UserOnly");

app.Run();
