using Microsoft.EntityFrameworkCore;
using RBACApp.Data;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using RBACApp.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;

var builder = WebApplication.CreateBuilder(args);

// Load environment variables
DotNetEnv.Env.Load();

// Configure JWT settings with error handling for missing environment variables
var jwtSettings = new JwtSettings
{
    Issuer = Environment.GetEnvironmentVariable("JWT_ISSUER")
        ?? throw new InvalidOperationException("JWT_ISSUER environment variable is not set."),
    Audience = Environment.GetEnvironmentVariable("JWT_AUDIENCE")
        ?? throw new InvalidOperationException("JWT_AUDIENCE environment variable is not set."),
    SecretKey = Environment.GetEnvironmentVariable("JWT_KEY")
        ?? throw new InvalidOperationException("JWT_KEY environment variable is not set."),
    ExpirationInMinutes = int.TryParse(Environment.GetEnvironmentVariable("JWT_EXPIRATION_MINUTES"), out var expiration)
        ? expiration
        : throw new InvalidOperationException("JWT_EXPIRATION_MINUTES environment variable is not valid.")
};

// Add JWT authentication
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = jwtSettings.Issuer,
            ValidAudience = jwtSettings.Audience,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings.SecretKey)),
            ClockSkew = TimeSpan.Zero
        };
    });

// Register authorization services
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AdminOnly", policy => policy.RequireRole("Admin"));
    options.AddPolicy("UserOnly", policy => policy.RequireRole("User"));
});

// Configure Entity Framework and database context
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlServer(Environment.GetEnvironmentVariable("CONNECTION_STRING")
        ?? throw new InvalidOperationException("CONNECTION_STRING environment variable is not set.")));

var app = builder.Build();

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

// Helper function to hash passwords with SHA256
string HashPassword(string password, string secretKey)
{
    using var sha256 = SHA256.Create();
    var combined = Encoding.UTF8.GetBytes(password + secretKey);
    var hash = sha256.ComputeHash(combined);
    return Convert.ToBase64String(hash);
}

// Register endpoint
app.MapPost("/register", async (RegisterRequest request, AppDbContext dbContext) =>
{
    if (await dbContext.Users.AnyAsync(u => u.Username == request.Username))
    {
        return Results.BadRequest(new { Error = "Username already exists." });
    }

    var hashedPassword = HashPassword(request.Password, jwtSettings.SecretKey);

    var user = new User
    {
        Username = request.Username,
        PasswordHash = hashedPassword,
        Role = request.Role
    };
    dbContext.Users.Add(user);
    await dbContext.SaveChangesAsync();

    return Results.Ok("User registered successfully.");
});

// Login endpoint
app.MapPost("/login", async (LoginRequest request, AppDbContext dbContext) =>
{
    var user = await dbContext.Users.FirstOrDefaultAsync(u => u.Username == request.Username);
    if (user == null) return Results.Unauthorized();

    var hashedPassword = HashPassword(request.Password, jwtSettings.SecretKey);
    if (user.PasswordHash != hashedPassword) return Results.Unauthorized();

    var tokenHandler = new JwtSecurityTokenHandler();
    var key = Encoding.UTF8.GetBytes(jwtSettings.SecretKey);
    var tokenDescriptor = new SecurityTokenDescriptor
    {
        Subject = new System.Security.Claims.ClaimsIdentity(new[]
        {
            new System.Security.Claims.Claim("id", user.Id.ToString()),
            new System.Security.Claims.Claim("username", user.Username),
            new System.Security.Claims.Claim("role", user.Role)
        }),
        Expires = DateTime.UtcNow.AddMinutes(jwtSettings.ExpirationInMinutes),
        Issuer = jwtSettings.Issuer,
        Audience = jwtSettings.Audience,
        SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
    };

    var accessToken = tokenHandler.CreateToken(tokenDescriptor);
    return Results.Ok(new { Token = tokenHandler.WriteToken(accessToken) });
});

// Admin-only endpoint
app.MapGet("/secure/admin-panel", () => Results.Ok("This is the admin panel."))
    .RequireAuthorization("AdminOnly");

// User-only endpoint
app.MapGet("/secure/user-profile", () => Results.Ok("This is the user profile."))
    .RequireAuthorization("UserOnly");

app.Run();
