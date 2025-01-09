namespace RBACApp.Models;

public class JwtSettings
{
    public required string Issuer { get; set; }
    public required string Audience { get; set; }
    public required string SecretKey { get; set; }
    public int ExpirationInMinutes { get; set; } = 60; // Default expiration
}
