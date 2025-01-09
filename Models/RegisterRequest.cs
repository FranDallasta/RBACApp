namespace RBACApp.Models;

public class RegisterRequest
{
    public required string Username { get; set; }
    public required string Password { get; set; }
    public required string Role { get; set; }
}
