public class User
{
    public int Id { get; set; }
    public required string Username { get; set; }
    public required string Email { get; set; }
    public bool IsEmailVerified { get; set; } = false;
    public string? AvatarUrl { get; set; }
    public DateTime CreatedAt { get; set; }
    public UserRole Role { get; set; } = UserRole.User;

    // Navigation
    public UserCredential? UserCredential { get; set; }
}