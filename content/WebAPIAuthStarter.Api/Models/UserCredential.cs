public class UserCredential
{
    public int Id { get; set; }
    public int UserId { get; set; }
    public required string PasswordHash { get; set; }
    public int FailedLoginAttempts { get; set; } = 0;
    public DateTime? LastLoginAttempt { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public string? VerifyToken { get; set; }
    public DateTime? VerifyTokenExpiration { get; set; }

    // Navigation
    public User User { get; set; } = null!;
}