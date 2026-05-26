using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

public class UserCredentialEntityTypeConfiguration : IEntityTypeConfiguration<UserCredential>
{
    public void Configure(EntityTypeBuilder<UserCredential> builder)
    {
        // Primary Key
        builder.HasKey(uc => uc.Id);

        // Security & Credentials
        builder.Property(uc => uc.PasswordHash)
            .IsRequired()
            .HasMaxLength(256); // Standard padding envelope safety for Argon2id, BCrypt, or PBKDF2

        // Login Auditing & Safety
        builder.Property(uc => uc.FailedLoginAttempts)
            .IsRequired()
            .HasDefaultValue(0);

        builder.Property(uc => uc.LastLoginAttempt)
            .HasColumnType("timestamp with time zone"); // Forces explicit PostgreSQL 'timestamptz' alignment

        // Verification Token Fields
        builder.Property(uc => uc.VerifyToken)
            .HasMaxLength(64); // Optimized size boundary for 32-byte secure crypto hex outputs

        builder.Property(uc => uc.VerifyTokenExpiration)
            .HasColumnType("timestamp with time zone");

        // CRITICAL PERFORMANCE OPTIMIZATION: Postgres Filtered/Sparse Index
        // Because the '/verify' endpoint performs lookups directly against this string,
        // adding an index is mandatory. By adding a filter, Postgres completely ignores rows 
        // where VerifyToken is NULL. This keeps the index tree microscopic, fast, and optimized.
        builder.HasIndex(uc => uc.VerifyToken)
            .HasFilter("\"VerifyToken\" IS NOT NULL");

        // System Metadata Timestamp
        builder.Property(uc => uc.CreatedAt)
            .IsRequired()
            .HasColumnType("timestamp with time zone")
            .HasDefaultValueSql("CURRENT_TIMESTAMP");
    }
}