using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

using BC = BCrypt.Net.BCrypt;

namespace BaseAuth.Api.Controllers;

[ApiController]
[Route("api/auth")]
public class AuthController : ControllerBase
{
    private readonly IConfiguration _config;
    private readonly DefaultDbContext _context;
    private readonly IMailService _mailService;
    private readonly ILogger<AuthController> _logger;

    // TODO: If you change the password hashing algorithm or BCrypt work factor, you MUST update this dummy hash.
    // It exists to ensure strict computational timing consistency against side-channel attacks for non-existent users.
    private const string DummyPasswordHash = "$2a$11$K8V81/bWv23VpM8.AhnXHeWdfZ9Ie56K.yB77XNq8KshW9pXB.Gqy";

    public AuthController(IConfiguration config, DefaultDbContext context, IMailService mailService, ILogger<AuthController> logger)
    {
        _config = config;
        _context = context ?? throw new ArgumentNullException(nameof(context));
        _mailService = mailService;
        _logger = logger;
    }

    [HttpPost("register")]
    [EndpointSummary("Registers a new user account inside the tracking schema.")]
    [ProducesResponseType(typeof(RegistrationResponse), StatusCodes.Status201Created)]
    [ProducesResponseType(typeof(OperationStatusResponse), StatusCodes.Status409Conflict)]
    public async Task<ActionResult<RegistrationResponse>> Register([FromBody] RegisterRequest req)
    {
        var normalizedEmail = req.Email.Trim().ToLower();
        var normalizedUsername = req.Username.Trim().ToLower();

        var userExists = await _context.Users.AnyAsync(u => u.Email == normalizedEmail || u.Username == normalizedUsername);
        if (userExists)
        {
            _logger.LogWarning("Registration failed: Username '{Username}' or Email is already in use.", normalizedUsername);
            return Conflict(new OperationStatusResponse(false, "Username or Email is already in use."));
        }

        var passwordHash = BC.HashPassword(req.Password);
        var emailVerificationToken = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));

        var newUser = new User
        {
            Username = normalizedUsername,
            Email = normalizedEmail,
            IsEmailVerified = false,
            Role = UserRole.User
        };

        var newCredential = new UserCredential
        {
            PasswordHash = passwordHash,
            VerifyToken = emailVerificationToken,
            // TODO: Customize activation token expiration limit as needed.
            VerifyTokenExpiration = DateTime.UtcNow.AddHours(2)
        };

        newUser.UserCredential = newCredential;

        _context.Users.Add(newUser);
        await _context.SaveChangesAsync();

        var mailSent = await _mailService.SendVerificationEmailAsync(newUser.Email, newUser.Username, emailVerificationToken);

        if (mailSent)
        {
            _logger.LogInformation("User {UserId} '{Username}' successfully registered. Verification email sent.", newUser.Id, newUser.Username);
        }
        else
        {
            _logger.LogWarning("User {UserId} '{Username}' successfully registered, but the verification email failed to send.", newUser.Id, newUser.Username);
        }

        return CreatedAtAction(
            nameof(Register),
            new { id = newUser.Id },
            new RegistrationResponse
            {
                UserId = newUser.Id,
                Username = newUser.Username,
                Email = newUser.Email,
                Message = mailSent
                    ? "Registration successful! Please check your inbox to verify your email before logging in."
                    : "Registration successful, but we encountered an error sending the verification email. Please try resending the verification link."
            }
        );
    }

    [HttpPost("login")]
    [EndpointSummary("Validates identity signatures and emits an authorized access token.")]
    [ProducesResponseType(typeof(AuthResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(OperationStatusResponse), StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(OperationStatusResponse), StatusCodes.Status400BadRequest)]
    public async Task<ActionResult<AuthResponse>> Login([FromBody] LoginRequest req)
    {
        var normalizedEmail = req.Email.Trim().ToLower();
        const string invalidCredentialsMsg = "Invalid credentials provided.";

        // TODO: Adjust progressive lockout rules per your operational requirements.
        const int MaxFailedAttempts = 5;
        const int LockoutMinutes = 15;

        var user = await _context.Users
            .Include(u => u.UserCredential)
            .FirstOrDefaultAsync(u => u.Email == normalizedEmail);

        var credential = user?.UserCredential;

        if (credential != null && credential.FailedLoginAttempts >= MaxFailedAttempts)
        {
            if (credential.LastLoginAttempt.HasValue &&
                credential.LastLoginAttempt.Value.AddMinutes(LockoutMinutes) > DateTime.UtcNow)
            {
                var remainingTime = credential.LastLoginAttempt.Value.AddMinutes(LockoutMinutes) - DateTime.UtcNow;

                _logger.LogWarning("Login failed: Account '{Email}' is temporarily locked due to excessive failed attempts.", normalizedEmail);

                return BadRequest(new OperationStatusResponse(
                    false,
                    $"This account is temporarily locked due to too many failed login attempts. Please try again in {Math.Ceiling(remainingTime.TotalMinutes)} minutes."
                ));
            }
        }

        var hashToVerify = credential?.PasswordHash ?? DummyPasswordHash;
        var passwordMatches = BC.Verify(req.Password, hashToVerify);

        if (credential != null)
        {
            credential.LastLoginAttempt = DateTime.UtcNow;
        }

        if (user == null || credential == null || !passwordMatches)
        {
            if (credential != null)
            {
                credential.FailedLoginAttempts += 1;
                await _context.SaveChangesAsync();
            }

            _logger.LogWarning("Login failed for '{Email}': Invalid credentials.", normalizedEmail);

            return Unauthorized(new OperationStatusResponse(false, invalidCredentialsMsg));
        }

        if (!user.IsEmailVerified)
        {
            _logger.LogWarning("Login failed: User {UserId} '{Username}' attempted to log in but their email is unverified.", user.Id, user.Username);
            return BadRequest(new OperationStatusResponse(false, "Account is unverified. Please check your inbox for the activation link."));
        }

        credential.FailedLoginAttempts = 0;
        await _context.SaveChangesAsync();

        var token = GenerateJwtToken(user);

        _logger.LogInformation("User {UserId} '{Username}' successfully logged in.", user.Id, user.Username);

        return Ok(new AuthResponse
        {
            Token = token,
            Username = user.Username,
            Email = user.Email,
            Role = user.Role.ToString()
        });
    }

    [HttpPost("verify")]
    [EndpointSummary("Verifies a user's email address using an activation token.")]
    [ProducesResponseType(typeof(OperationStatusResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(OperationStatusResponse), StatusCodes.Status400BadRequest)]
    public async Task<ActionResult<OperationStatusResponse>> Verify([FromBody] VerifyRequest req)
    {
        var normalizedEmail = req.Email.Trim().ToLower();
        var lookupToken = req.Token.Trim().ToUpper();

        var credential = await _context.UserCredentials
            .Include(uc => uc.User)
            .FirstOrDefaultAsync(uc => uc.VerifyToken == lookupToken);

        if (credential == null || credential.User == null || credential.User.Email != normalizedEmail)
        {
            _logger.LogWarning("Verification failed: Invalid token or email mismatch for '{Email}'.", normalizedEmail);
            return BadRequest(new OperationStatusResponse(false, "The verification token or email address provided is invalid."));
        }

        if (credential.User.IsEmailVerified)
        {
            _logger.LogInformation("Verification attempt for user {UserId}: Account is already verified.", credential.User.Id);
            return Ok(new OperationStatusResponse(true, "Your email address has already been verified! You can proceed to log in."));
        }

        if (credential.VerifyTokenExpiration.HasValue && DateTime.UtcNow > credential.VerifyTokenExpiration.Value)
        {
            _logger.LogWarning("Verification failed for user {UserId}: Token has expired.", credential.User.Id);
            return BadRequest(new OperationStatusResponse(false, "This verification token has expired. Please request a new activation link."));
        }

        credential.User.IsEmailVerified = true;
        credential.VerifyToken = null;
        credential.VerifyTokenExpiration = null;

        _logger.LogInformation("User {UserId} successfully verified their email address.", credential.User.Id);

        await _context.SaveChangesAsync();

        return Ok(new OperationStatusResponse(true, "Your email address has been successfully verified! You can now log in to the application."));
    }

    [HttpPost("resend-verification")]
    [EndpointSummary("Send a new verification link to the user.")]
    [ProducesResponseType(typeof(OperationStatusResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(OperationStatusResponse), StatusCodes.Status500InternalServerError)]
    public async Task<ActionResult<OperationStatusResponse>> ResendVerification([FromBody] ResendVerifyRequest req)
    {
        var normalizedEmail = req.Email.Trim().ToLower();
        var user = await _context.Users
            .Include(u => u.UserCredential)
            .FirstOrDefaultAsync(u => u.Email == normalizedEmail);

        if (user == null || user.UserCredential == null || user.IsEmailVerified)
        {
            _logger.LogInformation("Resend verification requested for '{Email}', but account was not found or is already verified.", normalizedEmail);
            return Ok(new OperationStatusResponse(true, "If an unverified account with that email address exists, a new verification link has been sent."));
        }

        var emailVerificationToken = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        user.UserCredential.VerifyToken = emailVerificationToken;
        user.UserCredential.VerifyTokenExpiration = DateTime.UtcNow.AddHours(2);
        await _context.SaveChangesAsync();

        var mailSent = await _mailService.SendVerificationEmailAsync(user.Email, user.Username, emailVerificationToken);
        if (!mailSent)
        {
            _logger.LogError("Failed to send the resend verification email to user {UserId}.", user.Id);
            return StatusCode(500, new OperationStatusResponse(false, "Failed to send the verification email. Please try again later."));
        }

        _logger.LogInformation("A new verification link was successfully sent to user {UserId}.", user.Id);

        return Ok(new OperationStatusResponse(true, "If an unverified account with that email address exists, a new verification link has been sent."));
    }

    private string GenerateJwtToken(User user)
    {
        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new Claim(ClaimTypes.Name, user.Username),
            new Claim(ClaimTypes.Email, user.Email),
            new Claim(ClaimTypes.Role, user.Role.ToString())
        };

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["JWT_SECRET_KEY"]!));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            issuer: _config["JWT_ISSUER"],
            audience: _config["JWT_AUDIENCE"],
            claims: claims,
            // TODO: Customize JWT token lifespan. For production, consider using shorter-lived access tokens along with refresh tokens.
            expires: DateTime.UtcNow.AddHours(2),
            signingCredentials: creds
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}