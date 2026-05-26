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

    private const string DummyPasswordHash = "$2a$11$K8V81/bWv23VpM8.AhnXHeWdfZ9Ie56K.yB77XNq8KshW9pXB.Gqy";

    public AuthController(IConfiguration config, DefaultDbContext context, IMailService mailService)
    {
        _config = config;
        _context = context ?? throw new ArgumentNullException(nameof(context));
        _mailService = mailService;
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
            VerifyTokenExpiration = DateTime.UtcNow.AddHours(2)
        };

        newUser.UserCredential = newCredential;

        _context.Users.Add(newUser);
        await _context.SaveChangesAsync();

        var mailSent = await _mailService.SendVerificationEmailAsync(newUser.Email, newUser.Username, emailVerificationToken);

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

            return Unauthorized(new OperationStatusResponse(false, invalidCredentialsMsg));
        }

        if (!user.IsEmailVerified)
        {
            return BadRequest(new OperationStatusResponse(false, "Account is unverified. Please check your inbox for the activation link."));
        }

        credential.FailedLoginAttempts = 0;
        await _context.SaveChangesAsync();

        var token = GenerateJwtToken(user);

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
            return BadRequest(new OperationStatusResponse(false, "The verification token or email address provided is invalid."));
        }

        if (credential.User.IsEmailVerified)
        {
            return Ok(new OperationStatusResponse(true, "Your email address has already been verified! You can proceed to log in."));
        }

        if (credential.VerifyTokenExpiration.HasValue && DateTime.UtcNow > credential.VerifyTokenExpiration.Value)
        {
            return BadRequest(new OperationStatusResponse(false, "This verification token has expired. Please request a new activation link."));
        }

        credential.User.IsEmailVerified = true;
        credential.VerifyToken = null;
        credential.VerifyTokenExpiration = null;

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
            return Ok(new OperationStatusResponse(true, "If an unverified account with that email address exists, a new verification link has been sent."));
        }

        var emailVerificationToken = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        user.UserCredential.VerifyToken = emailVerificationToken;
        user.UserCredential.VerifyTokenExpiration = DateTime.UtcNow.AddHours(2);
        await _context.SaveChangesAsync();

        var mailSent = await _mailService.SendVerificationEmailAsync(user.Email, user.Username, emailVerificationToken);
        if (!mailSent)
        {
            return StatusCode(500, new OperationStatusResponse(false, "Failed to send the verification email. Please try again later."));
        }

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
            expires: DateTime.UtcNow.AddHours(2),
            signingCredentials: creds
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}