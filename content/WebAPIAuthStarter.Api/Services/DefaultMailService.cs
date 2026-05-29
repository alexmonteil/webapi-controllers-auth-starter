using System.Net.Sockets;

using MailKit.Net.Smtp;
using MailKit.Security;

using Microsoft.Extensions.Options;

using MimeKit;

public class DefaultMailService : IMailService
{

    private readonly MailSettings _settings;
    private readonly ILogger<DefaultMailService> _logger;

    public DefaultMailService(IOptions<MailSettings> options, ILogger<DefaultMailService> logger)
    {
        _settings = options.Value;
        _logger = logger;
    }

    public async Task<bool> SendVerificationEmailAsync(string mailTo, string username, string token)
    {
        // Build email message metadata
        var email = new MimeMessage();
        email.From.Add(new MailboxAddress(_settings.AppName, _settings.MailAddress));
        email.To.Add(new MailboxAddress(username, mailTo));
        email.Subject = $"Verify your {_settings.AppName} Account";

        // Construct verification link
        // TODO: CUSTOMIZE THIS URL! 
        // This should point to your FRONTEND application's verification page. 
        // The frontend will then parse the token from the URL and make a secure HTTP POST request 
        // to the /api/auth/verify endpoint as mandated by the idempotency design.
        var verificationUrl = $"https://localhost:7001/api/auth/verify-email?token={token}";

        var bodyBuilder = new BodyBuilder
        {
            HtmlBody = $@"
                <h3>Welcome to the grid, {username}!</h3>
                <p>Please activate your security credentials by clicking the link below:</p>
                <p><a href='{verificationUrl}'>Verify Email Address</a></p>
                <small>This token will expire in 2 hours.</small>"
        };
        email.Body = bodyBuilder.ToMessageBody();

        // Send the payload via MailKit Smtp client
        using var client = new SmtpClient();
        try
        {
            await client.ConnectAsync(_settings.MailHost, _settings.MailPort, SecureSocketOptions.StartTls);
            await client.AuthenticateAsync(_settings.MailAddress, _settings.MailPassword);
            await client.SendAsync(email);

            return true;
        }
        catch (AuthenticationException ex)
        {
            _logger.LogError(ex, "SMTP authentication failed for provider {Host}.", _settings.MailHost);
            return false;
        }
        catch (SmtpCommandException ex)
        {
            _logger.LogError(ex, "SMTP command error occurred. Status code: {StatusCode}.", ex.StatusCode);
            return false;
        }
        catch (Exception ex) when (ex is IOException or SocketException)
        {
            _logger.LogWarning(ex, "Transient network failure connecting to SMTP host {Host}.", _settings.MailHost);
            return false;
        }
        finally
        {
            if (client.IsConnected)
            {
                await client.DisconnectAsync(true);
            }
        }
    }
}