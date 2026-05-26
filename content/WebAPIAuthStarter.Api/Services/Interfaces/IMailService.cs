public interface IMailService
{
    Task<bool> SendVerificationEmailAsync(string mailTo, string username, string token);
}