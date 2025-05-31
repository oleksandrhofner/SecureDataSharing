using Microsoft.AspNetCore.Identity;
using SecureDataSharing.Models;
using Microsoft.Extensions.Logging;
using System.Text.Encodings.Web; // Для HtmlEncoder
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration; // Для IConfiguration
using SendGrid;
using SendGrid.Helpers.Mail;
using System.Text.Encodings.Web;


namespace SecureDataSharing.Services
{
    public class EmailSender : IEmailSender<ApplicationUser>
    {
        private readonly ILogger<EmailSender> _logger;
        private readonly IConfiguration _configuration; // Для доступу до API ключа

        public EmailSender(ILogger<EmailSender> logger, IConfiguration configuration)
        {
            _logger = logger;
            _configuration = configuration;
        }

        private async Task ExecuteSendEmail(string apiKey, string subject, string message, string toEmail, string toUserName)
        {
            var client = new SendGridClient(apiKey);
            var from = new EmailAddress("securedatasharinguk@gmail.com", "SecureDataSharing App");
            var to = new EmailAddress(toEmail, toUserName);
            var plainTextContent = message;
            var htmlContent = message;
            var msg = MailHelper.CreateSingleEmail(from, to, subject, plainTextContent, htmlContent);

            var response = await client.SendEmailAsync(msg);

            if (response.IsSuccessStatusCode)
            {
                _logger.LogInformation("Email to {Email} queued successfully! Subject: {Subject}", toEmail, subject);
            }
            else
            {
                _logger.LogError("Failed to send email to {Email}. StatusCode: {StatusCode}, Body: {Body}",
                    toEmail, response.StatusCode, await response.Body.ReadAsStringAsync());
            }
        }

        public async Task SendConfirmationLinkAsync(ApplicationUser user, string email, string confirmationLink)
        {
            var apiKey = _configuration["SendGridKey"]; // Отримуємо ключ з User Secrets або appsettings
            if (string.IsNullOrEmpty(apiKey))
            {
                _logger.LogError("SendGridKey is not configured.");
                return;
            }

            var subject = "Підтвердьте вашу електронну пошту";
            var message = $"Будь ласка, підтвердьте ваш обліковий запис, <a href='{HtmlEncoder.Default.Encode(confirmationLink)}'>натиснувши тут</a>.";

            await ExecuteSendEmail(apiKey, subject, message, email, user.UserName ?? email);
        }

        public async Task SendPasswordResetLinkAsync(ApplicationUser user, string email, string resetLink)
        {
            var apiKey = _configuration["SendGridKey"];
            if (string.IsNullOrEmpty(apiKey))
            {
                _logger.LogError("SendGridKey is not configured.");
                return;
            }

            var subject = "Скидання вашого пароля";
            var message = $"Будь ласка, скиньте ваш пароль, <a href='{HtmlEncoder.Default.Encode(resetLink)}'>натиснувши тут</a>.";

            await ExecuteSendEmail(apiKey, subject, message, email, user.UserName ?? email);
        }

        public async Task SendPasswordResetCodeAsync(ApplicationUser user, string email, string resetCode)
        {
            var apiKey = _configuration["SendGridKey"];
            if (string.IsNullOrEmpty(apiKey))
            {
                _logger.LogError("SendGridKey is not configured.");
                return;
            }
            var subject = "Ваш код для скидання пароля";
            var message = $"Ваш код для скидання пароля: {resetCode}";

            await ExecuteSendEmail(apiKey, subject, message, email, user.UserName ?? email);
        }


    }
}
