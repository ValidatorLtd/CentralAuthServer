using CentralAuthServer.Core.Services;
using System;
using System.Net;
using System.Net.Mail;
using System.Threading.Tasks;

namespace CentralAuthServer.Infrastructure.Services
{
    public class EmailSender : IEmailSender
    {
        public async Task SendEmailAsync(string toEmail, string subject, string htmlMessage)
        {
            try
            {
                // Hardcoded SMTP settings as requested
                var smtpClient = new SmtpClient("smtp.office365.com")
                {
                    Port = 587,
                    Credentials = new NetworkCredential("mghanat@iristel.com", "kmbbjfqmwphwknkn"),
                    EnableSsl = true
                };

                var mailMessage = new MailMessage
                {
                    From = new MailAddress("mghanat@iristel.com"),
                    Subject = subject,
                    Body = htmlMessage,
                    IsBodyHtml = true
                };
                mailMessage.To.Add(toEmail);

                await smtpClient.SendMailAsync(mailMessage);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to send email: {ex.Message}");
                throw; // Optionally rethrow the exception
            }
        }
    }
}
