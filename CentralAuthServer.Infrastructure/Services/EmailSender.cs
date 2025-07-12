using CentralAuthServer.Core.Services;
using System;
using System.Threading.Tasks;

namespace CentralAuthServer.Infrastructure.Services
{
    public class EmailSender : IEmailSender
    {
        public Task SendEmailAsync(string toEmail, string subject, string htmlMessage)
        {
            // For now, just simulate
            Console.WriteLine($"To: {toEmail}");
            Console.WriteLine($"Subject: {subject}");
            Console.WriteLine($"Message: {htmlMessage}");
            return Task.CompletedTask;
        }
    }
}
